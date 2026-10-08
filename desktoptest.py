"""桌面窗口的端到端自测。

验证的是"双击之后到底有没有出现一个像样的窗口"，而不只是"进程没崩"：
  1. PE 子系统必须是 GUI —— 否则双击还会弹出控制台
  2. 进程能起来，并且 HTTP 控制台先就绪（窗口要加载它）
  3. 真的出现了一个标题为「netlens 流量控制台」的可见窗口
  4. 窗口里嵌着 WebView2 的子控件 —— 只验证"窗口存在"是不够的，
     窗口建出来但 WebView2 没挂上去，照样是个白框
  5. WebView2 的数据目录落在指定位置，而不是 exe 旁边
  6. 关掉进程后没有残留

用法：python desktoptest.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

WEB = ("127.0.0.1", 19610)
SOCKS = ("127.0.0.1", 11090)
PROXY = ("127.0.0.1", 18090)
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ok_all = True


def log(ok, msg):
    global ok_all
    ok_all = ok_all and ok
    print(("  [PASS] " if ok else "  [FAIL] ") + msg, flush=True)


def api(path):
    url = "http://%s:%d%s" % (WEB[0], WEB[1], path)
    with OPENER.open(url, timeout=5) as r:
        return json.loads(r.read().decode())


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    exe = os.path.join(here, "netlens.exe")
    if not os.path.exists(exe):
        print("找不到 netlens.exe")
        return 1

    print("\n1) PE 属性")
    out = subprocess.run([sys.executable, os.path.join(here, "checkmanifest.py"), exe],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    log("子系统 = 2" in out, "PE 子系统是 Windows GUI（双击不弹控制台）")
    log("requireAdministrator" in out, "清单仍然要求管理员权限")
    log("图标资源：1 个图标组" in out, "图标资源已打进 exe")

    print("\n2) 构建窗口探针")
    probe = os.path.join(here, "windowcheck.exe")
    r = subprocess.run(["go", "build", "-o", probe, "./tools/windowcheck"],
                       cwd=here, capture_output=True, text=True)
    if r.returncode != 0:
        log(False, "探针编译失败: " + (r.stderr or "")[:300])
        return 1
    log(True, "windowcheck.exe 就绪")

    # 先确认端口没人占，不然会连到上一次留下的僵尸进程上，错得莫名其妙
    for p in (WEB[1], SOCKS[1], PROXY[1]):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            print("端口 %d 已被占用，先清掉残留进程：taskkill /F /IM netlens.exe" % p)
            return 1
        finally:
            s.close()

    tmp = tempfile.mkdtemp(prefix="netlens-desktop-")
    proc = subprocess.Popen([
        exe, "-web", "%s:%d" % WEB, "-socks", "%s:%d" % SOCKS,
        "-http", "%s:%d" % PROXY, "-ca-dir", tmp, "-no-browser",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []

    def drain():
        for line in proc.stdout:
            lines.append(line.decode("utf-8", "replace"))
    import threading
    threading.Thread(target=drain, daemon=True).start()

    try:
        print("\n3) 服务先就绪，再建窗口")
        ready = False
        for _ in range(80):
            try:
                st = api("/api/status")
                ready = True
                break
            except Exception:
                if proc.poll() is not None:
                    break
                time.sleep(0.25)
        log(ready, "控制台 HTTP 服务已就绪（窗口加载的是它）")
        if not ready:
            print("        进程输出：" + "".join(lines)[-500:])
            return 1
        log(proc.poll() is None, "进程仍在运行（没有因为开窗而退出）")

        time.sleep(3.0)  # 等 WebView2 初始化

        print("\n4) 窗口本身")
        r = subprocess.run([probe, "-pid", str(proc.pid)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        wout = r.stdout or ""
        log("netlens 流量控制台" in wout, "出现了标题为「netlens 流量控制台」的可见窗口")
        chrome = [l for l in wout.splitlines() if "child class=" in l and "Chrome" in l]
        log(bool(chrome), "窗口里嵌着 WebView2 控件（子控件 %s）"
            % (chrome[0].split("=")[-1] if chrome else "无"))
        if not chrome:
            print("        窗口探针输出：\n" + "\n".join("          " + l for l in wout.splitlines()[:12]))

        print("\n5) WebView2 数据目录")
        data_dir = os.path.join(tmp, "webview")
        log(os.path.isdir(data_dir), "数据目录落在 -ca-dir 下的 webview/（不是 exe 旁边）")
        log(not os.path.isdir(os.path.join(here, "netlens.exe.WebView2")),
            "exe 旁边没有生成 WebView2 缓存文件夹")

        print("\n6) 页面内容真的渲染了吗")
        # 窗口加载的就是这个页面；用 HTTP 再确认一次内容完整（API + HTML）
        with OPENER.open("http://%s:%d/" % WEB, timeout=5) as r:
            html = r.read().decode("utf-8", "replace")
        log("netlens" in html and "流量控制台" in html, "页面 HTML 能取到")
        log("运行日志" in html, "新版页面（含独立日志入口）已生效")
        st = api("/api/status")
        log(st["socks"] == "%s:%d" % SOCKS, "页面接口数据正确")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
        time.sleep(0.5)
        # 进程树里不该留下 mihomo（本次没启动它，但确认一下收尾逻辑）
        left = subprocess.run(["tasklist", "/FI", "IMAGENAME eq mihomo.exe"],
                              capture_output=True, text=True, errors="replace").stdout
        log("mihomo.exe" not in left, "没有残留的 mihomo 进程")
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.exists(probe):
            os.remove(probe)

    print("\n" + ("全部通过" if ok_all else "存在失败项"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
