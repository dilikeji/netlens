"""内存上界探测：确认记录仓库的字节预算真的在起作用。

背景：为了让页面能「查看文本 / 下载」，文件类 body 也从"不抓"改成了"抓一份"。
那记录仓库的内存还必须是有界的（否则跑久了就是把机器吃光）。
这里用一个小预算（32MB）灌进远超额度的数据，看它到底守不守得住。

用法：python memprobe.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB = ("127.0.0.1", 19700)
PROXY = ("127.0.0.1", 18180)
UP = ("127.0.0.1", 18181)
BUDGET_MB = 32
BLOBS = 300
BLOB_SIZE = 200 * 1024   # 每个响应 200KB

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ok_all = True


def log(ok, msg):
    global ok_all
    ok_all = ok_all and ok
    print(("  [PASS] " if ok else "  [FAIL] ") + msg, flush=True)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = os.urandom(BLOB_SIZE)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def api(path):
    with OPENER.open("http://%s:%d%s" % (WEB[0], WEB[1], path), timeout=10) as r:
        return json.loads(r.read().decode())


def proxy_get(path, host_header):
    s = socket.create_connection(PROXY, timeout=10)
    s.sendall(("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
               % (host_header, path, host_header)).encode())
    n = 0
    while True:
        try:
            d = s.recv(65536)
        except Exception:
            break
        if not d:
            break
        n += len(d)
    s.close()
    return n


def rss_kb(pid):
    out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid],
                         capture_output=True, text=True, errors="replace").stdout
    for line in out.splitlines():
        if "netlens" in line:
            parts = line.replace(",", "").split()
            for i, p in enumerate(parts):
                if p.isdigit() and i > 0:
                    try:
                        return int(parts[-2])
                    except Exception:
                        pass
    return -1


def require_free(*ports):
    """先确认端口没人占。

    不然会连到上一个测试留下的僵尸进程上，报出来的错还完全对不上
    （实测过一次：`connect` 报 WSAEADDRINUSE，看着像代码问题，其实是残留进程）。
    """
    for p in ports:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            print("端口 %d 已被占用，先清掉残留进程：taskkill /F /IM netlens.exe" % p)
            sys.exit(1)
        finally:
            s.close()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    exe = os.path.join(here, "netlens.exe")
    require_free(WEB[1], PROXY[1], UP[1])
    tmp = tempfile.mkdtemp(prefix="netlens-mem-")
    up = ThreadingHTTPServer(UP, H)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    proc = subprocess.Popen([
        exe, "-web", "%s:%d" % WEB, "-socks", "127.0.0.1:11180",
        "-http", "%s:%d" % PROXY, "-ca-dir", tmp, "-no-window", "-no-browser",
        "-max-store-mb", str(BUDGET_MB),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        for _ in range(80):
            try:
                api("/api/status")
                break
            except Exception:
                time.sleep(0.25)

        print("\n灌入 %d 个 %dKB 的响应（合计 %d MB），仓库预算 %d MB"
              % (BLOBS, BLOB_SIZE // 1024, BLOBS * BLOB_SIZE // 1024 // 1024, BUDGET_MB))
        t0 = time.time()
        for i in range(BLOBS):
            proxy_get("/blob/%d" % i, "%s:%d" % UP)
        st = api("/api/status")
        print("  %.1fs 完成，记录 %d 条，仓库 %d MB，进程 RSS %d MB"
              % (time.time() - t0, st["records"], st["memBytes"] // 1024 // 1024,
                 rss_kb(proc.pid) // 1024))

        log(st["memBytes"] <= (BUDGET_MB + 4) * 1024 * 1024,
            "仓库字节数守在预算内：%d MB ≤ %d MB" % (st["memBytes"] // 1024 // 1024, BUDGET_MB))
        rss = rss_kb(proc.pid) // 1024
        log(rss < 400, "进程 RSS 没有失控：%d MB" % rss)

        # 再灌一轮，确认是"稳定在上界"而不是"每轮涨一截"
        for i in range(BLOBS):
            proxy_get("/blob2/%d" % i, "%s:%d" % UP)
        st2 = api("/api/status")
        rss2 = rss_kb(proc.pid) // 1024
        print("  第二轮后：记录 %d 条，仓库 %d MB，RSS %d MB"
              % (st2["records"], st2["memBytes"] // 1024 // 1024, rss2))
        log(st2["memBytes"] <= (BUDGET_MB + 4) * 1024 * 1024, "第二轮仓库仍然守在预算内")
        log(rss2 < rss * 1.6 + 80, "第二轮 RSS 没有翻倍（%d MB → %d MB）" % (rss, rss2))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
        up.shutdown()
        up.server_close()
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + ("全部通过" if ok_all else "存在失败项"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
