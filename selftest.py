"""netlens 端到端自测。

覆盖：
  1. 明文 HTTP（走 HTTP 代理入口，非标准端口 → 靠首字节嗅探识别）
  2. HTTPS 中间人（走 SOCKS5 入口，非标准端口，只信任 netlens 的根证书）
  3. WebSocket（走 SOCKS5 入口，握手 + 帧）
  4. 响应锁定：创建规则后，把上游停掉再发同样的请求，必须仍然拿到被改过的响应

用法（在 netlens.exe 所在目录）：
    python selftest.py
"""
import base64
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB = ("127.0.0.1", 19600)
SOCKS = ("127.0.0.1", 11080)
PROXY = ("127.0.0.1", 18080)
UP_HTTP = ("127.0.0.1", 18100)   # 明文 HTTP，非标准端口（兼做二进制接口）
UP_WS = ("127.0.0.1", 18101)     # WebSocket，非标准端口
UP_RAW = ("127.0.0.1", 18102)    # 裸 TCP，用来制造"无法解析"的透传流量
UP_TLS = ("127.0.0.1", 18443)    # TLS，非标准端口
UP9 = ("127.0.0.1", 18103)       # 第二实例用的上游

STDOUT_LINES = []

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

ok_all = True


def log(ok, msg):
    global ok_all
    ok_all = ok_all and ok
    print(("  [PASS] " if ok else "  [FAIL] ") + msg, flush=True)


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("连接被关闭，已收 %d/%d 字节" % (len(buf), n))
        buf += chunk
    return buf


# ---------------------------------------------------------------- 上游服务

# 一张能被识别的"PNG"：故意在正文里塞可读文本，用来证明
# 判定走的是 Content-Type 而不是"看起来像不像文本"
FAKE_PNG = (b"\x89PNG\r\n\x1a\n" + b"FAKE-IMAGE-PAYLOAD " * 64)


class JSONHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.startswith("/api/data"):
            body = json.dumps({"from": "upstream", "path": self.path, "n": 42}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Upstream", "yes")
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/file"):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(FAKE_PNG)))
            self.end_headers()
            self.wfile.write(FAKE_PNG)
        elif self.path.startswith("/api/rawbin"):
            # 没有 Content-Type，只能靠字节判断
            self.send_response(200)
            self.send_header("Content-Length", str(len(FAKE_PNG)))
            self.end_headers()
            self.wfile.write(FAKE_PNG)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_OPTIONS(self):
        # CORS 预检：正常回 204，用来验证"请求照常转发、只是不记录"
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def serve_http(addr, tls_ctx=None):
    srv = ThreadingHTTPServer(addr, JSONHandler)
    if tls_ctx:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def serve_raw(addr):
    """裸 TCP 服务：把收到的字节原样回显，用来制造"无法解析"的透传流量。"""
    ln = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ln.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ln.bind(addr)
    ln.listen(4)

    def loop():
        while True:
            try:
                c, _ = ln.accept()
            except OSError:
                return
            threading.Thread(target=lambda: echo(c), daemon=True).start()

    def echo(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    return
                c.sendall(d)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return ln


def serve_ws(addr):
    """最小 WebSocket 服务端：握手后把收到的每一帧原样回显。"""
    ln = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ln.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ln.bind(addr)
    ln.listen(8)

    def handle(c):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = c.recv(4096)
                if not chunk:
                    return
                head += chunk
            key = ""
            for line in head.decode("latin1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
            while True:
                h = c.recv(2)
                if len(h) < 2:
                    return
                op = h[0] & 0x0F
                ln_ = h[1] & 0x7F
                if ln_ == 126:
                    ln_ = struct.unpack("!H", recvn(c, 2))[0]
                elif ln_ == 127:
                    ln_ = struct.unpack("!Q", recvn(c, 8))[0]
                mask = recvn(c, 4) if h[1] & 0x80 else b""
                data = recvn(c, ln_)
                if mask:
                    data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                if op == 0x8:
                    return
                # 回显（服务端帧不带 mask）
                out = b"\x81" + (bytes([len(data)]) if len(data) < 126 else b"\x7e" + struct.pack("!H", len(data)))
                c.sendall(out + data)
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    def loop():
        while True:
            try:
                c, _ = ln.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return ln


# ---------------------------------------------------------------- 代理客户端

def socks5_connect(host, port):
    s = socket.create_connection(SOCKS, timeout=10)
    s.sendall(b"\x05\x01\x00")
    if recvn(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 方法协商失败")
    h = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack("!H", port))
    rep = recvn(s, 10)
    if rep[1] != 0:
        raise RuntimeError("SOCKS5 CONNECT 失败: %d" % rep[1])
    return s


def proxy_get(path, host_header, proxy=PROXY, method="GET"):
    """走 HTTP 代理入口发一个明文请求（请求行是绝对 URL）。"""
    s = socket.create_connection(proxy, timeout=10)
    req = ("%s http://%s%s HTTP/1.1\r\nHost: %s\r\n\r\n" % (method, host_header, path, host_header)).encode()
    s.sendall(req)
    buf = b""
    s.settimeout(5)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    s.close()
    return buf


def parse_http(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        out, i = b"", 0
        while True:
            j = body.index(b"\r\n", i)
            n = int(body[i:j].split(b";")[0], 16)
            if n == 0:
                break
            out += body[j + 2:j + 2 + n]
            i = j + 2 + n + 2
        body = out
    return status, headers, body


# 沙箱里设了 http_proxy，访问 127.0.0.1 也会被劫持，必须显式绕过
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api_raw(path):
    """取原始响应（不解析 JSON），用来测下载接口。"""
    with OPENER.open("http://%s:%d%s" % (WEB[0], WEB[1], path), timeout=10) as r:
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()


def api(path, method="GET", payload=None):
    url = "http://%s:%d%s" % (WEB[0], WEB[1], path)
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with OPENER.open(req, timeout=10) as r:
        return json.loads(r.read().decode())


# ---------------------------------------------------------------- 主流程

def require_free(*ports):
    """先确认端口没人占。

    不然会连到上一次测试留下的僵尸进程上，报出来的错还完全对不上
    （实测过一次：connect 报 WSAEADDRINUSE，看着像代码问题，其实是残留进程）。
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
    if not os.path.exists(exe):
        print("找不到 netlens.exe，请先执行：go build -o netlens.exe .")
        return 1
    require_free(WEB[1], SOCKS[1], PROXY[1], UP_HTTP[1], UP_WS[1], UP_RAW[1], UP_TLS[1])

    tmp = tempfile.mkdtemp(prefix="netlens-ca-")
    proc = subprocess.Popen([
        exe,
        "-web", "%s:%d" % WEB, "-socks", "%s:%d" % SOCKS, "-http", "%s:%d" % PROXY,
        "-ca-dir", tmp, "-no-browser", "-no-window",
        "-insecure-upstream", "-max-body", "262144",
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def drain():
        for line in proc.stdout:
            text = line.decode("utf-8", "replace")
            STDOUT_LINES.append(text.rstrip("\n"))
            sys.stdout.write("    | " + text)
            sys.stdout.flush()
    threading.Thread(target=drain, daemon=True).start()

    # TLS 上游：自签证书（netlens 用 -insecure-upstream 跳过校验）
    cert_file = os.path.join(tmp, "up.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", cert_file, "-out", cert_file, "-days", "2",
                    "-subj", "/CN=127.0.0.1",
                    "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)

    up_http = serve_http(UP_HTTP)
    up_ws = serve_ws(UP_WS)
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.load_cert_chain(cert_file, cert_file)
    up_tls = serve_http(UP_TLS, tls_ctx)

    try:
        # 等控制台起来
        for _ in range(60):
            try:
                api("/api/status")
                break
            except Exception:
                time.sleep(0.25)
        else:
            print("netlens 控制台没起来")
            return 1
        print("\n== netlens 已启动 ==\n")

        # ---- 1. 明文 HTTP（非标准端口 18100，靠嗅探）
        print("1) 明文 HTTP 经 HTTP 代理入口")
        raw = proxy_get("/api/data?x=1", "%s:%d" % UP_HTTP)
        status, headers, body = parse_http(raw)
        log(status == 200, "状态码 200（实际 %s）" % status)
        log(b"upstream" in body, "响应体来自上游：%s" % body[:80])
        log(headers.get("x-upstream") == "yes", "上游自定义响应头透传")

        # ---- 2. HTTPS 中间人（非标准端口 18443）
        print("\n2) HTTPS 经 SOCKS5（非标准端口 → 嗅探 → 中间人）")
        ca_path = os.path.join(tmp, "netlens-ca.crt")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=ca_path)   # 关键：只信任 netlens 的根
        s = socks5_connect(*UP_TLS)
        tls = ctx.wrap_socket(s, server_hostname="127.0.0.1")
        tls.sendall(b"GET /api/data?tls=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        raw = b""
        while True:
            try:
                chunk = tls.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            raw += chunk
        tls.close()
        status, headers, body = parse_http(raw)
        log(status == 200, "MITM 后状态码 200（实际 %s）" % status)
        log(b"upstream" in body, "解密后拿到明文响应体：%s" % body[:80])

        # ---- 3. WebSocket
        print("\n3) WebSocket 经 SOCKS5")
        ws = socks5_connect(*UP_WS)
        ws.sendall(("GET /ws HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
                    "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n" % UP_WS).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += ws.recv(4096)
        log(b"101" in head.split(b"\r\n")[0], "握手 101（%s）" % head.split(b"\r\n")[0].decode())
        payload = b"hello-netlens"
        mask = b"\x11\x22\x33\x44"
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        ws.sendall(b"\x81" + bytes([0x80 | len(payload)]) + mask + masked)
        h = recvn(ws, 2)
        n = h[1] & 0x7F
        if n == 126:
            n = struct.unpack("!H", recvn(ws, 2))[0]
        echoed = recvn(ws, n)
        log(echoed == payload, "帧内容回显一致：%r" % echoed)
        ws.close()

        time.sleep(0.6)

        # ---- 4. 记录是否都进了页面数据
        print("\n4) 控制台记录")
        recs = api("/api/records?limit=50")["records"]
        kinds = {}
        for r in recs:
            kinds.setdefault(r["kind"], []).append(r)
        log("http" in kinds, "有 HTTP 记录（%d 条）" % len(kinds.get("http", [])))
        log("ws" in kinds, "有 WebSocket 记录（%d 条）" % len(kinds.get("ws", [])))
        ws_rec = kinds.get("ws", [None])[0]
        if ws_rec:
            log(ws_rec["status"] == 101, "WS 记录状态码 101")
            detail = api("/api/records/%d" % ws_rec["id"])["record"]
            frames = detail.get("frames") or []
            log(len(frames) >= 1, "WS 帧被记录（%d 帧，方向 %s）" % (len(frames), frames[0]["dir"] if frames else "-"))
            if frames:
                log("hello-netlens" in json.dumps(frames[0]["payload"]), "帧载荷已解码")

        # ---- 4b. 二进制响应只展示"这是个文件"
        print("\n4b) 二进制响应不展示内容")
        raw = proxy_get("/api/file", "%s:%d" % UP_HTTP)
        status, headers, body = parse_http(raw)
        log(body == FAKE_PNG, "上游确实返回了二进制内容（%d 字节）" % len(body))

        raw = proxy_get("/api/rawbin", "%s:%d" % UP_HTTP)
        status, headers, body = parse_http(raw)
        log(body == FAKE_PNG, "无 Content-Type 的二进制也返回正常")

        time.sleep(0.5)
        recs = api("/api/records?limit=50")["records"]
        f_rec = [r for r in recs if r["path"] == "/api/file"]
        b_rec = [r for r in recs if r["path"] == "/api/rawbin"]
        log(bool(f_rec), "记录了 /api/file")
        if f_rec:
            d = api("/api/records/%d" % f_rec[0]["id"])["record"]
            log(d.get("respFile", {}).get("contentType") == "image/png",
                "按 Content-Type 判定为文件：%s" % d.get("respFile", {}).get("contentType"))
            log(d.get("respFile", {}).get("size") == len(FAKE_PNG),
                "大小正确：%s" % d.get("respFile", {}).get("size"))
            # 内容要留着：页面上有「查看文本」和「下载」两个按钮，没内容就是摆设
            log(d["respBody"].get("binary") and d["respBody"].get("len") == len(FAKE_PNG),
                "内容仍然带给了页面（binary/base64，%s 字节）" % d["respBody"].get("len"))

            # ---- 下载接口：必须原样吐回字节
            st2, hdr2, body2 = api_raw("/api/records/%d/body?which=resp" % f_rec[0]["id"])
            log(st2 == 200 and body2 == FAKE_PNG, "下载接口原样返回了 %d 字节" % len(body2))
            # api_raw 把 header 名统一转成小写了，取值也得用小写
            log(hdr2.get("content-type", "").startswith("image/png"),
                "下载带上了正确的 Content-Type：%s" % hdr2.get("content-type"))
            log("attachment" in hdr2.get("content-disposition", "")
                and ".png" in hdr2.get("content-disposition", ""),
                "下载文件名带扩展名：%s" % hdr2.get("content-disposition"))
        if b_rec:
            d = api("/api/records/%d" % b_rec[0]["id"])["record"]
            log(bool(d.get("respFile")), "没有 Content-Type 时按字节判定为文件")
            log(d["respBody"].get("len") == len(FAKE_PNG), "同样能拿到内容")
        txt_rec = [r for r in recs if r["path"].startswith("/api/data")]
        if txt_rec:
            d = api("/api/records/%d" % txt_rec[0]["id"])["record"]
            log(d.get("respFile") is None and "upstream" in json.dumps(d["respBody"]),
                "文本响应仍然完整展示内容")

        # ---- 4c. OPTIONS 请求照常转发，但不记录
        print("\n4c) CORS 预检（OPTIONS）被过滤")
        raw = proxy_get("/api/data", "%s:%d" % UP_HTTP, method="OPTIONS")
        status, headers, body = parse_http(raw)
        log(status == 204, "OPTIONS 请求仍然被正常转发（上游返回 %s）" % status)
        log(headers.get("access-control-allow-origin") == "*", "上游的 CORS 响应头正常回给客户端")
        time.sleep(0.5)
        recs = api("/api/records?limit=100")["records"]
        log(not [r for r in recs if r["method"] == "OPTIONS"], "OPTIONS 没有出现在记录里")
        st = api("/api/status")
        log(st["hiddenOptions"] >= 1, "状态里能看到被过滤的 OPTIONS 计数：%s" % st["hiddenOptions"])

        # ---- 4d. 无法解析的透传连接被过滤掉
        print("\n4d) 无法解析的连接默认不入库")
        up_raw = serve_raw(UP_RAW)
        s = socks5_connect(*UP_RAW)
        s.sendall(b"\x00\x01\x02\x03 NOT-HTTP \xff\xfe\x00")
        try:
            s.recv(64)   # 等回显，确认链路真的通了
        except Exception:
            pass
        s.close()
        time.sleep(0.6)

        recs = api("/api/records?limit=100")["records"]
        log(not [r for r in recs if r["kind"] == "tcp"], "透传连接没有出现在记录里")
        st = api("/api/status")
        log(st["hiddenTunnels"] >= 1, "页面状态里能看到被过滤的计数：%s" % st["hiddenTunnels"])
        up_raw.close()

        # ---- 4e. 屏蔽的粒度是域名
        print("\n4e) 屏蔽按域名生效")
        seed = next(r for r in recs if r["path"].startswith("/api/data"))
        b1 = api("/api/blocked", "POST", {"fromId": seed["id"]})
        log(b1["item"]["host"] == seed["host"], "从记录派生出的是域名：%s" % b1["item"]["host"])
        log("path" not in b1["item"], "屏蔽项里不再带路径")
        b2 = api("/api/blocked", "POST", {"host": seed["host"]})
        log(b2["added"] is False, "重复屏蔽同一个域名不会新增一条")
        b2b = api("/api/blocked", "POST", {"host": seed["host"], "path": "/whatever"})
        log(b2b["added"] is False, "带上路径再屏蔽也不新增（路径被忽略）")
        log(len(b2b["blocked"]) == 1, "名单里始终只有一条：%d" % len(b2b["blocked"]))
        log(api("/api/status")["blocked"] == 1, "状态里报出已屏蔽域名数")
        api("/api/blocked/%d" % b1["item"]["id"], "DELETE")
        log(len(api("/api/blocked")["blocked"]) == 0, "可以取消屏蔽")

        plain = [r for r in recs if r["kind"] == "http" and r["scheme"] == "http"]
        tls = [r for r in recs if r["kind"] == "http" and r["scheme"] == "https"]
        log(bool(plain), "明文 HTTP 记录被标记为 http")
        log(bool(tls), "MITM 记录被标记为 https")
        # 必须挑明是哪一条：/api/file、/api/rawbin 也是明文 HTTP，且更新
        data_rec = next((r for r in plain if r["path"].startswith("/api/data")), None)
        log(data_rec is not None, "找到 /api/data 那条记录")
        if data_rec:
            d = api("/api/records/%d" % data_rec["id"])["record"]
            log(any(k.lower() == "host" for k, _ in d["reqHdr"]), "详情里有请求头")
            log(any(k.lower() == "x-upstream" for k, _ in d["respHdr"]), "详情里有响应头")
            log("upstream" in json.dumps(d["respBody"]), "详情里有响应体")

        # ---- 5. 锁定响应：改响应内容，然后停掉上游再请求
        print("\n5) 锁定响应（修改响应内容）")
        target = data_rec
        fake = {"locked": True, "msg": "由 netlens 伪造", "id": 987}
        api("/api/rules", "POST", {
            "fromId": target["id"],
            "name": "自测锁定",
            "status": 200,
            "hdr": [["Content-Type", "application/json; charset=utf-8"], ["X-Locked", "netlens"]],
            "body": {"text": json.dumps(fake)},
            "ignoreQuery": True,
        })
        rules = api("/api/rules")["rules"]
        log(any(r["name"] == "自测锁定" for r in rules), "规则已创建：%s" % (rules[0]["pattern"] if rules else "-"))

        # 关掉上游，证明确实没有走网络。
        # 注意 shutdown() 只是停掉 serve_forever 循环，监听套接字还占着端口；
        # Windows 的 SO_REUSEADDR 允许第二个 socket 绑同一个端口，
        # 之后新连接可能被投递到那个已经没人 accept 的死套接字上。
        # 所以要 server_close() 真正释放端口，后面重启服务才不会打到鬼身上。
        up_http.shutdown()
        up_http.server_close()
        time.sleep(0.3)

        raw = proxy_get("/api/data?x=2", "%s:%d" % UP_HTTP)
        status, headers, body = parse_http(raw)
        got = json.loads(body.decode())
        log(status == 200, "锁定后仍返回 200（上游已关闭）")
        log(got == fake, "返回的是被修改过的内容：%s" % body.decode()[:80])
        log(headers.get("x-locked") == "netlens", "返回的是被修改过的响应头")

        time.sleep(0.4)
        recs = api("/api/records?limit=20")["records"]
        mock = [r for r in recs if r.get("mocked")]
        log(bool(mock), "该请求在页面上被标记为「已锁定」（规则 #%s）" % (mock[0]["ruleId"] if mock else "-"))

        # ---- 5b. 同一条链路上的 HTTPS：锁定后要能从 TLS 层原样写回
        print("\n5b) 锁定 HTTPS(MITM) 响应")
        tls_rec = [r for r in api("/api/records?limit=50")["records"]
                   if r["kind"] == "http" and r["scheme"] == "https"][0]
        fake2 = {"locked": "https", "n": 1}
        api("/api/rules", "POST", {
            "fromId": tls_rec["id"], "status": 200, "name": "自测锁定-HTTP与HTTPS两种",
            "hdr": [["Content-Type", "application/json"]],
            "body": {"text": json.dumps(fake2, ensure_ascii=False)},
            "ignoreQuery": True,
        })
        up_tls.shutdown()      # 上游彻底关掉
        up_tls.server_close()  # 见上面说明：必须真正释放端口
        time.sleep(0.3)

        # 这里要重新握手一次：原来的连接已经被上游关闭带走了
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.load_verify_locations(cafile=ca_path)
        s2 = socks5_connect(*UP_TLS)
        tls2 = ctx2.wrap_socket(s2, server_hostname="127.0.0.1")
        tls2.sendall(b"GET /api/data?tls=2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        raw = b""
        while True:
            try:
                chunk = tls2.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            raw += chunk
        tls2.close()
        status, headers, body = parse_http(raw)
        try:
            got2 = json.loads(body.decode())
        except Exception:
            got2 = None
        log(status == 200, "MITM 链路上锁定后返回 200（上游已关闭）")
        log(got2 == fake2, "TLS 层回写的内容正确：%s" % body.decode(errors="replace")[:80])
        log(headers.get("x-locked") is None and "content-length" in headers,
            "响应头按实际字节数重算（Content-Length=%s）" % headers.get("content-length"))

        # ---- 6. 解锁
        print("\n6) 解除锁定")
        all_rules = api("/api/rules")["rules"]
        log(len(all_rules) == 2, "当前有 2 条规则（明文 + HTTPS）")
        for r in all_rules:
            api("/api/rules/%d" % r["id"], "DELETE")
        log(len(api("/api/rules")["rules"]) == 0, "全部规则已删除")
        up2 = serve_http(UP_HTTP)
        time.sleep(0.2)
        raw = proxy_get("/api/data?x=3", "%s:%d" % UP_HTTP)
        status, headers, body = parse_http(raw)
        log(b"upstream" in body, "解锁后恢复走真实上游：%s" % body[:60])
        up2.shutdown()
        up2.server_close()

        # ---- 6b. 中间人握手失败 → 自动改走透传
        print("\n6b) 中间人握手失败的主机会被自动透传")
        up_tls2 = serve_http(UP_TLS, tls_ctx)
        time.sleep(0.3)

        def tls_get(trust, tag):
            """用指定信任库走 SOCKS5 发一个 HTTPS 请求。"""
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.load_verify_locations(cafile=trust)
            sk = socks5_connect(*UP_TLS)
            ts = c.wrap_socket(sk, server_hostname="127.0.0.1")
            ts.sendall(("GET /api/data?%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" % tag).encode())
            buf = b""
            while True:
                try:
                    chunk = ts.recv(65536)
                except Exception:
                    break
                if not chunk:
                    break
                buf += chunk
            ts.close()
            return parse_http(buf)

        # 只信任上游那张自签证书 → netlens 的伪造证书会被判为未知 CA，握手必然失败
        failed = False
        try:
            tls_get(cert_file, "first")
        except ssl.SSLError:
            failed = True
        except Exception:
            failed = True
        log(failed, "不认伪造证书的客户端握手失败（模拟 Electron / Node 程序）")

        time.sleep(0.6)
        tun = api("/api/tunnel")
        log("127.0.0.1" in tun["auto"], "该主机被自动加入透传名单：%s" % tun["auto"])

        # 第二次：这次应该直接透传，客户端看到的是上游真证书，校验通过
        try:
            status, _, body = tls_get(cert_file, "second")
            log(status == 200, "重试时直接透传，拿到 200（上游真证书校验通过）")
            log(b"upstream" in body, "透传后内容完整")
        except Exception as e:
            log(False, "重试仍然失败：%r" % e)

        # 清理：把它移出名单，免得影响后面的用例（也顺便验证移除接口）
        removed = api("/api/tunnel/remove", "POST", {"host": "127.0.0.1"})
        log(removed.get("ok") is True and "127.0.0.1" not in removed["auto"], "可以把主机移出自动透传名单")
        time.sleep(0.2)

        # ---- 7. 内嵌 mihomo：释放 + 启停
        # 注意：这里故意写入 tun.enable=false 的配置，
        # 免得自测真的去接管本机路由表。
        print("\n7) 内嵌 mihomo 的释放与启停")
        st0 = api("/api/mihomo")
        log(os.path.exists(st0["exePath"]), "mihomo.exe 已释放到运行目录")
        log(os.path.exists(st0["cfgPath"]), "config.yaml 已释放到运行目录")
        # 内置配置固定写的是 1080，而本进程监听的是 11080，
        # 所以这里必须报"不一致"——这正是界面要提示用户的场景
        log(st0["socks5"] == "127.0.0.1:1080", "读到内置配置的 SOCKS5 出站：%s" % st0["socks5"])
        log(st0["expectSocks"] == "%s:%d" % SOCKS, "读到本程序实际监听：%s" % st0["expectSocks"])
        log(st0["portMatch"] is False, "端口不一致时能识别出来（界面会给出警告）")
        log(st0["running"] is False, "初始状态为未运行")

        safe_cfg = "\n".join([
            "mixed-port: 17890",
            "mode: rule",
            "allow-lan: false",
            "log-level: info",
            "tun:",
            "  enable: false",
            "proxies:",
            '  - name: "LOCAL-SOCKS5"',
            "    type: socks5",
            "    server: 127.0.0.1",
            "    port: %d" % SOCKS[1],
            "rules:",
            "  - MATCH,DIRECT",
            "",
        ])
        saved = api("/api/mihomo/config", "POST", {"config": safe_cfg})
        log(saved["ok"] is True, "配置保存成功")
        log(saved["status"]["portMatch"] is True, "端口一致性校验通过（当前配置 %s）" % saved["status"]["socks5"])

        # 故意把端口改错，看它能不能识别出来
        bad = safe_cfg.replace("port: %d" % SOCKS[1], "port: 9999")
        badres = api("/api/mihomo/config", "POST", {"config": bad})
        log(badres["status"]["portMatch"] is False, "端口写错时能识别出不匹配")
        api("/api/mihomo/config", "POST", {"config": safe_cfg})

        started = api("/api/mihomo/start", "POST")
        log(started.get("ok") is True, "启动指令返回成功")
        pid = started["status"]["pid"]
        log(pid > 0, "拿到 mihomo 进程 PID %s" % pid)

        time.sleep(2.0)
        st1 = api("/api/mihomo")
        log(st1["running"] is True, "运行状态为 true")
        log(st1["uptimeSec"] >= 1, "运行时长已累计 %ss" % st1["uptimeSec"])
        ver = st1["version"] or ""
        log("Mihomo" in ver or ver == "", "版本信息：%s" % (ver[:60] or "(从日志里没读到，不影响)"))

        logs = api("/api/mihomo/log?since=0")
        log(len(logs["lines"]) > 0, "捕获到 mihomo 日志 %d 行" % len(logs["lines"]))
        if logs["lines"]:
            for l in logs["lines"][:2]:
                print("        " + l[:120])

        stopped = api("/api/mihomo/stop", "POST")
        log(stopped.get("ok") is True, "停止指令返回成功")
        time.sleep(0.5)
        st2 = api("/api/mihomo")
        log(st2["running"] is False, "停止后状态为未运行")

        # ---- 8. 默认等级：控制台不打印每条请求
        print("\n8) 控制台输出（默认等级）")
        out = "\n".join(STDOUT_LINES)
        log("netlens" in out, "打印了启动横幅")
        log("→ REQUEST" not in out, "没有打印每条请求")
        log("FAKE-IMAGE-PAYLOAD" not in out, "没有把二进制内容打进控制台")

        # ---- 9. -v 等级：打印每条请求，但二进制仍然只占一行
        print("\n9) 控制台输出（-v 等级）")
        up9 = serve_http(UP9)
        tmp9 = tempfile.mkdtemp(prefix="netlens-ca9-")
        p9 = subprocess.Popen([
            exe, "-web", "127.0.0.1:19601", "-socks", "127.0.0.1:11081",
            "-http", "127.0.0.1:18081", "-ca-dir", tmp9,
            "-no-browser", "-no-window", "-insecure-upstream", "-v",
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines9 = []

        def drain9():
            for line in p9.stdout:
                text = line.decode("utf-8", "replace")
                lines9.append(text)
                sys.stdout.write("    | " + text)
                sys.stdout.flush()
        threading.Thread(target=drain9, daemon=True).start()

        p9_proxy = ("127.0.0.1", 18081)
        for _ in range(60):
            try:
                proxy_get("/api/data", "%s:%d" % up9.server_address[:2], proxy=p9_proxy)
                break
            except Exception:
                time.sleep(0.25)
        proxy_get("/api/file", "%s:%d" % UP9, proxy=p9_proxy)
        time.sleep(0.8)
        blob = "".join(lines9)
        log("→ REQUEST" in blob, "-v 下会打印每条请求")
        log("[文件]" in blob and "image/png" in blob, "二进制响应只打一行 [文件] 说明")
        log("FAKE-IMAGE-PAYLOAD" not in blob, "二进制内容没有被打进控制台")
        p9.terminate()
        try:
            p9.wait(timeout=5)
        except Exception:
            p9.kill()
        up9.shutdown()
        shutil.rmtree(tmp9, ignore_errors=True)

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        for s in (up_http, up_tls):
            try:
                s.shutdown()
            except Exception:
                pass
        up_ws.close()
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + ("全部通过" if ok_all else "存在失败项"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
