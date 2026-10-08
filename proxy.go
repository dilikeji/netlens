package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config 是命令行配置。
type Config struct {
	WebAddr    string // 控制台页面
	SocksAddr  string // SOCKS5 入口
	HTTPAddr   string // HTTP 代理入口
	CADir      string
	RulesFile  string
	TunnelFile string // 「自动透传」名单的持久化文件
	BlockFile  string // 「屏蔽」名单的持久化文件
	MihomoDir  string // 内嵌 mihomo 的释放目录 / 工作目录
	MihomoAuto bool   // 启动时自动拉起 mihomo

	TunnelHosts []string
	HTTPPorts   map[string]struct{}
	TLSPorts    map[string]struct{}
	NoSniff     bool

	NoColor       bool
	LogLevel      LogLevel
	PrintMax      int   // 文本 body 的抓取上限
	MaxFile       int64 // 文件类 body 的抓取上限（页面可以按文本看、也能下载）
	MaxRecords    int
	MaxStoreBytes int64

	// ShowTunnel 决定"无法解析协议、只能字节透传"的连接要不要记进页面。
	// 默认不记：全量接管后这类连接（QUIC、私有协议…）数量很大，
	// 记下来只会把有用的 HTTP 记录挤掉。
	ShowTunnel bool

	// ShowOptions 决定 CORS 预检（OPTIONS）要不要记进页面。
	// 默认不记：量极大且没有内容价值，留着只会把列表刷满。
	// 注意这只影响"记不记"，请求照常转发——拦掉的话前端跨域会直接挂。
	ShowOptions bool

	// 桌面窗口
	NoWindow   bool   // 不建窗口，只跑服务
	WebDataDir string // WebView2 的数据/缓存目录

	InsecureUpstream bool
	InstallCA        bool
	NoBrowser        bool
}

// connInfo 描述"这条连接从哪来、被判定成什么协议"。
// 一条连接上的所有请求共享它。
type connInfo struct {
	Source string // socks5 / http-proxy
	Client string
	Proto  string
}

// Proxy 是整个程序的枢纽，同时扮演三个角色：
//  1. SOCKS5 出站代理（Mihomo / 系统全局代理指向这里）
//  2. 标准 HTTP 代理（CONNECT + 明文转发）
//  3. TLS 中间人，把解密后的明文 HTTP 交给 forward
//
// 所有可解析的事务都写进 Store，页面通过 SSE 实时拿到。
type Proxy struct {
	cfg   *Config
	ca    *CA
	log   *Logger
	store *Store
	rules *RuleStore
	tr    *http.Transport

	tunnels *TunnelList

	hiddenTunnels atomic.Int64 // 被过滤掉的透传连接数，页面上亮一下免得用户以为没流量
	hiddenOptions atomic.Int64 // 被过滤掉的 OPTIONS 请求数
}

// HiddenTunnels 返回被过滤掉的透传连接数。
func (p *Proxy) HiddenTunnels() int64 { return p.hiddenTunnels.Load() }

// HiddenOptions 返回被过滤掉的 OPTIONS 请求数。
func (p *Proxy) HiddenOptions() int64 { return p.hiddenOptions.Load() }

// bodyLimitFor 按 Content-Type 决定这个 body 抓多少。
//
// 文件（图片/音视频/压缩包…）默认不以文本方式展示，但用户可能想
// "以文本方式看看"或者"下载下来"，所以内容还是要抓一份——
// 只是用独立的、更小的上限：记录仓库是全局共享内存预算的，
// 抓太多大文件会把真正要看的文本记录挤出去。
func (p *Proxy) bodyLimitFor(contentType string) int {
	if looksLikeFile(nil, contentType) {
		return int(p.cfg.MaxFile)
	}
	return p.cfg.PrintMax
}

func NewProxy(cfg *Config, ca *CA, lg *Logger, store *Store, rules *RuleStore) *Proxy {
	tr := &http.Transport{
		Proxy:                 nil, // 直连出口，绝不再走系统代理，否则会形成环
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: cfg.InsecureUpstream,
		},
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, // 关闭 h2 协商
	}
	p := &Proxy{cfg: cfg, ca: ca, log: lg, store: store, rules: rules, tr: tr}
	p.tunnels = NewTunnelList(cfg.TunnelHosts, cfg.TunnelFile, store.BroadcastStatus)
	return p
}

// Tunnels 暴露透传名单给页面（自动学到的那些要能看、能删）。
func (p *Proxy) Tunnels() *TunnelList { return p.tunnels }

// ---------------------------------------------------------------- HTTP 代理入口

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ci := &connInfo{Source: "http-proxy"}
	if r.RemoteAddr != "" {
		ci.Client = r.RemoteAddr
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, ci)
		return
	}
	target := r.URL.Host
	if target == "" {
		target = r.Host
	}
	ci.Proto = "HTTP 代理（明文请求行）"
	p.forward("http", target, r, w, ci)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request, ci *connInfo) {
	host, port := splitHostPort(r.Host, "443")
	target := net.JoinHostPort(host, port)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "netlens: 服务器不支持连接劫持", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	// CONNECT 必须先回 200，客户端才会开始发数据
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = conn.Close()
		return
	}
	p.route(conn, host, port, target, ci)
}

// ---------------------------------------------------------------- SOCKS5 入口

func (p *Proxy) HandleSOCKSConn(conn net.Conn) {
	p.log.Debugf("SOCKS5 新连接 <- %s", conn.RemoteAddr())

	c, target, err := socks5Handshake(conn)
	if err != nil {
		p.log.Errorf("SOCKS5 握手失败 (%s): %v", conn.RemoteAddr(), err)
		_ = conn.Close()
		return
	}
	ci := &connInfo{Source: "socks5", Client: conn.RemoteAddr().String()}
	host, port := splitHostPort(target, "443")
	p.route(c, host, port, target, ci)
}

// ---------------------------------------------------------------- 分发

// route 决定一条已建立的目标连接怎么处理。
// SOCKS5 与 HTTP 代理两个入口都走这里，保证行为一致。
//
// 关键点：**不靠端口号猜协议**。只有明确配置过的端口才走捷径，
// 其余一律嗅探首个字节——否则挂 81 / 8000 / 8443 的接口会全部漏掉。
func (p *Proxy) route(conn net.Conn, host, port, target string, ci *connInfo) {
	if p.isHTTPPort(port) {
		ci.Proto = "端口 " + port + " 配置为明文 HTTP"
		if !p.serveConn(conn, "http", target, ci) {
			_ = conn.Close()
		}
		return
	}

	wantMITM := p.isTLSPort(port)
	if wantMITM {
		ci.Proto = "端口 " + port + " 配置为 TLS"
	}

	if !wantMITM && !p.cfg.NoSniff {
		kind, wrapped := sniffProtocol(conn)
		conn = wrapped // 嗅探预读的字节在这个包装里，后续必须用它
		switch kind {
		case protoHTTP:
			ci.Proto = "首字节嗅探 → 明文 HTTP"
			p.log.Infof("%s:%s %s，按 HTTP 解析", host, port, ci.Proto)
			if !p.serveConn(conn, "http", target, ci) {
				_ = conn.Close()
			}
			return
		case protoTLS:
			if p.skipMITM(host) {
				ci.Proto = "首字节嗅探 → TLS（在透传名单，不解密）"
				p.log.Infof("%s:%s %s", host, port, ci.Proto)
			} else {
				ci.Proto = "首字节嗅探 → TLS 中间人"
				p.log.Infof("%s:%s %s", host, port, ci.Proto)
				wantMITM = true
			}
		default:
			ci.Proto = "首字节嗅探 → 无法识别，字节透传"
			p.log.Infof("%s:%s %s", host, port, ci.Proto)
		}
	}

	if wantMITM && !p.skipMITM(host) {
		if !p.mitm(conn, host, target, ci) {
			_ = conn.Close()
		}
		return
	}
	p.tunnelClient(conn, target, host, port, ci)
}

func (p *Proxy) skipMITM(host string) bool { return p.tunnels.Has(host) }

func (p *Proxy) isHTTPPort(port string) bool {
	_, ok := p.cfg.HTTPPorts[port]
	return ok
}

func (p *Proxy) isTLSPort(port string) bool {
	_, ok := p.cfg.TLSPorts[port]
	return ok
}

// ---------------------------------------------------------------- TLS 中间人

// mitm 对 c 做 TLS 中间人，之后按 HTTP 解析。
// 返回 true 表示连接已被 WebSocket 接管，调用方不要再关它。
func (p *Proxy) mitm(c net.Conn, host, target string, ci *connInfo) bool {
	tlsConn := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		// 用 SNI 决定签哪张证书：客户端可能用 IP 连但带域名 SNI
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			name := chi.ServerName
			if name == "" {
				name = host
			}
			cert, err := p.ca.Leaf(name)
			if err != nil {
				return nil, err
			}
			p.log.Debugf("为 %s 签发伪造证书（客户端 SNI=%q）", name, chi.ServerName)
			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"http/1.1"},
			}, nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// 握手失败基本都是"对面不认我们的伪造证书"——Electron / Node 写的程序
		// 用的是自带 CA bundle，不读 Windows 证书库。这类连不上只能直接透传，
		// 所以把它记下来，同一主机的后续连接就不再尝试中间人。
		//
		// 当前这条连接救不回来（伪造证书已经发出去了，客户端正是因此才关的连接），
		// 但程序重试就能通。
		//
		// 超时不算——那多半只是客户端慢，不代表证书有问题。
		if !isTimeoutErr(err) {
			if p.tunnels.AddAuto(host) {
				p.log.Noticef("%s 中间人握手失败（%v），已自动加入透传名单，后续连接不再解密", host, err)
			}
		}
		p.log.Debugf("TLS 中间人握手失败 %s: %v", host, err)
		return false
	}
	state := tlsConn.ConnectionState()
	p.log.Debugf("TLS 已解密 %s ver=%s alpn=%q", host, tlsVersionName(state.Version), state.NegotiatedProtocol)

	return p.serveConn(tlsConn, "https", target, ci)
}

// serveConn 用一次性 listener 把单条连接交给 net/http 解析。
//
// 这么做是为了把 chunked / keep-alive / Expect:100-continue / Trailer
// 这些 HTTP/1.1 细节交给标准库，比自己写解析循环可靠得多。
//
// 它必须阻塞到连接真正结束——调用方返回后会关闭底层连接。
// 返回 true 表示连接已被 handler 接管（WebSocket），不能重复关闭。
func (p *Proxy) serveConn(conn net.Conn, scheme, target string, ci *connInfo) bool {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.forward(scheme, target, r, w, ci)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	done := make(chan struct{})
	var once sync.Once
	var hijacked atomic.Bool
	finish := func() { once.Do(func() { close(done) }) }
	srv.ConnState = func(_ net.Conn, st http.ConnState) {
		switch st {
		case http.StateHijacked:
			hijacked.Store(true)
			finish()
		case http.StateClosed:
			finish()
		}
	}

	go func() { _ = srv.Serve(&singleConnListener{conn: conn}) }()

	<-done
	_ = srv.Close()
	return hijacked.Load()
}

// singleConnListener 只吐一条连接，然后返回 io.EOF。
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, io.EOF
	}
	l.done = true
	return l.conn, nil
}
func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// ---------------------------------------------------------------- 请求转发

func (p *Proxy) forward(scheme, target string, r *http.Request, w http.ResponseWriter, ci *connInfo) {
	id := p.store.NextID()
	if r.URL.Scheme == "" {
		r.URL.Scheme = scheme
	}
	// 转发目标以连接上协商出的真实地址为准：Host 头允许省略端口，
	// 只按 Host 头连会把 81 端口的服务打到 80 去。
	r.URL.Host = ensurePort(r.Host, target)

	// WebSocket：握手也是 HTTP，但拿到 101 之后要接管 TCP 做帧级转发
	if isWebSocketUpgrade(r) {
		p.handleWebSocket(w, r, id, ci)
		return
	}

	reqBody := p.readRequestBody(r, p.bodyLimitFor(r.Header.Get("Content-Type")))
	rec := p.newRecord(id, scheme, r, ci, KindHTTP)
	rec.ReqSize = reqBody.Total()
	rec.ReqTrunc = reqBody.truncated
	// 是文件就额外打个标记（页面默认折叠内容、给"查看文本/下载"两个按钮），
	// 但内容照样留着——不然那两个按钮就成了摆设
	rec.ReqFile = classifyBody(reqBody.Bytes(), r.Header.Get("Content-Type"),
		r.Header.Get("Content-Encoding"), reqBody.Total())
	rec.ReqBody = reqBody.Blob()
	// OPTIONS 是 CORS 预检，量极大且没有内容价值，默认不入库。
	// 后续那些 p.store.Update(id, ...) 对不存在的记录是空操作，所以这里
	// 只是"不建记录"，转发逻辑一行都不用改。
	skip := r.Method == http.MethodOptions && !p.cfg.ShowOptions
	if skip {
		p.hiddenOptions.Add(1)
	} else {
		p.store.Add(rec)
		p.log.Request(rec)
	}

	// ① 锁定规则优先：命中就完全不访问上游，直接回伪造响应
	if rule := p.rules.Match(r.Method, rec.Host, rec.Port, rec.Path, r.URL.RawQuery,
		bodyHashOf(reqBody.Bytes()), reqBody.truncated); rule != nil {
		p.serveMock(w, rec, rule)
		return
	}

	// ② 正常转发
	outReq := r.Clone(context.Background())
	outReq.Close = false
	outReq.URL.Scheme = scheme
	outReq.URL.Host = r.URL.Host
	// outReq.Host 保留客户端原始 Host 头（虚拟主机可能依赖它）
	stripHopHeaders(outReq.Header)

	resp, err := p.tr.RoundTrip(outReq)
	if err != nil {
		msg := fmt.Sprintf("上游请求失败 %s://%s: %v", scheme, outReq.URL.Host, err)
		p.finishRecord(id, func(rr *Record) { rr.Err = msg })
		p.log.Errorf("#%d %s", id, msg)
		http.Error(w, "netlens: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	stripHopHeaders(resp.Header)
	// 响应头先落库，页面能立刻看到状态码，不用等 body 传完
	p.store.Update(id, func(rr *Record) {
		rr.Status = resp.StatusCode
		rr.RespHdr = headerPairs(resp.Header)
	})

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	capture := newBodyCapture(p.bodyLimitFor(resp.Header.Get("Content-Type")))
	p.copyResponse(w, resp.Body, capture)

	file := classifyBody(capture.Bytes(), resp.Header.Get("Content-Type"),
		resp.Header.Get("Content-Encoding"), capture.Total())
	p.finishRecord(id, func(rr *Record) {
		rr.Status = resp.StatusCode
		rr.RespSize = capture.Total()
		rr.RespTrunc = capture.truncated
		rr.RespFile = file
		rr.RespBody = capture.Blob()
	})
	if done, ok := p.store.Get(id); ok {
		p.log.Response(done)
	}
}

// serveMock 用锁定规则里的内容直接回应客户端。
//
// body 存的是**已解压**的内容，所以这里必须把 Content-Encoding 去掉，
// 否则客户端会拿一段明文去 gunzip，报错。
func (p *Proxy) serveMock(w http.ResponseWriter, rec *Record, rule *Rule) {
	body := rule.Body.Data
	hdr := pairsToHeader(rule.Hdr)
	hdr.Del("Content-Encoding")
	hdr.Del("Transfer-Encoding")
	hdr.Del("Content-Length")
	stripHopHeaders(hdr)
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	status := rule.Status
	if status == 0 {
		status = http.StatusOK
	}

	p.log.Mock(rec, rule)
	if rule.DelayMS > 0 {
		time.Sleep(time.Duration(rule.DelayMS) * time.Millisecond)
	}

	copyHeader(w.Header(), hdr)
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}

	p.store.Update(rec.ID, func(rr *Record) {
		rr.Mocked = true
		rr.RuleID = rule.ID
		rr.Status = status
		rr.RespHdr = headerPairs(hdr)
		rr.RespBody = Blob{Data: append([]byte(nil), body...)}
		rr.RespSize = int64(len(body))
		rr.End = time.Now()
		rr.DurMS = msSince(rec.Start)
	})
	if done, ok := p.store.Get(rec.ID); ok {
		p.log.Response(done)
	}
}

// newRecord 组装一条 HTTP 记录的公共字段。
func (p *Proxy) newRecord(id uint64, scheme string, r *http.Request, ci *connInfo, kind string) *Record {
	host, port := splitHostPort(r.URL.Host, defaultPort(scheme))
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	// net/http 在服务端会把 Host 从 Header 里摘出来单独放进 r.Host，
	// 直接照抄 r.Header 会让详情页少一个最重要的请求头，这里补回去。
	hdrs := [][2]string{}
	if r.Host != "" {
		hdrs = append(hdrs, [2]string{"Host", r.Host})
	}
	hdrs = append(hdrs, headerPairs(r.Header)...)

	rec := &Record{
		ID: id, Kind: kind, Scheme: scheme, Method: r.Method,
		Host: host, Port: port, Path: path, Query: r.URL.RawQuery,
		Source: ci.Source, Client: ci.Client, Proto: ci.Proto,
		ReqHdr: hdrs,
		Start:  time.Now(),
	}
	rec.URL = rec.fullURL()
	return rec
}

func (p *Proxy) finishRecord(id uint64, fn func(*Record)) {
	p.store.Update(id, func(rr *Record) {
		fn(rr)
		rr.End = time.Now()
		rr.DurMS = msSince(rr.Start)
	})
}

// readRequestBody 最多预读 limit 字节用于展示 / 规则匹配，
// 剩余部分仍然原样流式转发给上游——大文件上传不会被截断，也不会把内存吃爆。
func (p *Proxy) readRequestBody(r *http.Request, limit int) *bodyCapture {
	c := newBodyCapture(limit)
	if r.Body == nil || r.Body == http.NoBody || limit <= 0 {
		return c
	}

	head := make([]byte, limit)
	n, err := io.ReadFull(r.Body, head)
	head = head[:n]
	_, _ = c.Write(head)

	// ReadFull 返回 nil 说明读满了 PrintMax 字节（后面还有数据）；
	// 返回任何 error 都说明整个 body 已经读完。
	if err != nil {
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(head))
		if r.ContentLength >= 0 {
			r.ContentLength = int64(n)
		}
		return c
	}

	c.truncated = true
	rest := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), rest), rest}
	return c
}

// copyResponse 边转发边采集前 PrintMax 字节，并且每块都 Flush，
// 保证 SSE / 流式响应不被缓冲卡住。
func (p *Proxy) copyResponse(w http.ResponseWriter, body io.Reader, cap *bodyCapture) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_, _ = cap.Write(buf[:n])
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// ---------------------------------------------------------------- 字节透传

func (p *Proxy) tunnelClient(client net.Conn, target, host, port string, ci *connInfo) {
	defer func() { _ = client.Close() }()

	// 无法解析的流量默认不记录：全量接管后这类连接（QUIC、私有协议…）很多，
	// 记下来除了刷屏没有任何用，还会把真正要看的 HTTP 记录挤出去。
	// 只想确认"确实有流量"，看页面状态栏那个被隐藏的计数就够了。
	if !p.cfg.ShowTunnel {
		p.hiddenTunnels.Add(1)
		up, err := net.DialTimeout("tcp", target, 15*time.Second)
		if err != nil {
			p.log.Debugf("透传连接 %s 失败: %v", target, err)
			return
		}
		defer func() { _ = up.Close() }()
		p.copyBoth(client, up)
		return
	}

	id := p.store.NextID()
	rec := &Record{
		ID: id, Kind: KindTCP, Scheme: "tcp", Method: "-",
		Host: host, Port: port,
		Source: ci.Source, Client: ci.Client, Proto: ci.Proto,
		Start: time.Now(), Note: "无法解析协议，按字节原样透传",
	}
	rec.URL = host + ":" + port
	p.store.Add(rec)
	p.log.Tunnel(true, id, host, port, 0, 0, 0)

	up, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		msg := fmt.Sprintf("连接 %s 失败: %v", target, err)
		p.finishRecord(id, func(rr *Record) { rr.Err = msg })
		p.log.Errorf("%s", msg)
		return
	}
	defer func() { _ = up.Close() }()

	start := time.Now()
	sent, recv := p.copyBoth(client, up)
	dur := time.Since(start)
	p.store.Update(id, func(rr *Record) {
		rr.ReqSize = sent
		rr.RespSize = recv
		rr.End = time.Now()
		rr.DurMS = float64(dur.Milliseconds())
	})
	p.log.Tunnel(false, id, host, port, sent, recv, dur)
}

// copyBoth 双向原样转发，返回上行 / 下行字节数。
// 一侧读完就 CloseWrite 唤醒对侧，等两边都结束才返回。
func (p *Proxy) copyBoth(client, up net.Conn) (sent, recv int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sent, _ = io.Copy(up, client)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	recv, _ = io.Copy(client, up)
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	wg.Wait()
	return sent, recv
}

// ---------------------------------------------------------------- 工具函数

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }

// isTimeoutErr 区分"客户端太慢"和"客户端不认证书"——只有后者值得自动透传。
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func splitHostPort(hostport, defPort string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, defPort
}

// ensurePort 保证 host 带上端口，省略时用连接上真实协商出来的端口。
func ensurePort(host, target string) string {
	if host == "" {
		return target
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if _, port, err := net.SplitHostPort(target); err == nil && port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization", "Te",
	"Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Del(tok)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return "TLS?" + strconv.Itoa(int(v))
}

func defaultPort(scheme string) string {
	if scheme == "http" || scheme == "ws" {
		return "80"
	}
	return "443"
}
