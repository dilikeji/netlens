// netlens —— 面向 Windows 11 的 App 流量控制台。
//
// 数据流：
//
//	目标 App / 浏览器
//	   │  把代理指向 netlens（SOCKS5 或 HTTP 代理）
//	   ▼
//	netlens ── 拿到真实目标（域名:端口），不靠端口号猜协议：
//	   ├─ 配置过的明文端口      → 直接按 HTTP 解析
//	   ├─ 配置过的 TLS 端口     → 中间人解密后按 HTTP 解析
//	   ├─ 其他端口：嗅探首字节
//	   │     0x16        → TLS  → 中间人解密
//	   │     大写字母    → HTTP → 直接解析（含 WebSocket 升级）
//	   │     其他        → 字节透传，只记流量
//	   └─ 命中「锁定规则」→ 不访问上游，直接回你编辑过的响应
//	   │
//	   ▼
//	Internet
//
// 所有可解析的事务都进内存仓库，页面通过 SSE 实时刷新；
// 浏览器里点开任意一条，就能看到请求头、请求体、响应头、响应体，
// 以及 WebSocket 的每一帧。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	setupConsole() // Windows: 切 UTF-8 代码页 + 打开 ANSI 颜色
	cfg := parseFlags()

	lg := NewLogger(cfg.NoColor, cfg.LogLevel)

	if cfg.InstallCA {
		if err := installCA(cfg.CADir); err != nil {
			lg.Errorf("导入根证书失败: %v", err)
			lg.Errorf("请用「管理员身份」运行，或手动执行：certutil -addstore -f ROOT %s", CACertPath(cfg.CADir))
		} else {
			lg.Noticef("根证书已导入 Windows 受信任根证书颁发机构")
		}
	}

	ca, err := LoadOrCreateCA(cfg.CADir)
	if err != nil {
		lg.Errorf("初始化 CA 失败: %v", err)
		os.Exit(1)
	}

	store := NewStore(cfg.MaxRecords, cfg.MaxStoreBytes)
	blocked := NewBlockStore(cfg.BlockFile, store.BroadcastStatus)
	// 桌面模式下没有控制台窗口，程序自己的日志必须一并送进页面，
	// 否则出错了用户只能看到"双击没反应"。
	lg.SetMirror(store.EnqueueLog)

	rules := NewRuleStore(cfg.RulesFile)
	proxy := NewProxy(cfg, ca, lg, store, rules)
	mihomo := NewMihomo(cfg.MihomoDir, cfg.SocksAddr, cfg.MihomoAuto, lg, store)
	app := NewApp(cfg, ca, proxy, store, rules, mihomo, blocked, lg)

	var closers []interface{ Close() error }

	// ---- SOCKS5 入口（给 Mihomo / 支持 SOCKS5 的程序用）
	if cfg.SocksAddr != "" {
		ln, err := net.Listen("tcp", cfg.SocksAddr)
		if err != nil {
			lg.Errorf("监听 SOCKS5 %s 失败: %v", cfg.SocksAddr, err)
			os.Exit(1)
		}
		closers = append(closers, ln)
		go acceptLoop(ln, proxy, lg)
	}

	// ---- HTTP 代理入口
	if cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", cfg.HTTPAddr)
		if err != nil {
			lg.Errorf("监听 HTTP 代理 %s 失败: %v", cfg.HTTPAddr, err)
			os.Exit(1)
		}
		closers = append(closers, ln)
		srv := &http.Server{
			Handler:           proxy,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go func() { _ = srv.Serve(ln) }()
	}

	// ---- 控制台页面
	if cfg.WebAddr == "" {
		lg.Errorf("未指定控制台端口（-web），启动终止")
		os.Exit(1)
	}
	webLn, err := net.Listen("tcp", cfg.WebAddr)
	if err != nil {
		lg.Errorf("监听控制台 %s 失败: %v", cfg.WebAddr, err)
		os.Exit(1)
	}
	closers = append(closers, webLn)
	webURL := browserURL(cfg.WebAddr)
	app.webURL = webURL
	webSrv := &http.Server{
		Handler:           app.Routes(),
		ReadHeaderTimeout: 15 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = webSrv.Serve(webLn) }()

	lg.Banner(cfg, ca, webURL, mihomo)

	// 根证书是否已被系统信任要起一个 certutil 去查，放到后台做，别拖慢启动
	go app.RefreshCA()

	// mihomo 默认不自动拉起：TUN 模式要管理员权限、还会改路由表，
	// 不适合在用户没准备的时候偷偷启动。需要的话加 -mihomo-auto。
	if cfg.MihomoAuto {
		if err := mihomo.Start(); err != nil {
			lg.Errorf("自动启动 mihomo 失败: %v", err)
		}
	}

	if cfg.NoWindow {
		// 无窗口模式：和改造前一样跑服务、等退出信号。
		// 自动化测试和排查问题都靠它（GUI 子系统下从终端启动仍能看到日志）。
		if !cfg.NoBrowser {
			go openBrowser(webURL, lg)
		}
		waitForSignal()
	} else {
		// 桌面模式：服务已经全部就绪，再把窗口建起来。
		// 顺序很重要——反过来会先看到一个连不上的白屏。
		runDesktop(webURL, cfg.WebDataDir, lg)
	}

	lg.Noticef("正在关闭…")
	// 别把 mihomo 留成孤儿：它挂着 TUN 路由，用户下次会莫名其妙上不了网
	if mihomo.IsRunning() {
		if err := mihomo.Stop(); err != nil {
			lg.Errorf("停止 mihomo 失败: %v（请手动结束 mihomo.exe）", err)
		}
	}
	for _, c := range closers {
		_ = c.Close()
	}
	time.Sleep(120 * time.Millisecond)
}

// waitForSignal 阻塞到用户按下 Ctrl+C / 收到退出信号。
func waitForSignal() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

func acceptLoop(ln net.Listener, p *Proxy, lg *Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			lg.Errorf("accept 失败: %v", err)
			return
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					lg.Errorf("处理连接时 panic: %v", r)
				}
			}()
			p.HandleSOCKSConn(conn)
		}()
	}
}

// ---------------------------------------------------------------- 命令行

func parseFlags() *Config {
	cfg := &Config{}
	var tunnel, httpPorts, tlsPorts string
	var maxStoreMB int
	var showTunnel, showOptions, verbose, quiet bool

	flag.StringVar(&cfg.WebAddr, "web", "127.0.0.1:9600", "控制台页面监听地址，浏览器会自动打开它")
	flag.StringVar(&cfg.SocksAddr, "socks", "127.0.0.1:1080", "SOCKS5 入口监听地址，空字符串表示不启动")
	flag.StringVar(&cfg.HTTPAddr, "http", "127.0.0.1:8080", "HTTP 代理入口监听地址，空字符串表示不启动")
	flag.StringVar(&cfg.CADir, "ca-dir", defaultCADir(), "根证书存放目录")
	flag.StringVar(&cfg.RulesFile, "rules-file", "", "锁定规则的持久化文件（默认只存在内存里，重启即清空）")
	flag.StringVar(&cfg.MihomoDir, "mihomo-dir", "", "mihomo 运行目录（默认 <ca-dir>/runtime，内嵌的 mihomo.exe 与 config.yaml 会释放到这里）")
	flag.BoolVar(&cfg.MihomoAuto, "mihomo-auto", false, "启动时自动拉起 mihomo（TUN 接管需要管理员权限）")
	flag.StringVar(&tunnel, "tunnel", "", "不做中间人、直接透传的域名，逗号分隔（用于做了证书固定的 App）")
	flag.StringVar(&httpPorts, "http-ports", "80", "直接按明文 HTTP 解析的端口，逗号分隔")
	flag.StringVar(&tlsPorts, "tls-ports", "443", "做 TLS 中间人解密的端口，逗号分隔")
	flag.BoolVar(&cfg.NoSniff, "no-sniff", false, "关闭未知端口的首字节嗅探")
	flag.IntVar(&cfg.PrintMax, "max-body", 512*1024, "文本 body 每条记录最多抓取的字节数")
	flag.Int64Var(&cfg.MaxFile, "max-file", 1<<20, "文件类 body（图片/音视频/压缩包…）每条记录最多抓取的字节数，留 0 表示不抓（只统计大小）")
	flag.IntVar(&cfg.MaxRecords, "max-records", 2000, "内存里最多保留多少条记录")
	// 默认别给太大：这是常驻桌面的工具，实测 32MB 预算对应 RSS ~145MB，
	// 按比例 256MB 预算能把进程推到 1GB 以上。128MB 足够翻查几千条记录，
	// 页面状态栏会实时显示当前占用，不够再加。
	flag.IntVar(&maxStoreMB, "max-store-mb", 128, "记录占用的内存上限（MB）")
	flag.BoolVar(&cfg.InsecureUpstream, "insecure-upstream", false, "跳过上游服务器证书校验（目标站用自签证书时才用）")
	flag.BoolVar(&cfg.InstallCA, "install-ca", false, "启动时把根证书导入 Windows 受信任根（需要管理员权限）")
	flag.BoolVar(&cfg.NoBrowser, "no-browser", false, "启动后不自动打开浏览器（仅无窗口模式有效）")
	flag.BoolVar(&cfg.NoWindow, "no-window", false, "不打开桌面窗口，只在后台跑服务（自动化测试、排查问题时用）")
	flag.StringVar(&cfg.WebDataDir, "web-data-dir", "", "WebView2 的数据/缓存目录（默认 <ca-dir>/webview）")
	flag.BoolVar(&cfg.NoColor, "no-color", false, "关闭控制台彩色输出")
	flag.BoolVar(&showTunnel, "show-tunnel", false, "把「无法解析、只能字节透传」的连接也记到页面上（默认过滤掉，只留一个计数）")
	flag.BoolVar(&showOptions, "show-options", false, "把 CORS 预检（OPTIONS）也记到页面上（默认过滤掉，请求照常转发）")
	flag.BoolVar(&verbose, "v", false, "控制台打印每条请求/响应、协议判定和子进程输出（默认不打，看页面即可）")
	flag.BoolVar(&quiet, "quiet", false, "控制台只打印启动横幅和错误")
	flag.Parse()

	// 默认「安静」：接管全部流量后每条请求打一屏，只会把错误冲走。
	switch {
	case quiet:
		cfg.LogLevel = LogQuiet
	case verbose:
		cfg.LogLevel = LogVerbose
	default:
		cfg.LogLevel = LogNormal
	}
	cfg.ShowTunnel = showTunnel
	cfg.ShowOptions = showOptions

	for _, h := range strings.Split(tunnel, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.TunnelHosts = append(cfg.TunnelHosts, h)
		}
	}
	cfg.HTTPPorts = parsePortSet(httpPorts)
	cfg.TLSPorts = parsePortSet(tlsPorts)
	cfg.MaxStoreBytes = int64(maxStoreMB) << 20
	if cfg.PrintMax <= 0 {
		cfg.PrintMax = 512 * 1024
	}
	if cfg.MaxFile < 0 {
		cfg.MaxFile = 0
	}
	if cfg.MihomoDir == "" {
		cfg.MihomoDir = filepath.Join(cfg.CADir, "runtime")
	}
	if cfg.WebDataDir == "" {
		cfg.WebDataDir = filepath.Join(cfg.CADir, "webview")
	}
	// 「自动透传」和「屏蔽」都是"学到的状态"，必须落盘，
	// 否则每次重启都要让目标程序再失败一次、屏蔽过的 URL 又全冒出来
	if cfg.TunnelFile == "" {
		cfg.TunnelFile = filepath.Join(cfg.CADir, "tunnel-auto.json")
	}
	if cfg.BlockFile == "" {
		cfg.BlockFile = filepath.Join(cfg.CADir, "blocked.json")
	}
	return cfg
}

func parsePortSet(s string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

func defaultCADir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "netlens")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".netlens")
}

// installCA 用 Windows 自带的 certutil 把根证书装进"受信任的根证书颁发机构"。
func installCA(dir string) error {
	certPath := CACertPath(dir)
	if !fileExists(certPath) {
		return errors.New("根证书尚未生成，请先不带 -install-ca 运行一次")
	}
	out, err := exec.Command("certutil", "-addstore", "-f", "ROOT", certPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------------------------------------------------------------- 浏览器

// browserURL 把监听地址变成浏览器能访问的地址。
// 监听 0.0.0.0 或空主机时，本机访问要用 127.0.0.1。
func browserURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") { // IPv6 字面量
		host = "[" + host + "]"
	}
	return (&url.URL{Scheme: "http", Host: host + ":" + port, Path: "/"}).String()
}

func openBrowser(u string, lg *Logger) {
	// 给监听协程一点时间起来，避免浏览器抢在前面
	time.Sleep(300 * time.Millisecond)

	// 优先交给 explorer.exe 转发，而不是自己 ShellExecute。
	//
	// 本程序默认带 requireAdministrator 清单，是提升状态运行的；
	// 直接从提升进程打开浏览器，会把浏览器也拉成管理员身份，
	// 或者因为两个进程完整性级别不同、消息发不过去，导致又开一个新浏览器实例。
	// explorer.exe 本身以普通权限跑在桌面会话里，把 URL 交给它就绕开了这个坑。
	if err := exec.Command("explorer.exe", u).Start(); err == nil {
		lg.Noticef("已打开控制台：%s", u)
		return
	}

	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	if err := cmd.Start(); err != nil {
		lg.Errorf("自动打开浏览器失败: %v（请手动访问 %s）", err, u)
		return
	}
	lg.Noticef("已打开控制台：%s", u)
}
