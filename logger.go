package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	cReset   = "\x1b[0m"
	cDim     = "\x1b[2m"
	cBold    = "\x1b[1m"
	cRed     = "\x1b[31m"
	cGreen   = "\x1b[32m"
	cYellow  = "\x1b[33m"
	cMagenta = "\x1b[35m"
	cCyan    = "\x1b[36m"
	cGray    = "\x1b[90m"
	cBRed    = "\x1b[91m"
	cBGreen  = "\x1b[92m"
	cBYellow = "\x1b[93m"
	cBCyan   = "\x1b[96m"
)

const lineWidth = 78

// LogLevel 控制控制台打印多少东西。
//
// 为什么默认是"安静"：接管全部流量之后每条请求打一屏日志，
// 只会把真正要看的错误冲走。看请求是页面的事，控制台留给"程序在干什么"。
type LogLevel int

const (
	LogQuiet   LogLevel = iota // 只有启动横幅和错误
	LogNormal                  // + 关键事件（起停、规则变更）
	LogVerbose                 // + 每条请求/响应、协议判定、子进程输出
)

// Logger 只负责往控制台打字。页面上看到的内容与它无关
// （页面走 Store → SSE 那条路），所以这里可以放心按等级过滤。
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	color  bool
	level  LogLevel
	mirror func(string) // 同时把日志送一份到页面（桌面模式没有控制台可看）
}

func NewLogger(noColor bool, level LogLevel) *Logger {
	return &Logger{out: os.Stdout, color: !noColor, level: level}
}

// SetMirror 让日志在写控制台的同时也送一份给页面。
//
// 桌面模式下窗口一开，控制台就没了；如果日志只往 stdout 写，
// 出错时用户看到的就是"双击没反应"。所以这一步是必须的，不是锦上添花。
func (l *Logger) SetMirror(fn func(string)) {
	l.mu.Lock()
	l.mirror = fn
	l.mu.Unlock()
}

func (l *Logger) paint(code, s string) string {
	if !l.color {
		return s
	}
	return code + s + cReset
}

func (l *Logger) write(s string) {
	l.mu.Lock()
	_, _ = io.WriteString(l.out, s)
	mirror := l.mirror
	l.mu.Unlock()

	if mirror == nil {
		return
	}
	// 送进页面之前先剥掉 ANSI 颜色码，否则日志面板里全是转义序列。
	// 注意在锁外调用：mirror 会去拿 Store 的锁，别和自己嵌套。
	clean := ansiRe.ReplaceAllString(s, "")
	for _, line := range strings.Split(strings.TrimRight(clean, "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			mirror(line)
		}
	}
}

// Errorf 任何等级都打——出了问题还不知道为什么，是最难查的那种情况。
func (l *Logger) Errorf(format string, args ...any) {
	l.write(l.paint(cRed, "  ! "+fmt.Sprintf(format, args...)) + "\n")
}

// Noticef 是"程序做了什么决定"这类少量关键事件，默认等级就会打。
func (l *Logger) Noticef(format string, args ...any) {
	if l.level < LogNormal {
		return
	}
	l.write(l.paint(cBGreen, "  · "+fmt.Sprintf(format, args...)) + "\n")
}

// Infof 是每条连接的判定结论（协议嗅探结果），只在 -v 下打。
func (l *Logger) Infof(format string, args ...any) {
	if l.level < LogVerbose {
		return
	}
	l.write(l.paint(cGray, "  · "+fmt.Sprintf(format, args...)) + "\n")
}

func (l *Logger) Debugf(format string, args ...any) {
	if l.level < LogVerbose {
		return
	}
	l.write(l.paint(cGray, "  · "+fmt.Sprintf(format, args...)) + "\n")
}

// Child 打印子进程（mihomo）的输出。
//
// 只在 -v 下打到控制台：mihomo 在 info 级别就会为每条连接打一行，
// 全量接管后能刷满屏幕。这些日志仍然原样送到页面的日志面板，一条不少。
func (l *Logger) Child(tag, s string) {
	if l.level < LogVerbose {
		return
	}
	l.write(l.paint(cGray, "  │ "+tag+" ") + s + "\n")
}

func (l *Logger) Banner(cfg *Config, ca *CA, webURL string, mh *Mihomo) {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(l.paint(cBCyan, "  netlens") +
		l.paint(cGray, "  ·  App 流量控制台（HTTP / HTTPS / WebSocket）") + "\n")
	b.WriteString(l.paint(cGray, "  "+strings.Repeat("─", lineWidth)) + "\n")
	if cfg.NoWindow {
		fmt.Fprintf(&b, "  控制台   %s\n", l.paint(cBGreen, webURL))
	} else {
		fmt.Fprintf(&b, "  窗口     %s   %s\n", l.paint(cBGreen, webURL),
			l.paint(cGray, "← 在桌面窗口里显示，链接仍可用浏览器打开"))
	}
	if cfg.SocksAddr != "" {
		fmt.Fprintf(&b, "  SOCKS5   %s   %s\n", l.paint(cBGreen, cfg.SocksAddr),
			l.paint(cGray, "← 出站代理指向这里"))
	}
	if cfg.HTTPAddr != "" {
		fmt.Fprintf(&b, "  HTTP     %s   %s\n", l.paint(cBGreen, cfg.HTTPAddr),
			l.paint(cGray, "← 也可以只给某个程序配代理"))
	}
	fmt.Fprintf(&b, "  根证书   %s\n", l.paint(cYellow, CACertPath(cfg.CADir)))
	if mh != nil {
		st := mh.Status()
		state := l.paint(cGray, "未运行（页面上一键启动）")
		if st.Running {
			state = l.paint(cBGreen, fmt.Sprintf("运行中 PID %d", st.PID))
		}
		fmt.Fprintf(&b, "  mihomo   %s · %s\n", l.paint(cGray, st.Dir), state)
		perm := l.paint(cBGreen, "管理员（已提权）")
		if !st.Elevated {
			perm = l.paint(cYellow, "普通权限 —— TUN 会启动失败，请「以管理员身份运行」")
		}
		fmt.Fprintf(&b, "  权限     %s\n", perm)
		if !st.PortMatch {
			fmt.Fprintf(&b, "  %s\n", l.paint(cYellow,
				"注意：配置里 socks5 出站是 "+st.Socks5+"，与本程序监听的 "+st.ExpectSocks+" 不一致，流量不会到达页面"))
		}
	}
	if len(cfg.TunnelHosts) > 0 {
		fmt.Fprintf(&b, "  透传名单 %s\n", l.paint(cGray, strings.Join(cfg.TunnelHosts, ", ")+"（不解密）"))
	}
	logHint := "  日志     安静（只打横幅和错误）"
	switch l.level {
	case LogNormal:
		logHint = "  日志     关键事件（加 -v 可打印每条请求）"
	case LogVerbose:
		logHint = "  日志     详细（每条请求/响应 + 协议判定 + 子进程输出）"
	}
	fmt.Fprintf(&b, "%s\n", l.paint(cGray, logHint))
	b.WriteString(l.paint(cGray, "  "+strings.Repeat("─", lineWidth)) + "\n\n")
	l.write(b.String())
}

// Request 打印一条请求（仅 -v）。
func (l *Logger) Request(r *Record) {
	if l.level < LogVerbose {
		return
	}
	var b strings.Builder
	right := ""
	if r.Kind == KindWS {
		right = l.paint(cMagenta, "WS 升级")
	}
	b.WriteString(l.head("→ REQUEST", cBCyan, r.ID, r.Start, right))
	fmt.Fprintf(&b, "%s %s\n", l.paint(cBold, r.Method), l.paint(cBold, r.fullURL()))
	if r.Client != "" {
		fmt.Fprintf(&b, "%s\n", l.paint(cGray, "from "+r.Source+" "+r.Client+"  ·  "+r.Proto))
	}
	for _, kv := range r.ReqHdr {
		fmt.Fprintf(&b, "%s%s\n", l.paint(cGray, kv[0]+": "), kv[1])
	}
	writeBodyBlock(&b, r.ReqBody, r.ReqFile, r.ReqHdr, r.ReqSize, r.ReqTrunc, l)
	l.write(b.String())
}

// Response 打印一条响应（仅 -v）。
func (l *Logger) Response(r *Record) {
	if l.level < LogVerbose {
		return
	}
	right := statusColor(r.Status, l)
	if r.DurMS > 0 {
		right += l.paint(cGray, " · ") + l.paint(cGray, fmt.Sprintf("%.0fms", r.DurMS))
	}
	if r.Mocked {
		right = l.paint(cBYellow, "已锁定") + l.paint(cGray, " · ") + right
	}
	var b strings.Builder
	b.WriteString(l.head("← RESPONSE", cGreen, r.ID, time.Now(), right))

	if r.Err != "" {
		b.WriteString(l.paint(cRed, "  "+r.Err) + "\n")
		l.write(b.String())
		return
	}
	for _, kv := range r.RespHdr {
		fmt.Fprintf(&b, "%s%s\n", l.paint(cGray, kv[0]+": "), kv[1])
	}
	writeBodyBlock(&b, r.RespBody, r.RespFile, r.RespHdr, r.RespSize, r.RespTrunc, l)
	l.write(b.String())
}

// Mock 打印规则接管的情况。
func (l *Logger) Mock(r *Record, rule *Rule) {
	if l.level < LogNormal {
		return
	}
	l.write(l.paint(cBYellow, fmt.Sprintf("  ◆ #%d 命中锁定规则 #%d %s —— 不访问上游，直接返回伪造响应\n",
		r.ID, rule.ID, rule.Pattern())))
}

func (l *Logger) WSFrame(id uint64, f *WSFrameRec) {
	if l.level < LogVerbose {
		return
	}
	arrow := "→"
	if f.Dir == "S→C" {
		arrow = "←"
	}
	var b strings.Builder
	b.WriteString(l.paint(cGray, "  ") + l.paint(cMagenta, arrow+" WS "+f.Opcode) +
		l.paint(cGray, fmt.Sprintf("  #%d  len=%d", id, f.Length)) + "\n")
	switch {
	case isTextOpcodeRec(f.Opcode) && len(f.Payload.Data) > 0:
		text := string(f.Payload.Data)
		if pretty, ok := tryPrettyJSON(f.Payload.Data); ok {
			text = pretty
		}
		lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
		if len(lines) > 40 {
			lines = append(lines[:40], "…")
		}
		for _, line := range lines {
			b.WriteString("    " + line + "\n")
		}
	case f.Length > 0:
		b.WriteString(l.paint(cGray, "    [文件] 二进制帧 · "+humanBytes(f.Length)+"（不打印内容）\n"))
	}
	l.write(b.String())
}

func (l *Logger) Tunnel(open bool, id uint64, host, port string, sent, recv int64, dur time.Duration) {
	if l.level < LogVerbose {
		return
	}
	if open {
		l.write(l.paint(cGray, fmt.Sprintf("  #%d  ⤳ 直连透传 %s:%s（未解密）\n", id, host, port)))
		return
	}
	l.write(l.paint(cGray, fmt.Sprintf("  #%d  ⤳ 透传结束 %s:%s  上行 %s / 下行 %s · %s\n",
		id, host, port, humanBytes(sent), humanBytes(recv), dur.Round(time.Millisecond))))
}

// ---------------------------------------------------------------- 渲染辅助

func (l *Logger) head(label, color string, id uint64, ts time.Time, right string) string {
	left := fmt.Sprintf("#%d %s", id, label)
	head := l.paint(cGray, ts.Format("15:04:05.000")) + " " + l.paint(color, l.paint(cBold, left))
	if right == "" {
		return "\n" + head + "\n"
	}
	pad := lineWidth - len(left) - 16 - len(right)
	if pad < 2 {
		pad = 2
	}
	return "\n" + head + l.paint(cGray, strings.Repeat(" ", pad)) + right + "\n"
}

// writeBodyBlock 打印 body。
//
// 文件（图片/音视频/压缩包…）只打一行说明，绝不打十六进制：
// 终端里那一屏乱码既看不懂，又会把上下文冲掉。
func writeBodyBlock(b *strings.Builder, body Blob, file *FileInfo, hdr [][2]string, total int64, truncated bool, l *Logger) {
	if file != nil {
		fmt.Fprintf(b, "%s\n", l.paint(cGray, "    [文件] "+orUnknown(file.ContentType)+
			" · "+humanBytes(file.Size)+"（二进制内容不打印）"))
		return
	}
	if len(body.Data) == 0 {
		return
	}
	enc := headerValue(hdr, "Content-Encoding")
	data, unzipped := decodeBody(body.Data, enc)

	note := ""
	if unzipped {
		note = "（已解压 " + enc + "）"
	}
	if !looksTextual(data) {
		fmt.Fprintf(b, "%s\n", l.paint(cGray, "    [文件] "+orUnknown(headerValue(hdr, "Content-Type"))+
			" · "+humanBytes(total)+"（二进制内容不打印）"))
		return
	}

	text := string(data)
	if pretty, ok := tryPrettyJSON(data); ok {
		text = pretty
		note += "（JSON 已格式化）"
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	const maxLines = 80
	for i, line := range lines {
		if i >= maxLines {
			fmt.Fprintf(b, "%s\n", l.paint(cGray, fmt.Sprintf("    …（共 %d 行，已截断）", len(lines))))
			break
		}
		b.WriteString("    " + line + "\n")
	}
	tail := fmt.Sprintf("共 %d 字节", total)
	if truncated {
		tail += "，已截断"
	}
	if note != "" || truncated {
		fmt.Fprintf(b, "%s\n", l.paint(cGray, "    "+tail+note))
	}
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "未知类型"
	}
	return s
}

func headerValue(hdr [][2]string, key string) string {
	for _, kv := range hdr {
		if strings.EqualFold(kv[0], key) {
			return kv[1]
		}
	}
	return ""
}

func isTextOpcodeRec(name string) bool { return name == "TEXT" || name == "CONT" }

func statusColor(code int, l *Logger) string {
	s := statusLine(code)
	switch {
	case code >= 500:
		return l.paint(cBRed, s)
	case code >= 400:
		return l.paint(cRed, s)
	case code >= 300:
		return l.paint(cYellow, s)
	case code >= 200:
		return l.paint(cBGreen, s)
	case code == int(http.StatusSwitchingProtocols):
		return l.paint(cMagenta, s)
	default:
		return l.paint(cGray, s)
	}
}
