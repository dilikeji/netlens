package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

// App 是控制台后端的装配点：把 Store / RuleStore / Proxy 串到 HTTP 接口上。
type App struct {
	cfg     *Config
	ca      *CA
	proxy   *Proxy
	store   *Store
	rules   *RuleStore
	mihomo  *Mihomo
	blocked *BlockStore
	log     *Logger
	startAt time.Time
	webURL  string

	caMu sync.Mutex
	caOK bool // 根证书是否已在系统信任库里
}

// CAInstalled 返回缓存的检测结果（启动时查一次，装完再查一次）。
func (a *App) CAInstalled() bool {
	a.caMu.Lock()
	defer a.caMu.Unlock()
	return a.caOK
}

// RefreshCA 重新检查根证书是否已被系统信任。
// 查一次要起一个 certutil 进程（几十毫秒），所以只在启动和安装之后调。
func (a *App) RefreshCA() {
	ok := caTrusted(a.cfg.CADir)
	a.caMu.Lock()
	changed := ok != a.caOK
	a.caOK = ok
	a.caMu.Unlock()
	if changed {
		a.log.Noticef("根证书信任状态：%v", ok)
	}
}

func NewApp(cfg *Config, ca *CA, proxy *Proxy, store *Store, rules *RuleStore,
	mh *Mihomo, blocked *BlockStore, lg *Logger) *App {
	return &App{cfg: cfg, ca: ca, proxy: proxy, store: store, rules: rules,
		mihomo: mh, blocked: blocked, log: lg, startAt: time.Now()}
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /api/status", a.handleStatus)
	mux.HandleFunc("GET /api/events", a.handleEvents)
	mux.HandleFunc("GET /api/records", a.handleRecords)
	mux.HandleFunc("GET /api/records/{id}", a.handleRecordDetail)
	mux.HandleFunc("POST /api/records/clear", a.handleClear)
	mux.HandleFunc("GET /api/rules", a.handleRuleList)
	mux.HandleFunc("POST /api/rules", a.handleRuleCreate)
	mux.HandleFunc("POST /api/rules/{id}", a.handleRuleUpdate)
	mux.HandleFunc("DELETE /api/rules/{id}", a.handleRuleDelete)
	mux.HandleFunc("GET /api/ca.crt", a.handleCACert)
	mux.HandleFunc("POST /api/ca/install", a.handleCAInstall)
	mux.HandleFunc("GET /api/mihomo", a.handleMihomoStatus)
	mux.HandleFunc("POST /api/mihomo/start", a.handleMihomoStart)
	mux.HandleFunc("POST /api/mihomo/stop", a.handleMihomoStop)
	mux.HandleFunc("GET /api/mihomo/config", a.handleMihomoConfigGet)
	mux.HandleFunc("POST /api/mihomo/config", a.handleMihomoConfigSet)
	mux.HandleFunc("POST /api/mihomo/config/reset", a.handleMihomoConfigReset)
	mux.HandleFunc("GET /api/mihomo/log", a.handleMihomoLog)
	mux.HandleFunc("POST /api/mihomo/open-dir", a.handleMihomoOpenDir)
	mux.HandleFunc("GET /api/tunnel", a.handleTunnelList)
	mux.HandleFunc("POST /api/tunnel/remove", a.handleTunnelRemove)
	mux.HandleFunc("GET /api/blocked", a.handleBlockedList)
	mux.HandleFunc("POST /api/blocked", a.handleBlockedAdd)
	mux.HandleFunc("DELETE /api/blocked/{id}", a.handleBlockedRemove)
	mux.HandleFunc("GET /api/records/{id}/body", a.handleRecordBody)
	return mux
}

// handleRecordBody 把记录的 body 原样吐出来，供页面下载。
//
// 有 Content-Encoding 就先解压再给：用户点"下载"想要的是那个文件本身，
// 不是它在路上被 gzip 压缩后的样子。
func (a *App) handleRecordBody(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "记录号不合法")
		return
	}
	rec, ok := a.store.Get(id)
	if !ok {
		httpError(w, 404, "记录不存在或已被淘汰")
		return
	}

	reqSide := r.URL.Query().Get("which") == "req"
	body, hdr := rec.RespBody, rec.RespHdr
	if reqSide {
		body, hdr = rec.ReqBody, rec.ReqHdr
	}
	data := body.Data
	if len(data) == 0 {
		httpError(w, 404, "这条记录没有抓到内容（body 为空，或已被内存预算淘汰）")
		return
	}
	if dec, ok := decodeBody(data, headerValue(hdr, "Content-Encoding")); ok {
		data = dec
	}

	ct := headerValue(hdr, "Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+downloadName(id, reqSide, ct)+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if rec.RespTrunc && !reqSide {
		// 抓取有上限，超过的部分本来就没存下来
		w.Header().Set("X-Netlens-Truncated", "1")
	}
	_, _ = w.Write(data)
}

// downloadName 按 Content-Type 猜个像样的扩展名，猜不到就用 .bin。
func downloadName(id uint64, reqSide bool, contentType string) string {
	side := "resp"
	if reqSide {
		side = "req"
	}
	ext := ".bin"
	if list, err := mime.ExtensionsByType(mediaType(contentType)); err == nil && len(list) > 0 {
		ext = list[0]
	}
	return fmt.Sprintf("netlens-%d-%s%s", id, side, ext)
}

// ---------------------------------------------------------------- 透传名单

func (a *App) handleTunnelList(w http.ResponseWriter, r *http.Request) {
	t := a.proxy.Tunnels()
	writeJSON(w, map[string]any{"manual": t.Manual(), "auto": t.Auto()})
}

func (a *App) handleTunnelRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if !a.proxy.Tunnels().Remove(req.Host) {
		httpError(w, 404, "「"+req.Host+"」不在自动透传名单里")
		return
	}
	a.log.Noticef("已把 %s 移出自动透传名单，下次会重新尝试解密", req.Host)
	writeJSON(w, map[string]any{"ok": true, "auto": a.proxy.Tunnels().Auto()})
}

// ---------------------------------------------------------------- 屏蔽名单

func (a *App) handleBlockedList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"blocked": a.blocked.List()})
}

// handleBlockedAdd 支持两种用法：带 fromId 从记录派生域名，或直接给 host。
// 屏蔽粒度是整个域名——它下面所有路径都不再展示。
func (a *App) handleBlockedAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromID uint64 `json:"fromId"`
		Host   string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if req.FromID > 0 {
		rec, ok := a.store.Get(req.FromID)
		if !ok {
			httpError(w, 404, "记录不存在或已被淘汰")
			return
		}
		req.Host = rec.Host
	}
	if strings.TrimSpace(req.Host) == "" {
		httpError(w, 400, "缺少 host")
		return
	}
	item, added := a.blocked.Add(req.Host)
	if added {
		a.log.Noticef("已屏蔽域名 %s（该域名下所有请求都不再展示，流量照常转发）", item.Host)
	}
	writeJSON(w, map[string]any{"item": item, "added": added, "blocked": a.blocked.List()})
}

func (a *App) handleBlockedRemove(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		httpError(w, 400, "屏蔽项号不合法")
		return
	}
	if !a.blocked.Remove(id) {
		httpError(w, 404, "屏蔽项不存在")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "blocked": a.blocked.List()})
}

// handleMihomoOpenDir 在资源管理器里打开运行目录，方便直接改 config.yaml。
func (a *App) handleMihomoOpenDir(w http.ResponseWriter, r *http.Request) {
	if err := a.mihomo.OpenDir(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(uiHTML)
}

// ---------------------------------------------------------------- 状态

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	n, bytes := a.store.Stats()
	writeJSON(w, map[string]any{
		"web":          a.webURL,
		"socks":        a.cfg.SocksAddr,
		"http":         a.cfg.HTTPAddr,
		"caPath":       CACertPath(a.cfg.CADir),
		"caCommonName": "netlens Root CA",
		"caInstalled":  a.CAInstalled(),
		"records":      n,
		"memBytes":     bytes,
		"rules":        a.rules.Count(),
		"maxRecords":   a.cfg.MaxRecords,
		"maxBytes":     a.cfg.MaxStoreBytes,
		"maxBody":      a.cfg.PrintMax,
		"uptimeSec":    int(time.Since(a.startAt).Seconds()),
		"mihomo":       a.mihomo.Status(),
		// 无法解析的透传连接默认不入库，只计数——
		// 让页面能说一句"确实有流量，只是都被过滤掉了"
		"hiddenTunnels": a.proxy.HiddenTunnels(),
		"showTunnel":    a.cfg.ShowTunnel,
		"hiddenOptions": a.proxy.HiddenOptions(),
		"showOptions":   a.cfg.ShowOptions,
		"tunnelAuto":    len(a.proxy.Tunnels().Auto()),
		"tunnelManual":  len(a.proxy.Tunnels().Manual()),
		"blocked":       len(a.blocked.List()),
	})
}

// ---------------------------------------------------------------- mihomo

func (a *App) handleMihomoStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.mihomo.Status())
}

func (a *App) handleMihomoStart(w http.ResponseWriter, r *http.Request) {
	if err := a.mihomo.Start(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	a.store.BroadcastStatus()
	writeJSON(w, map[string]any{"ok": true, "status": a.mihomo.Status()})
}

func (a *App) handleMihomoStop(w http.ResponseWriter, r *http.Request) {
	if err := a.mihomo.Stop(); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	a.store.BroadcastStatus()
	writeJSON(w, map[string]any{"ok": true, "status": a.mihomo.Status()})
}

func (a *App) handleMihomoConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.mihomo.Config()
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"config": cfg, "path": a.mihomo.CfgPath()})
}

// handleMihomoConfigSet 保存配置。
// 正在运行时改配置不会立刻生效——mihomo 只在启动时读一次，所以这里明确提示要重启。
func (a *App) handleMihomoConfigSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, 400, "请求体解析失败: "+err.Error())
		return
	}
	if err := a.mihomo.SetConfig(req.Config); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	note := ""
	if a.mihomo.IsRunning() {
		note = "（需要重启 mihomo 才生效）"
	}
	a.mihomo.appendLog("配置已更新" + note)
	writeJSON(w, map[string]any{"ok": true, "status": a.mihomo.Status()})
}

func (a *App) handleMihomoConfigReset(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.mihomo.ResetConfig()
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	a.mihomo.appendLog("配置已恢复为内置默认值（需要重启 mihomo 才生效）")
	writeJSON(w, map[string]any{"ok": true, "config": cfg, "status": a.mihomo.Status()})
}

func (a *App) handleMihomoLog(w http.ResponseWriter, r *http.Request) {
	since := atoiDefault(r.URL.Query().Get("since"), 0)
	lines, total := a.mihomo.Logs(since)
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, map[string]any{"lines": lines, "total": total})
}

// ---------------------------------------------------------------- 记录

func (a *App) handleRecords(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 500)
	var out []*Record
	if since := atoiDefault(r.URL.Query().Get("since"), 0); since > 0 {
		out = a.store.ListSince(uint64(since), limit)
	} else {
		out = a.store.List(limit)
	}
	if out == nil {
		out = []*Record{}
	}
	writeJSON(w, map[string]any{"records": out, "total": a.store.Count()})
}

func (a *App) handleRecordDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "记录号不合法")
		return
	}
	rec, ok := a.store.Get(id)
	if !ok {
		httpError(w, 404, "记录不存在或已被淘汰")
		return
	}
	decorate(rec)
	rec.RawRequest = rawRequest(rec)
	rec.RawResponse = rawResponse(rec)
	writeJSON(w, map[string]any{"record": rec, "rules": a.rules.List()})
}

// decorate 准备详情页要用的 body：
//
//  1. 补上"这是不是文件"的标记（文件在页面上默认折叠，给"查看文本/下载"两个按钮）；
//  2. 是文本 → 再给一份解压后的内容，页面展示和编辑都用这份"看得懂"的。
//
// 注意文件的内容不再丢掉：页面上有"以文本方式查看"和"下载"两个按钮，
// 内容没了这两个按钮就是摆设。内存占用由抓取上限和仓库的总预算一起兜着。
func decorate(r *Record) {
	if r.ReqFile == nil && len(r.ReqBody.Data) > 0 {
		if f := classifyBody(r.ReqBody.Data, headerValue(r.ReqHdr, "Content-Type"),
			headerValue(r.ReqHdr, "Content-Encoding"), r.ReqSize); f != nil {
			r.ReqFile = f
		}
	}
	if r.RespFile == nil && len(r.RespBody.Data) > 0 {
		if f := classifyBody(r.RespBody.Data, headerValue(r.RespHdr, "Content-Type"),
			headerValue(r.RespHdr, "Content-Encoding"), r.RespSize); f != nil {
			r.RespFile = f
		}
	}

	if r.ReqFile == nil && len(r.ReqBody.Data) > 0 {
		if dec, ok := decodeBody(r.ReqBody.Data, headerValue(r.ReqHdr, "Content-Encoding")); ok {
			r.ReqBodyDecoded = Blob{Data: dec}
			r.ReqDecoded = true
		}
	}
	if r.RespFile == nil && len(r.RespBody.Data) > 0 {
		if dec, ok := decodeBody(r.RespBody.Data, headerValue(r.RespHdr, "Content-Encoding")); ok {
			r.RespBodyDecoded = Blob{Data: dec}
			r.RespDecoded = true
		}
	}
}

func (a *App) handleClear(w http.ResponseWriter, r *http.Request) {
	a.store.Clear()
	writeJSON(w, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- 规则

func (a *App) handleRuleList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"rules": a.rules.List()})
}

// ruleRequest 是页面提交的"锁定"请求。
//
// 两种用法：
//   - 带 fromId：从某条已有记录派生匹配条件（推荐，页面就是这么干的）
//   - 不带 fromId：完全手工指定 method/host/port/path
//
// 无论哪种用法，status / hdr / body / delayMs 都是"要伪造的响应"。
type ruleRequest struct {
	FromID      uint64      `json:"fromId"`
	Name        string      `json:"name"`
	Status      int         `json:"status"`
	Hdr         [][2]string `json:"hdr"`
	Body        Blob        `json:"body"`
	DelayMS     int         `json:"delayMs"`
	IgnoreQuery bool        `json:"ignoreQuery"`
	MatchBody   bool        `json:"matchBody"`

	Method string `json:"method"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	Path   string `json:"path"`
	Query  string `json:"query"`
}

func (a *App) handleRuleCreate(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, 400, "请求体解析失败: "+err.Error())
		return
	}

	rule := &Rule{
		Name:        strings.TrimSpace(req.Name),
		Enabled:     true,
		Method:      strings.ToUpper(strings.TrimSpace(req.Method)),
		Host:        strings.ToLower(strings.TrimSpace(req.Host)),
		Port:        strings.TrimSpace(req.Port),
		Path:        strings.TrimSpace(req.Path),
		Query:       req.Query,
		IgnoreQuery: req.IgnoreQuery,
		Status:      req.Status,
		Hdr:         req.Hdr,
		Body:        req.Body,
		DelayMS:     req.DelayMS,
		FromID:      req.FromID,
	}

	// 从记录派生匹配条件：这样页面只需要传"改成了什么"，不用重传匹配字段
	if req.FromID > 0 {
		rec, ok := a.store.Get(req.FromID)
		if !ok {
			httpError(w, 404, "来源记录不存在或已被淘汰")
			return
		}
		rule.Method = rec.Method
		rule.Host = strings.ToLower(rec.Host)
		rule.Port = rec.Port
		rule.Path = rec.Path
		rule.Query = rec.Query
		rule.KindHint = rec.Kind
		if req.MatchBody {
			if rec.ReqTrunc {
				httpError(w, 400, "该请求体被截断（超过抓取上限），无法按请求体精确匹配")
				return
			}
			rule.BodyHash = bodyHashOf(rec.ReqBody.Data)
		}
	}

	// 兜底：伪造响应必须有一个合理的状态码
	if rule.Status == 0 {
		rule.Status = http.StatusOK
	}
	if rule.Name == "" {
		rule.Name = defaultRuleName(rule)
	}
	// 存进规则里的 body 是"直接回给客户端的字节"，
	// 所以不能保留 Content-Encoding（内容已经被我们解压成明文了）
	rule.Hdr = stripEncodingHeaders(rule.Hdr)

	created := a.rules.Add(rule)
	a.store.broadcastRules()
	a.log.Noticef("新增锁定规则 #%d %s（%s）", created.ID, created.Pattern(), created.Name)
	writeJSON(w, map[string]any{"rule": created})
}

func (a *App) handleRuleUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "规则号不合法")
		return
	}
	var req struct {
		Enabled *bool       `json:"enabled"`
		Status  *int        `json:"status"`
		Hdr     [][2]string `json:"hdr"`
		Body    *Blob       `json:"body"`
		DelayMS *int        `json:"delayMs"`
		Name    *string     `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, 400, "请求体解析失败: "+err.Error())
		return
	}

	updated, ok := a.rules.Update(id, func(rl *Rule) {
		if req.Enabled != nil {
			rl.Enabled = *req.Enabled
		}
		if req.Status != nil {
			rl.Status = *req.Status
		}
		if req.Hdr != nil {
			rl.Hdr = stripEncodingHeaders(req.Hdr)
		}
		if req.Body != nil {
			rl.Body = *req.Body
		}
		if req.DelayMS != nil {
			rl.DelayMS = *req.DelayMS
		}
		if req.Name != nil {
			rl.Name = *req.Name
		}
	})
	if !ok {
		httpError(w, 404, "规则不存在")
		return
	}
	a.store.broadcastRules()
	writeJSON(w, map[string]any{"rule": updated})
}

func (a *App) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, 400, "规则号不合法")
		return
	}
	if !a.rules.Delete(id) {
		httpError(w, 404, "规则不存在")
		return
	}
	a.store.broadcastRules()
	a.log.Noticef("已解除锁定规则 #%d", id)
	writeJSON(w, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- 推送

// handleEvents 用 SSE 把增量推给页面。
//
// 为什么不用 WebSocket：这里只需要单向推送，SSE 是标准库 + 浏览器原生，
// 断线还会自动重连，少一个需要维护的协议实现。
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpError(w, 500, "当前服务器不支持流式响应")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	id, sub := a.store.subscribe()
	defer a.store.unsubscribe(id)

	fmt.Fprintf(w, "data: {\"t\":\"hello\",\"total\":%d}\n\n", a.store.Count())
	fl.Flush()

	resyncTick := time.NewTicker(time.Second)
	defer resyncTick.Stop()
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-sub.ch:
			if !ok {
				return
			}
			if _, err := w.Write(msg); err != nil {
				return
			}
			fl.Flush()
		case <-resyncTick.C:
			if sub.resync.Swap(false) {
				if _, err := io.WriteString(w, "data: {\"t\":\"resync\"}\n\n"); err != nil {
					return
				}
				fl.Flush()
			}
		case <-keepAlive.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// ---------------------------------------------------------------- 证书

func (a *App) handleCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="netlens-ca.crt"`)
	_, _ = w.Write(a.ca.CertPEM())
}

func (a *App) handleCAInstall(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("certutil", "-addstore", "-f", "ROOT", CACertPath(a.cfg.CADir)).CombinedOutput()
	msg := strings.TrimSpace(string(out))
	// 不管成功失败都重新查一次：失败也可能是因为本来就装过了
	a.RefreshCA()
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": msg,
			"hint": "需要以管理员身份运行 netlens", "installed": a.CAInstalled()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg, "installed": a.CAInstalled()})
}

// ---------------------------------------------------------------- 工具

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func defaultRuleName(r *Rule) string {
	name := r.Method
	if name == "" {
		name = "ANY"
	}
	name += " " + r.Host + r.Path
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

// stripEncodingHeaders 去掉编码/长度相关的头。
//
// 规则里保存的 body 已经是解压后的明文，长度也由服务端按实际字节数重新算，
// 留着 Content-Encoding: gzip 会让客户端拿明文去 gunzip 而报错。
func stripEncodingHeaders(hdr [][2]string) [][2]string {
	out := make([][2]string, 0, len(hdr))
	for _, kv := range hdr {
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "content-encoding", "content-length", "transfer-encoding":
			continue
		}
		out = append(out, kv)
	}
	return out
}
