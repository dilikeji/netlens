package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- 记录模型

// 记录种类
const (
	KindHTTP = "http" // 一次可解析的 HTTP 事务（含 https 解密后的）
	KindWS   = "ws"   // WebSocket 会话（握手 + 帧）
	KindTCP  = "tcp"  // 无法解析、字节透传的连接
)

// WSFrameRec 是 WebSocket 的一个帧（载荷已按 mask 解码）。
type WSFrameRec struct {
	Seq     int       `json:"seq"`
	Dir     string    `json:"dir"` // C→S / S→C
	Opcode  string    `json:"opcode"`
	Length  int64     `json:"len"`
	At      time.Time `json:"at"`
	Payload Blob      `json:"payload"`
}

// Record 是页面上一行，也是详情页的全部数据来源。
type Record struct {
	ID     uint64 `json:"id"`
	Kind   string `json:"kind"`
	Scheme string `json:"scheme"` // http / https / ws / wss / tcp
	Method string `json:"method"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	URL    string `json:"url"`

	Source string `json:"source"` // socks5 / http-proxy
	Client string `json:"client"` // 客户端地址
	Proto  string `json:"proto"`  // 协议判定依据（端口 or 首字节嗅探）

	ReqHdr   [][2]string `json:"reqHdr"`
	ReqBody  Blob        `json:"reqBody"`
	ReqSize  int64       `json:"reqSize"`
	ReqTrunc bool        `json:"reqTrunc"`
	// 非空表示请求体是文件（图片/上传等），页面只显示类型和大小
	ReqFile *FileInfo `json:"reqFile,omitempty"`

	RespHdr   [][2]string `json:"respHdr"`
	RespBody  Blob        `json:"respBody"`
	RespSize  int64       `json:"respSize"`
	RespTrunc bool        `json:"respTrunc"`
	// 非空表示响应体是文件，页面只显示类型和大小
	RespFile *FileInfo `json:"respFile,omitempty"`
	Status   int       `json:"status"`

	// 详情接口才会填：解码 Content-Encoding 之后的内容，供页面展示和编辑
	RespBodyDecoded Blob `json:"respBodyDecoded,omitempty"`
	RespDecoded     bool `json:"respDecoded,omitempty"`
	ReqBodyDecoded  Blob `json:"reqBodyDecoded,omitempty"`
	ReqDecoded      bool `json:"reqDecoded,omitempty"`

	Mocked bool  `json:"mocked"` // 是否由锁定规则伪造返回
	RuleID int64 `json:"ruleId,omitempty"`

	Err   string    `json:"err,omitempty"`
	Start time.Time `json:"start"`
	End   time.Time `json:"end,omitempty"`
	DurMS float64   `json:"durMs"`

	Frames []WSFrameRec `json:"frames,omitempty"`
	Note   string       `json:"note,omitempty"`

	// 只有详情接口才会填，便于页面直接展示原始报文
	RawRequest  string `json:"rawRequest,omitempty"`
	RawResponse string `json:"rawResponse,omitempty"`
}

// size 用于内存预算统计。
func (r *Record) size() int64 {
	n := int64(len(r.ReqBody.Data) + len(r.RespBody.Data))
	for i := range r.Frames {
		n += int64(len(r.Frames[i].Payload.Data))
	}
	return n + 512 // 结构体本身与头部的大致开销
}

// summary 去掉大字段，供列表 / SSE 推送使用。
func (r *Record) summary() *Record {
	c := *r
	c.ReqBody = Blob{}
	c.RespBody = Blob{}
	c.ReqBodyDecoded = Blob{}
	c.RespBodyDecoded = Blob{}
	if len(c.Frames) > 0 {
		fs := make([]WSFrameRec, len(c.Frames))
		for i := range c.Frames {
			fs[i] = c.Frames[i]
			fs[i].Payload = Blob{}
		}
		c.Frames = fs
	}
	return &c
}

// fullURL 还原请求的完整 URL。
func (r *Record) fullURL() string {
	scheme := r.Scheme
	host := r.Host
	if r.Port != "" && !isDefaultPort(scheme, r.Port) {
		host += ":" + r.Port
	}
	u := scheme + "://" + host + r.Path
	if r.Query != "" {
		u += "?" + r.Query
	}
	return u
}

func isDefaultPort(scheme, port string) bool {
	switch scheme {
	case "http", "ws":
		return port == "80"
	case "https", "wss":
		return port == "443"
	}
	return false
}

// ---------------------------------------------------------------- 增量推送包

// sseBatch 是推给页面的增量包。
// 高频流量下逐条推送会把浏览器打爆，所以在 Store 里按 ~120ms 合并一次。
type sseBatch struct {
	T     string    `json:"t"`
	Add   []*Record `json:"add,omitempty"`
	Upd   []*Record `json:"upd,omitempty"`
	Clear bool      `json:"clear,omitempty"`
	Rules bool      `json:"rules,omitempty"`
	Stat  bool      `json:"stat,omitempty"` // mihomo 等外部状态有变化
	Log   []string  `json:"log,omitempty"`  // 子进程日志行
}

type subscriber struct {
	ch     chan []byte
	resync atomic.Bool
}

// ---------------------------------------------------------------- 存储

// Store 是记录仓库：有界环形缓冲 + 增量广播。
//
// 并发规则：代理侧只能通过 Add / Update 改数据；读出去的一律是副本，
// 页面渲染不会和正在写入的记录打架。
type Store struct {
	mu       sync.RWMutex
	recs     map[uint64]*Record
	order    []uint64
	bytes    int64
	maxItems int
	maxBytes int64
	seq      atomic.Uint64

	subMu   sync.Mutex
	subs    map[int]*subscriber
	nextSub int

	pqMu    sync.Mutex
	pqAdd   []*Record
	pqUpd   map[uint64]*Record
	pqLog   []string
	pqClear bool
	pqRules bool
	pqStat  bool
}

func NewStore(maxItems int, maxBytes int64) *Store {
	if maxItems <= 0 {
		maxItems = 2000
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	s := &Store{
		recs:     make(map[uint64]*Record),
		maxItems: maxItems,
		maxBytes: maxBytes,
		subs:     make(map[int]*subscriber),
		pqUpd:    make(map[uint64]*Record),
	}
	go s.flushLoop()
	return s
}

func (s *Store) NextID() uint64 { return s.seq.Add(1) }

func (s *Store) Add(r *Record) {
	if r.Start.IsZero() {
		r.Start = time.Now()
	}
	s.mu.Lock()
	s.recs[r.ID] = r
	s.order = append(s.order, r.ID)
	s.bytes += r.size()
	s.evictLocked()
	snap := r.summary()
	s.mu.Unlock()

	s.enqueueAdd(snap)
}

// Update 在锁内修改一条记录，改完自动做内存统计与增量广播。
func (s *Store) Update(id uint64, fn func(r *Record)) {
	s.mu.Lock()
	r, ok := s.recs[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	before := r.size()
	fn(r)
	s.bytes += r.size() - before
	s.evictLocked()
	snap := r.summary()
	s.mu.Unlock()

	s.enqueueUpd(snap)
}

func (s *Store) Get(id uint64) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.recs[id]
	if !ok {
		return nil, false
	}
	c := *r
	c.ReqBody = Blob{Data: append([]byte(nil), r.ReqBody.Data...)}
	c.RespBody = Blob{Data: append([]byte(nil), r.RespBody.Data...)}
	if len(r.Frames) > 0 {
		c.Frames = make([]WSFrameRec, len(r.Frames))
		copy(c.Frames, r.Frames)
		for i := range c.Frames {
			c.Frames[i].Payload = Blob{Data: append([]byte(nil), r.Frames[i].Payload.Data...)}
		}
	}
	return &c, true
}

// List 返回最近的记录（新的在前），最多 limit 条。
func (s *Store) List(limit int) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.order) {
		limit = len(s.order)
	}
	out := make([]*Record, 0, limit)
	for i := len(s.order) - 1; i >= 0 && len(out) < limit; i-- {
		if r, ok := s.recs[s.order[i]]; ok {
			out = append(out, r.summary())
		}
	}
	return out
}

// ListSince 返回 ID 大于 since 的记录（新的在前），供页面断线重连后补齐。
func (s *Store) ListSince(since uint64, limit int) []*Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Record, 0, 64)
	for i := len(s.order) - 1; i >= 0; i-- {
		id := s.order[i]
		if id <= since {
			break
		}
		if r, ok := s.recs[id]; ok {
			out = append(out, r.summary())
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.order)
}

func (s *Store) Stats() (n int, bytes int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.order), s.bytes
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.recs = make(map[uint64]*Record)
	s.order = nil
	s.bytes = 0
	s.mu.Unlock()

	s.pqMu.Lock()
	s.pqClear = true
	s.pqAdd = nil
	s.pqUpd = make(map[uint64]*Record)
	s.pqMu.Unlock()
	s.flush()
}

// evictLocked 淘汰最老的记录，直到满足条数与内存预算。必须持锁调用。
func (s *Store) evictLocked() {
	for len(s.order) > 0 && (len(s.order) > s.maxItems || s.bytes > s.maxBytes) {
		id := s.order[0]
		s.order = s.order[1:]
		if r, ok := s.recs[id]; ok {
			s.bytes -= r.size()
			delete(s.recs, id)
		}
	}
	if len(s.order) == 0 {
		s.bytes = 0
	}
}

// ---------------------------------------------------------------- 推送

func (s *Store) enqueueAdd(snap *Record) {
	s.pqMu.Lock()
	s.pqAdd = append(s.pqAdd, snap)
	s.pqMu.Unlock()
}

func (s *Store) enqueueUpd(snap *Record) {
	s.pqMu.Lock()
	s.pqUpd[snap.ID] = snap // 同一条记录只保留最新快照
	s.pqMu.Unlock()
}

func (s *Store) broadcastRules() {
	s.pqMu.Lock()
	s.pqRules = true
	s.pqMu.Unlock()
	s.flush()
}

// BroadcastStatus 通知页面"外部状态变了"（比如 mihomo 起来了又挂了）。
func (s *Store) BroadcastStatus() {
	s.pqMu.Lock()
	s.pqStat = true
	s.pqMu.Unlock()
	s.flush()
}

// EnqueueLog 把子进程的一行日志推给页面。攒在同一个批次里发，天然限流。
func (s *Store) EnqueueLog(line string) {
	s.pqMu.Lock()
	if len(s.pqLog) < 400 {
		s.pqLog = append(s.pqLog, line)
	}
	s.pqMu.Unlock()
}

func (s *Store) flushLoop() {
	t := time.NewTicker(120 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		s.flush()
	}
}

func (s *Store) flush() {
	s.pqMu.Lock()
	if len(s.pqAdd) == 0 && len(s.pqUpd) == 0 && len(s.pqLog) == 0 &&
		!s.pqClear && !s.pqRules && !s.pqStat {
		s.pqMu.Unlock()
		return
	}
	batch := sseBatch{
		T: "batch", Add: s.pqAdd, Clear: s.pqClear,
		Rules: s.pqRules, Stat: s.pqStat, Log: s.pqLog,
	}
	for _, r := range s.pqUpd {
		batch.Upd = append(batch.Upd, r)
	}
	sort.Slice(batch.Upd, func(i, j int) bool { return batch.Upd[i].ID < batch.Upd[j].ID })
	s.pqAdd = nil
	s.pqUpd = make(map[uint64]*Record)
	s.pqLog = nil
	s.pqClear = false
	s.pqRules = false
	s.pqStat = false
	s.pqMu.Unlock()

	data, err := json.Marshal(batch)
	if err != nil {
		return
	}
	msg := append([]byte("data: "), data...)
	msg = append(msg, '\n', '\n')

	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, sub := range s.subs {
		select {
		case sub.ch <- msg:
		default:
			// 页面跟不上：标记需要全量重同步，由 SSE 处理循环下发
			sub.resync.Store(true)
		}
	}
}

func (s *Store) subscribe() (int, *subscriber) {
	sub := &subscriber{ch: make(chan []byte, 1024)}
	s.subMu.Lock()
	defer s.subMu.Unlock()
	id := s.nextSub
	s.nextSub++
	s.subs[id] = sub
	return id, sub
}

func (s *Store) unsubscribe(id int) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	if sub, ok := s.subs[id]; ok {
		delete(s.subs, id)
		close(sub.ch)
	}
}

// ---------------------------------------------------------------- 辅助

// headerPairs 把 http.Header 变成有序的 [k,v] 列表，前端好渲染。
func headerPairs(h http.Header) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(h))
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, [2]string{k, v})
		}
	}
	return out
}

func pairsToHeader(pairs [][2]string) http.Header {
	h := http.Header{}
	for _, kv := range pairs {
		if strings.TrimSpace(kv[0]) == "" {
			continue
		}
		h.Add(kv[0], kv[1])
	}
	return h
}

// bodyHashOf 用于规则精确匹配请求体。空 body 返回空串（表示"不参与匹配"）。
func bodyHashOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// rawRequest 把请求重建成可读的原始报文（详情页"原始"标签用）。
func rawRequest(r *Record) string {
	var b strings.Builder
	b.WriteString(r.Method + " " + r.Path)
	if r.Query != "" {
		b.WriteString("?" + r.Query)
	}
	b.WriteString(" HTTP/1.1\r\n")
	host := r.Host
	if r.Port != "" && !isDefaultPort(r.Scheme, r.Port) {
		host += ":" + r.Port
	}
	b.WriteString("Host: " + host + "\r\n")
	for _, kv := range r.ReqHdr {
		if strings.EqualFold(kv[0], "Host") {
			continue
		}
		b.WriteString(kv[0] + ": " + kv[1] + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func rawResponse(r *Record) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + statusLine(r.Status) + "\r\n")
	for _, kv := range r.RespHdr {
		b.WriteString(kv[0] + ": " + kv[1] + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func statusLine(code int) string {
	if code == 0 {
		return "(无响应)"
	}
	if t := http.StatusText(code); t != "" {
		return strconv.Itoa(code) + " " + t
	}
	return strconv.Itoa(code)
}
