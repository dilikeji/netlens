package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Rule 是一条"响应锁定"规则。
//
// 命中之后，代理**不再访问上游**，直接把你编辑过的响应原样返回给客户端。
// 匹配条件默认是「方法 + 主机 + 端口 + 路径 + 查询串」，可以选择忽略查询串，
// 也可以额外要求请求体完全一致（sha256）。
type Rule struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	Method      string `json:"method"` // 空 = 任意方法
	Host        string `json:"host"`   // 小写主机名，空 = 任意
	Port        string `json:"port"`   // 空 = 任意端口
	Path        string `json:"path"`   // 空 = 任意路径
	Query       string `json:"query"`
	IgnoreQuery bool   `json:"ignoreQuery"`
	BodyHash    string `json:"bodyHash"` // 非空 = 还要求请求体 sha256 相同

	Status  int         `json:"status"`
	Hdr     [][2]string `json:"hdr"`
	Body    Blob        `json:"body"`
	DelayMS int         `json:"delayMs"`

	Hits      int64     `json:"hits"`
	CreatedAt time.Time `json:"createdAt"`
	LastHit   time.Time `json:"lastHit,omitempty"`
	FromID    uint64    `json:"fromId,omitempty"`   // 来源记录号，便于回溯
	KindHint  string    `json:"kindHint,omitempty"` // 来源记录的种类，用于提示限制
}

// MarshalJSON 额外带一个 pattern 字段。
// page 需要直接显示匹配表达式，而 Pattern 是计算出来的方法，默认不会被序列化。
func (r *Rule) MarshalJSON() ([]byte, error) {
	type alias Rule // 避免递归调用自己
	return json.Marshal(struct {
		*alias
		Pattern string `json:"pattern"`
	}{(*alias)(r), r.Pattern()})
}

// Pattern 是给页面显示的可读匹配表达式。
func (r *Rule) Pattern() string {
	var b strings.Builder
	if r.Method != "" {
		b.WriteString(r.Method + " ")
	}
	if r.Host != "" {
		b.WriteString(r.Host)
	} else {
		b.WriteString("*")
	}
	if r.Port != "" {
		b.WriteString(":" + r.Port)
	}
	if r.Path != "" {
		b.WriteString(r.Path)
	} else {
		b.WriteString("/*")
	}
	if !r.IgnoreQuery && r.Query != "" {
		b.WriteString("?" + r.Query)
	}
	if r.BodyHash != "" {
		b.WriteString("  [body:" + r.BodyHash[:8] + "]")
	}
	return b.String()
}

// matches 判定一条真实请求是否该被这条规则接管。
//
// 方法、主机、端口、路径都必须相等（规则里留空表示"不限制"）；
// 查询串在 IgnoreQuery 为真时不参与比较；BodyHash 非空时还要求
// 请求体的 sha256 完全相同（请求体被截断时一律不匹配，宁可不接管）。
func (r *Rule) matches(method, host, port, path, query, bodyHash string, bodyTruncated bool) bool {
	if !r.Enabled {
		return false
	}
	if r.Method != "" && r.Method != method {
		return false
	}
	if r.Host != "" && !strings.EqualFold(r.Host, host) {
		return false
	}
	if r.Port != "" && r.Port != port {
		return false
	}
	if r.Path != "" && r.Path != path {
		return false
	}
	if !r.IgnoreQuery && r.Query != query {
		return false
	}
	if r.BodyHash != "" {
		if bodyTruncated || bodyHash == "" || bodyHash != r.BodyHash {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- 规则仓库

type RuleStore struct {
	mu     sync.RWMutex
	rules  []*Rule
	nextID int64
	path   string // 非空时落盘（JSON），重启后仍生效
}

func NewRuleStore(path string) *RuleStore {
	rs := &RuleStore{path: path}
	if path != "" {
		rs.load()
	}
	return rs
}

func (rs *RuleStore) load() {
	data, err := os.ReadFile(rs.path)
	if err != nil {
		return
	}
	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return
	}
	rs.rules = rules
	for _, r := range rules {
		if r.ID > rs.nextID {
			rs.nextID = r.ID
		}
	}
}

func (rs *RuleStore) persistLocked() {
	if rs.path == "" {
		return
	}
	data, err := json.MarshalIndent(rs.rules, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(rs.path), 0o755)
	_ = os.WriteFile(rs.path, data, 0o600)
}

// Match 返回第一条命中的规则（已拷贝，调用方随便用），并累加命中次数。
func (rs *RuleStore) Match(method, host, port, path, query, bodyHash string, bodyTruncated bool) *Rule {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, r := range rs.rules {
		if r.matches(method, host, port, path, query, bodyHash, bodyTruncated) {
			r.Hits++
			r.LastHit = time.Now()
			cp := *r
			return &cp
		}
	}
	return nil
}

// Get 用于在代理侧记录"是哪条规则接管的"。
func (rs *RuleStore) Get(id int64) *Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	for _, r := range rs.rules {
		if r.ID == id {
			cp := *r
			return &cp
		}
	}
	return nil
}

func (rs *RuleStore) List() []*Rule {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	out := make([]*Rule, 0, len(rs.rules))
	for i := len(rs.rules) - 1; i >= 0; i-- { // 新的在前
		cp := *rs.rules[i]
		cp.Body = Blob{Data: append([]byte(nil), rs.rules[i].Body.Data...)}
		out = append(out, &cp)
	}
	return out
}

func (rs *RuleStore) Add(r *Rule) *Rule {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.nextID++
	r.ID = rs.nextID
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	rs.rules = append(rs.rules, r)
	rs.persistLocked()
	cp := *r
	return &cp
}

func (rs *RuleStore) Update(id int64, fn func(r *Rule)) (*Rule, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, r := range rs.rules {
		if r.ID == id {
			fn(r)
			rs.persistLocked()
			cp := *r
			return &cp, true
		}
	}
	return nil, false
}

func (rs *RuleStore) Delete(id int64) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for i, r := range rs.rules {
		if r.ID == id {
			rs.rules = append(rs.rules[:i], rs.rules[i+1:]...)
			rs.persistLocked()
			return true
		}
	}
	return false
}

func (rs *RuleStore) Count() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.rules)
}
