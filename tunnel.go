package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// TunnelList 是「不做中间人、直接字节透传」的主机名单。
//
// 两个来源：
//   - 手工：命令行 -tunnel 指定的，删不掉（那是用户写死在参数里的）
//   - 自动：中间人握手失败过的主机，之后直接透传
//
// 为什么需要「自动」这一档：像 Electron / Node 写的程序（electerm、VS Code…）
// 不读 Windows 的证书库，用的是自带那份 CA bundle。我们的伪造证书在它们眼里
// 就是未知 CA，握手必然失败。这类程序没法提前识别——SOCKS5 不会告诉我们
// 对面的进程名——只能失败一次、记住它。
//
// 当前这条连接是救不回来的：失败的原因恰恰是**我们已把伪造证书发给了客户端**，
// 客户端不接受才关掉的连接，没有"把 ClientHello 重放给真服务器"的余地。
// 但同一主机的后续连接会直接走透传，程序重试就能通。
type TunnelList struct {
	mu     sync.RWMutex
	manual map[string]struct{}
	auto   map[string]struct{}
	path   string
	notify func()
}

func NewTunnelList(manual []string, path string, notify func()) *TunnelList {
	t := &TunnelList{
		manual: map[string]struct{}{},
		auto:   map[string]struct{}{},
		path:   path,
		notify: notify,
	}
	for _, h := range manual {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			t.manual[h] = struct{}{}
		}
	}
	t.load()
	return t
}

// Has 判断某个主机是否要跳过中间人。
func (t *TunnelList) Has(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if _, ok := t.manual[host]; ok {
		return true
	}
	_, ok := t.auto[host]
	return ok
}

// AddAuto 记下"这个主机中间人握手失败过"，返回是否是新加进去的。
func (t *TunnelList) AddAuto(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	t.mu.Lock()
	if _, ok := t.manual[host]; ok {
		t.mu.Unlock()
		return false
	}
	if _, ok := t.auto[host]; ok {
		t.mu.Unlock()
		return false
	}
	t.auto[host] = struct{}{}
	t.saveLocked()
	t.mu.Unlock()

	if t.notify != nil {
		t.notify()
	}
	return true
}

// Remove 把某个主机从自动名单里删掉（手工指定的删不掉）。
func (t *TunnelList) Remove(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	t.mu.Lock()
	if _, ok := t.auto[host]; !ok {
		t.mu.Unlock()
		return false
	}
	delete(t.auto, host)
	t.saveLocked()
	t.mu.Unlock()

	if t.notify != nil {
		t.notify()
	}
	return true
}

func (t *TunnelList) Auto() []string   { return t.sorted(t.auto) }
func (t *TunnelList) Manual() []string { return t.sorted(t.manual) }

func (t *TunnelList) sorted(m map[string]struct{}) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- 持久化

// 不持久化的话，每次重启都要让目标程序再失败一次，很难受。
func (t *TunnelList) load() {
	if t.path == "" {
		return
	}
	data, err := os.ReadFile(t.path)
	if err != nil {
		return
	}
	var hosts []string
	if err := json.Unmarshal(data, &hosts); err != nil {
		return
	}
	t.mu.Lock()
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			t.auto[h] = struct{}{}
		}
	}
	t.mu.Unlock()
}

func (t *TunnelList) saveLocked() {
	if t.path == "" {
		return
	}
	hosts := make([]string, 0, len(t.auto))
	for k := range t.auto {
		hosts = append(hosts, k)
	}
	sort.Strings(hosts)
	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(t.path), 0o755)
	_ = os.WriteFile(t.path, data, 0o644)
}
