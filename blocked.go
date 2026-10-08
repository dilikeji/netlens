package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Blocked 是一条「屏蔽」规则。
//
// 粒度是**整个域名**：屏蔽 example.com 之后，它下面所有路径的请求都不再展示。
// 按路径匹配的话，同一个站点的每个接口都要点一次，实际用下来很烦。
//
// 语义是**只在页面上隐藏**，不是拦流量：
// 被屏蔽的请求照常转发、照常记录，只是不再出现在「全部 / HTTP / WS / 透传 / 锁定」里，
// 要看就去「屏蔽」那一栏。之所以不做成真拦截：点这个按钮的意图是
// "这个站别再刷我屏了"，而不是"把它断掉"——真断掉的话反而没法回头验证。
type Blocked struct {
	ID    int       `json:"id"`
	Host  string    `json:"host"`
	Label string    `json:"label"` // 显示用
	At    time.Time `json:"at"`
}

// BlockStore 保存屏蔽名单。按域名的**全部路径**生效。
type BlockStore struct {
	mu     sync.RWMutex
	items  []Blocked
	nextID int
	path   string
	notify func()
}

func NewBlockStore(path string, notify func()) *BlockStore {
	b := &BlockStore{path: path, notify: notify}
	b.load()
	return b
}

func (b *BlockStore) List() []Blocked {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Blocked, len(b.items))
	copy(out, b.items)
	return out
}

// Add 屏蔽一个域名。返回 (条目, 是否新增)——重复屏蔽同一个域名时 added 为 false。
func (b *BlockStore) Add(host string) (Blocked, bool) {
	host = strings.ToLower(strings.TrimSpace(host))

	b.mu.Lock()
	for _, it := range b.items {
		if it.Host == host {
			b.mu.Unlock()
			return it, false // 已经屏蔽过了
		}
	}
	b.nextID++
	item := Blocked{ID: b.nextID, Host: host, Label: host, At: time.Now()}
	b.items = append(b.items, item)
	b.saveLocked()
	b.mu.Unlock()

	if b.notify != nil {
		b.notify()
	}
	return item, true
}

func (b *BlockStore) Remove(id int) bool {
	b.mu.Lock()
	found := -1
	for i, it := range b.items {
		if it.ID == id {
			found = i
			break
		}
	}
	if found < 0 {
		b.mu.Unlock()
		return false
	}
	b.items = append(b.items[:found], b.items[found+1:]...)
	b.saveLocked()
	b.mu.Unlock()

	if b.notify != nil {
		b.notify()
	}
	return true
}

func (b *BlockStore) load() {
	if b.path == "" {
		return
	}
	data, err := os.ReadFile(b.path)
	if err != nil {
		return
	}
	var items []Blocked
	if err := json.Unmarshal(data, &items); err != nil {
		return
	}
	b.mu.Lock()
	// 早期版本是按 host+path 存的（同一个域名会有好几条），
	// 这里按域名去重收拢一次，老的 blocked.json 也能直接用
	b.items = nil
	for _, it := range items {
		host := strings.ToLower(strings.TrimSpace(it.Host))
		if host == "" {
			continue
		}
		dup := false
		for _, kept := range b.items {
			if kept.Host == host {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		b.nextID++
		b.items = append(b.items, Blocked{ID: b.nextID, Host: host, Label: host, At: it.At})
	}
	b.mu.Unlock()
}

func (b *BlockStore) saveLocked() {
	if b.path == "" {
		return
	}
	data, err := json.MarshalIndent(b.items, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(b.path), 0o755)
	_ = os.WriteFile(b.path, data, 0o644)
}
