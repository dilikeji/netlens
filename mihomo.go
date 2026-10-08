package main

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mihomo 的二进制和配置在编译期就嵌进程序里。
// 这样交付的是一个自包含的 exe，不依赖旁边放着哪些文件。
//
//go:embed embed/mihomo.exe
var embeddedMihomo []byte

//go:embed embed/config.yaml
var embeddedConfig []byte

// Mihomo 负责"释放 + 拉起 + 看住 + 收尸"嵌进来的那个 mihomo 进程。
//
// 为什么要在页面上控制它：TUN 接管是整条链路的起点，而它需要管理员权限、
// 会改路由表，不适合在程序启动时偷偷拉起。交给用户按一下最合适。
type Mihomo struct {
	mu  sync.Mutex
	dir string // 运行时目录（mihomo.exe / config.yaml 都释放到这里）

	cmd       *exec.Cmd
	running   bool
	pid       int
	startedAt time.Time
	exitCode  int
	exitErr   string
	version   string
	verTried  bool

	autoStart   bool
	elevated    bool   // 当前进程是否以管理员身份运行
	expectSocks string // netlens 自己监听的 SOCKS5 地址，用来校验配置是否对得上
	log         *Logger
	store       *Store

	logMu sync.Mutex
	logs  []string
}

const maxMihomoLogs = 2000

func NewMihomo(dir, expectSocks string, autoStart bool, lg *Logger, store *Store) *Mihomo {
	return &Mihomo{
		dir: dir, expectSocks: expectSocks, autoStart: autoStart,
		elevated: isElevated(), log: lg, store: store,
	}
}

func (m *Mihomo) Dir() string     { return m.dir }
func (m *Mihomo) ExePath() string { return filepath.Join(m.dir, "mihomo.exe") }
func (m *Mihomo) CfgPath() string { return filepath.Join(m.dir, "config.yaml") }

// ---------------------------------------------------------------- 释放文件

// ensureExtracted 把嵌入的 mihomo 与配置写到工作目录。
//
// 判断依据是 sidecar 里的内容哈希，而不是每次都对 60MB 的文件重算一遍摘要。
// 正在运行时不能覆盖 exe（Windows 会锁住映像），直接跳过。
func (m *Mihomo) ensureExtracted() error {
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return fmt.Errorf("创建目录 %s 失败: %w", m.dir, err)
	}

	m.mu.Lock()
	running := m.running
	m.mu.Unlock()
	if running {
		return nil
	}

	sum := sha256.Sum256(embeddedMihomo)
	want := hex.EncodeToString(sum[:])
	stampPath := filepath.Join(m.dir, ".mihomo.sha256")

	have := ""
	if b, err := os.ReadFile(stampPath); err == nil {
		have = strings.TrimSpace(string(b))
	}
	needWrite := have != want
	if !needWrite {
		if st, err := os.Stat(m.ExePath()); err != nil || st.Size() != int64(len(embeddedMihomo)) {
			needWrite = true
		}
	}
	if needWrite {
		if err := os.WriteFile(m.ExePath(), embeddedMihomo, 0o755); err != nil {
			return fmt.Errorf("释放 mihomo.exe 失败: %w", err)
		}
		_ = os.WriteFile(stampPath, []byte(want), 0o644)
	}

	// 配置只在不存在时释放——用户改过的配置不能被覆盖掉
	if _, err := os.Stat(m.CfgPath()); err != nil {
		if err := os.WriteFile(m.CfgPath(), embeddedConfig, 0o644); err != nil {
			return fmt.Errorf("释放 config.yaml 失败: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------- 配置

func (m *Mihomo) Config() (string, error) {
	if err := m.ensureExtracted(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(m.CfgPath())
	if err != nil {
		return string(embeddedConfig), nil
	}
	return string(b), nil
}

func (m *Mihomo) SetConfig(text string) error {
	if err := m.ensureExtracted(); err != nil {
		return err
	}
	return os.WriteFile(m.CfgPath(), []byte(text), 0o644)
}

func (m *Mihomo) ResetConfig() (string, error) {
	if err := m.ensureExtracted(); err != nil {
		return "", err
	}
	if err := os.WriteFile(m.CfgPath(), embeddedConfig, 0o644); err != nil {
		return "", err
	}
	return string(embeddedConfig), nil
}

// socks5Target 从配置里读出 SOCKS5 出站指向的地址。
//
// 这份配置的意义就在这一条：把 App 的流量从 mihomo 转交给 netlens。
// 一旦这里的端口和 netlens 实际监听的端口对不上，整条链路就是断的，
// 而现象只是"页面上什么都看不到"。所以在界面上要能直接看出来。
func socks5Target(cfg string) string {
	lines := strings.Split(cfg, "\n")
	inProxies, isSocks := false, false
	server, port := "", ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if indent == 0 {
			if strings.HasPrefix(line, "proxies:") {
				inProxies, isSocks = true, false
				continue
			}
			if inProxies {
				break // 出了 proxies 段
			}
			continue
		}
		if !inProxies {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			isSocks = false
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "type":
			isSocks = strings.EqualFold(val, "socks5")
		case "server":
			if isSocks && server == "" {
				server = val
			}
		case "port":
			if isSocks && port == "" {
				port = val
			}
		}
	}
	if server == "" {
		return ""
	}
	if port == "" {
		return server
	}
	return server + ":" + port
}

// tunEnabled 读配置里 tun.enable，用于在界面上提示"需要管理员权限"。
func tunEnabled(cfg string) bool {
	lines := strings.Split(cfg, "\n")
	inTun := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if indent == 0 {
			inTun = strings.HasPrefix(line, "tun:")
			continue
		}
		if inTun && strings.HasPrefix(line, "enable:") {
			return strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enable:")), "true")
		}
	}
	return false
}

// ---------------------------------------------------------------- 进程

func (m *Mihomo) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("mihomo 已经在运行")
	}
	m.mu.Unlock()

	if err := m.ensureExtracted(); err != nil {
		return err
	}

	cmd := exec.Command(m.ExePath(), "-d", m.dir, "-f", m.CfgPath())
	cmd.Dir = m.dir
	cmd.SysProcAttr = hideWindow()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 mihomo 失败：%w", err)
	}

	m.mu.Lock()
	m.cmd = cmd
	m.running = true
	m.pid = cmd.Process.Pid
	m.startedAt = time.Now()
	m.exitCode = 0
	m.exitErr = ""
	m.mu.Unlock()

	m.appendLog(fmt.Sprintf("已启动 mihomo（PID %d），工作目录 %s", cmd.Process.Pid, m.dir))
	m.log.Noticef("mihomo 已启动（PID %d）", cmd.Process.Pid)
	go m.pump(stdout)
	go m.pump(stderr)
	go m.wait(cmd)
	return nil
}

func (m *Mihomo) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	running := m.running
	pid := m.pid
	m.mu.Unlock()
	if !running || cmd == nil {
		return errors.New("mihomo 没有在运行")
	}

	m.appendLog(fmt.Sprintf("正在停止 mihomo（PID %d）…", pid))
	m.log.Noticef("正在停止 mihomo（PID %d）", pid)
	// 先让进程自己退；TUN 模式下它还要清理路由，能等就等一下
	_ = cmd.Process.Kill()
	if tk, err := exec.LookPath("taskkill"); err == nil {
		// 连子进程一起收掉，避免残留
		_ = exec.Command(tk, "/T", "/F", "/PID", strconv.Itoa(pid)).Run()
	}

	for i := 0; i < 60; i++ {
		if !m.IsRunning() {
			m.appendLog("mihomo 已停止")
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("等待 mihomo 退出超时")
}

func (m *Mihomo) wait(cmd *exec.Cmd) {
	err := cmd.Wait()
	m.mu.Lock()
	// 只有还是同一个进程时才改写状态，避免"停旧启新"时串台
	if m.cmd == cmd {
		m.running = false
		m.pid = 0
		if cmd.ProcessState != nil {
			m.exitCode = cmd.ProcessState.ExitCode()
		}
		if err != nil {
			m.exitErr = err.Error()
		}
	}
	m.mu.Unlock()

	if err != nil {
		m.appendLog("mihomo 退出：" + err.Error())
		m.log.Noticef("mihomo 已退出：%v", err)
	} else {
		m.appendLog("mihomo 已退出")
		m.log.Noticef("mihomo 已退出")
	}
	m.store.BroadcastStatus()
}

func (m *Mihomo) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// ---------------------------------------------------------------- 日志

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

func (m *Mihomo) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := ansiRe.ReplaceAllString(strings.TrimRight(sc.Text(), "\r\n"), "")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m.appendLog(line)
	}
}

func (m *Mihomo) appendLog(line string) {
	stamped := "[" + time.Now().Format("15:04:05") + "] " + line

	m.logMu.Lock()
	m.logs = append(m.logs, stamped)
	if len(m.logs) > maxMihomoLogs {
		m.logs = append([]string(nil), m.logs[len(m.logs)-maxMihomoLogs:]...)
	}
	m.logMu.Unlock()

	m.log.Child("mihomo", line)
	m.store.EnqueueLog(stamped)

	// 顺手从启动横幅里捞版本号，省得单独跑一次 -v
	if m.version == "" && strings.Contains(line, "Mihomo Meta") {
		m.mu.Lock()
		if m.version == "" {
			m.version = strings.TrimSpace(line)
		}
		m.mu.Unlock()
	}
}

// detectVersion 跑一次 `mihomo -v` 取版本号，结果缓存下来。
func (m *Mihomo) detectVersion() {
	if err := m.ensureExtracted(); err != nil {
		return
	}
	cmd := exec.Command(m.ExePath(), "-v")
	cmd.Dir = m.dir
	cmd.SysProcAttr = hideWindow()
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	m.mu.Lock()
	if m.version == "" {
		m.version = line
	}
	m.mu.Unlock()
}

// OpenDir 在资源管理器里打开运行目录。
func (m *Mihomo) OpenDir() error {
	if err := m.ensureExtracted(); err != nil {
		return err
	}
	return exec.Command("explorer.exe", m.dir).Start()
}

func (m *Mihomo) Logs(since int) ([]string, int) {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	total := len(m.logs)
	if since < 0 {
		since = 0
	}
	if since > total {
		since = total
	}
	out := append([]string(nil), m.logs[since:]...)
	return out, total
}

// ---------------------------------------------------------------- 状态

type MihomoStatus struct {
	Running     bool   `json:"running"`
	PID         int    `json:"pid"`
	UptimeSec   int    `json:"uptimeSec"`
	ExePath     string `json:"exePath"`
	CfgPath     string `json:"cfgPath"`
	Dir         string `json:"dir"`
	AutoStart   bool   `json:"autoStart"`
	Version     string `json:"version"`
	ExitCode    int    `json:"exitCode"`
	ExitErr     string `json:"exitErr"`
	Socks5      string `json:"socks5"`      // 配置里 socks5 出站指向
	ExpectSocks string `json:"expectSocks"` // netlens 实际监听的 SOCKS5
	PortMatch   bool   `json:"portMatch"`
	Tun         bool   `json:"tun"`
	Elevated    bool   `json:"elevated"`
	LogCount    int    `json:"logCount"`
}

func (m *Mihomo) Status() MihomoStatus {
	cfg, _ := m.Config()
	target := socks5Target(cfg)

	m.mu.Lock()
	st := MihomoStatus{
		Running: m.running, PID: m.pid, Dir: m.dir,
		ExePath: m.ExePath(), CfgPath: m.CfgPath(),
		AutoStart: m.autoStart, Version: m.version,
		ExitCode: m.exitCode, ExitErr: m.exitErr,
		Socks5: target, ExpectSocks: m.expectSocks,
		PortMatch: samePort(target, m.expectSocks),
		Tun:       tunEnabled(cfg),
		Elevated:  m.elevated,
	}
	if m.running {
		st.UptimeSec = int(time.Since(m.startedAt).Seconds())
	}
	// 启动横幅有时不经过 stdout，兜底跑一次 -v 把版本号补上（只试一次）
	if st.Version == "" && !m.verTried {
		m.verTried = true
		go m.detectVersion()
	}
	m.mu.Unlock()

	m.logMu.Lock()
	st.LogCount = len(m.logs)
	m.logMu.Unlock()

	return st
}

// samePort 比较两个 host:port 的端口部分，用于提示配置与监听是否一致。
func samePort(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	_, pa := splitHostPort(a, "")
	_, pb := splitHostPort(b, "")
	return pa != "" && pa == pb
}
