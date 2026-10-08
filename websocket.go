package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebSocket 处理。
//
// 握手本质就是一个带 Upgrade 的 HTTP 请求，我们在 MITM 出来的连接上把它劫持过来：
// 自己向上游发握手、把上游的 101 原样回给客户端，之后进入纯粹的字节级双向转发——
// 但转发的最小单位是「一个帧」，这样既能记录内容，又不破坏协议
// （客户端帧必须带 mask，原样透传最安全）。

const maxWSFrames = 2000 // 单个会话最多记录的帧数，防止长连接把内存吃爆

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request, id uint64, ci *connInfo) {
	scheme := "ws"
	if r.URL.Scheme == "https" {
		scheme = "wss"
	}
	rec := p.newRecord(id, scheme, r, ci, KindWS)
	rec.Kind = KindWS
	rec.Note = "WebSocket 升级请求"
	p.store.Add(rec)
	p.log.Request(rec)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "netlens: 无法劫持 WebSocket 连接", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	// r.URL.Host 已被 forward() 用连接上的真实端口补全，不能再回退到 r.Host
	host, port := splitHostPort(r.URL.Host, defaultPort(r.URL.Scheme))
	upConn, err := p.dialUpstream(r.URL.Scheme, host, port)
	if err != nil {
		msg := fmt.Sprintf("WebSocket 连接上游失败 %s:%s: %v", host, port, err)
		p.finishRecord(id, func(rr *Record) { rr.Err = msg })
		p.log.Errorf("#%d %s", id, msg)
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = upConn.Close() }()

	if err := writeWSHandshakeRequest(upConn, r); err != nil {
		msg := fmt.Sprintf("发送 WebSocket 握手失败: %v", err)
		p.finishRecord(id, func(rr *Record) { rr.Err = msg })
		p.log.Errorf("#%d %s", id, msg)
		return
	}

	br := bufio.NewReader(upConn)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		msg := fmt.Sprintf("读取 WebSocket 握手响应失败: %v", err)
		p.finishRecord(id, func(rr *Record) { rr.Err = msg })
		p.log.Errorf("#%d %s", id, msg)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	p.store.Update(id, func(rr *Record) {
		rr.Status = resp.StatusCode
		rr.RespHdr = headerPairs(resp.Header)
	})
	p.log.Debugf("#%d WebSocket 已劫持客户端连接，准备回写 %s", id, resp.Status)

	if err := writeWSHandshakeResponse(clientConn, resp); err != nil {
		p.log.Errorf("#%d 回写 WebSocket 握手响应失败: %v", id, err)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// 握手没成功，把响应体也转发回去（通常是错误 JSON）
		capture := newBodyCapture(p.cfg.PrintMax)
		_, _ = io.Copy(clientConn, io.TeeReader(resp.Body, capture))
		p.finishRecord(id, func(rr *Record) {
			rr.RespBody = capture.Blob()
			rr.RespSize = capture.Total()
			rr.RespTrunc = capture.truncated
			rr.Note = "WebSocket 升级失败"
		})
		p.logResponse(id)
		return
	}

	// 上游的 buffered reader 里可能已经缓存了首批帧数据
	up := net.Conn(&bufferedConn{Conn: upConn, r: br})
	sink := newFrameSink(p.store, id)
	p.store.Update(id, func(rr *Record) { rr.Note = "WebSocket 会话进行中" })

	done := make(chan struct{}, 2)
	go func() {
		p.relayWS(up, clientConn, id, "S→C", sink)
		done <- struct{}{}
	}()
	go func() {
		p.relayWS(clientConn, up, id, "C→S", sink)
		done <- struct{}{}
	}()
	<-done
	// 一侧断开即结束整个会话
	_ = clientConn.Close()
	_ = upConn.Close()
	<-done

	sink.flush()
	p.finishRecord(id, func(rr *Record) { rr.Note = "WebSocket 会话已结束" })
	p.log.Debugf("#%d WebSocket 会话结束", id)
}

func (p *Proxy) logResponse(id uint64) {
	if r, ok := p.store.Get(id); ok {
		p.log.Response(r)
	}
}

// ---------------------------------------------------------------- 帧记录

// frameSink 把帧批量写进 Store：攒够 20 帧或间隔超过 200ms 就落一次库。
// 否则一条高频 WS 会话会让页面每秒收到上千次推送。
type frameSink struct {
	store *Store
	id    uint64
	mu    sync.Mutex
	pend  []WSFrameRec
	last  time.Time
}

func newFrameSink(s *Store, id uint64) *frameSink {
	return &frameSink{store: s, id: id, last: time.Now()}
}

func (fs *frameSink) add(f WSFrameRec) {
	fs.mu.Lock()
	fs.pend = append(fs.pend, f)
	if len(fs.pend) >= 20 || time.Since(fs.last) > 200*time.Millisecond {
		fs.flushLocked()
	}
	fs.mu.Unlock()
}

func (fs *frameSink) flush() {
	fs.mu.Lock()
	fs.flushLocked()
	fs.mu.Unlock()
}

func (fs *frameSink) flushLocked() {
	if len(fs.pend) == 0 {
		return
	}
	batch := fs.pend
	fs.pend = nil
	fs.last = time.Now()
	fs.store.Update(fs.id, func(rr *Record) {
		if len(rr.Frames) >= maxWSFrames {
			return
		}
		if room := maxWSFrames - len(rr.Frames); room < len(batch) {
			batch = batch[:room]
		}
		rr.Frames = append(rr.Frames, batch...)
	})
}

// ---------------------------------------------------------------- 帧转发

func (p *Proxy) relayWS(src, dst net.Conn, id uint64, dir string, sink *frameSink) {
	defer func() { _ = src.SetReadDeadline(time.Now()) }() // 唤醒对侧阻塞的读
	for {
		frame, err := relayWSFrame(src, dst, p.cfg.PrintMax)
		if err != nil {
			if isBenignNetErr(err) {
				p.log.Debugf("#%d WebSocket %s 方向结束: %v", id, dir, err)
			} else {
				p.log.Errorf("#%d WebSocket %s 读取结束: %v", id, dir, err)
			}
			return
		}
		frame.Dir = dir
		p.log.WSFrame(id, frame)
		sink.add(*frame)
	}
}

// relayWSFrame 从 src 读出一个完整帧，原样写到 dst，
// 同时保留前 previewMax 字节（按 mask 解码）用于展示。
//
// 载荷必须原样转发：客户端发的帧要求带 mask，重新封装容易出错，
// 透传也意味着 permessage-deflate 之类的扩展不会被破坏。
func relayWSFrame(src io.Reader, dst io.Writer, previewMax int) (*WSFrameRec, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(src, head); err != nil {
		return nil, err
	}
	raw := append([]byte(nil), head...)

	opcode := head[0] & 0x0f
	masked := head[1]&0x80 != 0

	length := int64(head[1] & 0x7f)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(src, ext); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext))
		raw = append(raw, ext...)
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(src, ext); err != nil {
			return nil, err
		}
		u := binary.BigEndian.Uint64(ext)
		if u > 1<<32 {
			return nil, fmt.Errorf("WebSocket 帧长度异常: %d 字节", u)
		}
		length = int64(u)
		raw = append(raw, ext...)
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(src, mask[:]); err != nil {
			return nil, err
		}
		raw = append(raw, mask[:]...)
	}

	if _, err := dst.Write(raw); err != nil { // 帧头原样转发
		return nil, err
	}

	// 载荷分块转发，避免大帧（视频流）把内存吃掉
	capture := newBodyCapture(previewMax)
	buf := make([]byte, 32*1024)
	var off int64
	for off < length {
		n := int64(len(buf))
		if length-off < n {
			n = length - off
		}
		if _, err := io.ReadFull(src, buf[:n]); err != nil {
			return nil, err
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return nil, err
		}
		if masked {
			un := make([]byte, n)
			for i := int64(0); i < n; i++ {
				un[i] = buf[i] ^ mask[(off+i)%4]
			}
			_, _ = capture.Write(un)
		} else {
			_, _ = capture.Write(buf[:n])
		}
		off += n
	}

	return &WSFrameRec{
		Opcode:  opcodeName(opcode),
		Length:  length,
		At:      time.Now(),
		Payload: capture.Blob(),
	}, nil
}

func opcodeName(op byte) string {
	switch op {
	case 0x0:
		return "CONT"
	case 0x1:
		return "TEXT"
	case 0x2:
		return "BIN"
	case 0x8:
		return "CLOSE"
	case 0x9:
		return "PING"
	case 0xa:
		return "PONG"
	}
	return fmt.Sprintf("OP%d", op)
}

func isBenignNetErr(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "forcibly closed")
}

// ---------------------------------------------------------------- 上游连接

func (p *Proxy) dialUpstream(scheme, host, port string) (net.Conn, error) {
	addr := net.JoinHostPort(host, port)
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if scheme == "http" || scheme == "ws" {
		return d.DialContext(context.Background(), "tcp", addr)
	}
	return tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: p.cfg.InsecureUpstream,
	})
}

// writeWSHandshakeRequest 手工拼握手请求。
//
// 不用 (*http.Request).Write，因为它会重排/裁剪 Header，
// 而 WebSocket 握手对 Connection / Upgrade / Sec-WebSocket-* 的完整性敏感。
func writeWSHandshakeRequest(w io.Writer, r *http.Request) error {
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", r.URL.RequestURI())
	fmt.Fprintf(&b, "Host: %s\r\n", r.Host)

	written := map[string]bool{"host": true, "connection": true, "upgrade": true}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if written[lk] || lk == "content-length" || lk == "transfer-encoding" {
			continue
		}
		written[lk] = true
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("\r\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// writeWSHandshakeResponse 手工写 101，不用 resp.Write（它对 101 的处理不可控）。
func writeWSHandshakeResponse(w io.Writer, resp *http.Response) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}
