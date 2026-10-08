package main

import (
	"bufio"
	"net"
	"strings"
	"time"
)

type protoKind int

const (
	protoUnknown protoKind = iota
	protoHTTP
	protoTLS
)

func (k protoKind) String() string {
	switch k {
	case protoHTTP:
		return "明文 HTTP"
	case protoTLS:
		return "TLS"
	}
	return "无法识别"
}

// httpMethods 用于识别明文 HTTP 请求的开头（注意带尾随空格）。
var httpMethods = []string{
	"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
	"OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
}

const sniffTimeout = 2 * time.Second

// sniffProtocol 在不消耗字节的前提下判断连接上跑的是什么协议。
//
// 为什么需要它：App 的接口经常挂在 81、8000、8080、8443 这类非标准端口上。
// 只按端口号硬编码（80=明文、443=TLS）会把这些流量全部漏掉——
// 表现就是日志里只有一行"直连透传（未解密）"，看不到任何请求内容。
//
// 返回的 conn 已经包过 bufio，嗅探过程中读到的字节不会丢，
// 后续必须用这个返回值继续读写。
func sniffProtocol(c net.Conn) (protoKind, net.Conn) {
	br := bufio.NewReader(c)
	wrapped := net.Conn(&bufferedConn{Conn: c, r: br})

	_ = c.SetReadDeadline(time.Now().Add(sniffTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	head, err := br.Peek(1)
	if err != nil {
		return protoUnknown, wrapped
	}
	// TLS record 的第一个字节是 ContentType，Handshake 固定是 0x16
	if head[0] == 0x16 {
		return protoTLS, wrapped
	}
	// HTTP 方法名一定以大写字母开头，否则没必要继续看
	if head[0] < 'A' || head[0] > 'Z' {
		return protoUnknown, wrapped
	}

	// 方法名 + 空格至少 4 字节。读满就精确匹配；
	// 读不满（客户端分片发送）就用手头已有的字节做前缀匹配。
	if b, err := br.Peek(4); err == nil {
		if isHTTPMethodPrefix(string(b)) {
			return protoHTTP, wrapped
		}
		return protoUnknown, wrapped
	}
	if n := br.Buffered(); n > 0 {
		if b, err := br.Peek(n); err == nil && isHTTPMethodPrefix(string(b)) {
			return protoHTTP, wrapped
		}
	}
	return protoUnknown, wrapped
}

// isHTTPMethodPrefix 判断 s 是否可能是某个 HTTP 方法的开头。
// 双向匹配：s 可能是完整的方法名+空格，也可能只读到了方法名的一部分。
func isHTTPMethodPrefix(s string) bool {
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) || strings.HasPrefix(m, s) {
			return true
		}
	}
	return false
}
