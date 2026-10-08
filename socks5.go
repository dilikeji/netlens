package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// 最小可用 SOCKS5 服务端（仅 CONNECT，无认证）。
//
// 为什么用 SOCKS5 而不是透明代理：Mihomo 在把流量交给我们时会保留
// **原始目标域名**，这样既不用做 DNS 反查，又能拿到真实 Host，
// 对签发证书和记录日志都是刚需。
const (
	socks5Version = 0x05
	socks5NoAuth  = 0x00
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

var errUnsupportedCmd = errors.New("仅支持 SOCKS5 CONNECT 命令")

// socks5Handshake 完成 SOCKS5 协商，返回 (包装后的连接, 目标地址 host:port)。
//
// 返回的 conn 包了一层 bufio：握手时可能已经预读到了后续字节，
// 直接换成裸 conn 会丢数据。
func socks5Handshake(c net.Conn) (net.Conn, string, error) {
	br := bufio.NewReader(c)

	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return nil, "", fmt.Errorf("读取版本号失败: %w", err)
	}
	if head[0] != socks5Version {
		return nil, "", fmt.Errorf("不是 SOCKS5 协议 (version=%d)", head[0])
	}
	if n := int(head[1]); n > 0 {
		if _, err := io.ReadFull(br, make([]byte, n)); err != nil {
			return nil, "", fmt.Errorf("读取认证方法失败: %w", err)
		}
	}
	// 我们不要求认证
	if _, err := c.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return nil, "", err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return nil, "", fmt.Errorf("读取请求头失败: %w", err)
	}
	if req[0] != socks5Version {
		return nil, "", fmt.Errorf("请求版本错误: %d", req[0])
	}
	if req[1] != cmdConnect {
		_ = writeSocksReply(c, 0x07) // Command not supported
		return nil, "", errUnsupportedCmd
	}

	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return nil, "", err
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, "", err
		}
		host = string(b)
	default:
		_ = writeSocksReply(c, 0x08) // Address type not supported
		return nil, "", fmt.Errorf("不支持的地址类型: 0x%02x", req[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return nil, "", err
	}
	port := int(binary.BigEndian.Uint16(pb))

	if err := writeSocksReply(c, 0x00); err != nil {
		return nil, "", err
	}
	return &bufferedConn{Conn: c, r: br}, net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func writeSocksReply(c net.Conn, code byte) error {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	_, err := c.Write([]byte{socks5Version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// bufferedConn 让 bufio 预读的字节继续可见。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
