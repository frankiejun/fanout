package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// 同端口 mixed 代理：SOCKS5 与 HTTP CONNECT 跑在同一个监听上。
// 首字节 0x05 走 SOCKS5（含已有的 UDP ASSOCIATE），否则按 HTTP CONNECT 解析。
// HTTP 只做 CONNECT（HTTPS 透传）：明文 GET http:// 转发不支持，
// 现代站点基本都是 https，CONNECT 已覆盖浏览器只认 HTTP 代理的场景。

const (
	httpMaxHeaderBytes = 32 << 10
	httpMaxLineBytes   = 8 << 10
)

// serveMixed 按首字节把连接分给 SOCKS5 或 HTTP CONNECT。
func serveMixed(client net.Conn, cred *SocksCred, dial func(network, addr string) (net.Conn, error)) {
	defer client.Close()

	peek := bufio.NewReader(client)
	b, err := peek.Peek(1)
	if err != nil {
		return
	}
	if b[0] == socksVer5 {
		serveSocksOn(client, peek, cred, dial)
		return
	}
	serveHTTPConnect(client, peek, cred, dial)
}

// serveHTTPConnect 处理一条 HTTP CONNECT：认证→拨号→回 200→透传。
func serveHTTPConnect(client net.Conn, r *bufio.Reader, cred *SocksCred, dial func(network, addr string) (net.Conn, error)) {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	target, hdr, err := readConnectRequest(r)
	if err != nil {
		writeHTTPStatus(client, "400 Bad Request")
		return
	}
	if !checkHTTPAuth(hdr.Get("Proxy-Authorization"), cred) {
		_, _ = fmt.Fprintf(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"fanout\"\r\nContent-Length: 0\r\n\r\n")
		return
	}

	remote, err := dial("tcp", target)
	if err != nil {
		writeHTTPStatus(client, "502 Bad Gateway")
		return
	}
	defer remote.Close()

	if _, err := fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	_ = client.SetDeadline(time.Time{})
	_ = remote.SetDeadline(time.Time{})
	relay(client, remote)
}

// readConnectRequest 读 CONNECT 请求行与头，只接受 CONNECT 方法。
// 返回拨号目标（host:port）与请求头。header 读回来的 key 已规范化。
func readConnectRequest(r *bufio.Reader) (string, httpHeader, error) {
	line, err := readHTTPLine(r)
	if err != nil {
		return "", nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[0], "CONNECT") {
		return "", nil, fmt.Errorf("只支持 CONNECT")
	}
	target := parts[1]
	if _, _, err := net.SplitHostPort(target); err != nil {
		return "", nil, fmt.Errorf("目标地址无效: %s", target)
	}

	hdr := httpHeader{}
	total := len(line)
	for {
		hline, err := readHTTPLine(r)
		if err != nil {
			return "", nil, err
		}
		total += len(hline)
		if total > httpMaxHeaderBytes {
			return "", nil, fmt.Errorf("请求头太大")
		}
		if hline == "" {
			break
		}
		name, value, ok := strings.Cut(hline, ":")
		if !ok {
			return "", nil, fmt.Errorf("请求头格式不对")
		}
		hdr.add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return target, hdr, nil
}

// readHTTPLine 读一行 CRLF 结尾的 HTTP 行（不含结尾换行）。
func readHTTPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > httpMaxLineBytes {
		return "", fmt.Errorf("行太长")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// httpHeader 是极简的请求头容器：只取 Proxy-Authorization，不做全解析。
type httpHeader map[string]string

func (h httpHeader) add(name, value string) {
	key := strings.ToLower(name)
	if _, ok := h[key]; !ok {
		h[key] = value
	}
}

func (h httpHeader) Get(name string) string { return h[strings.ToLower(name)] }

// checkHTTPAuth 校验 Proxy-Authorization: Basic <base64(user:pass)>。
func checkHTTPAuth(hdr string, cred *SocksCred) bool {
	if cred == nil || cred.User == "" {
		return true
	}
	scheme, param, ok := strings.Cut(hdr, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(param))
	if err != nil {
		return false
	}
	want := cred.User + ":" + cred.Pass
	if len(raw) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(raw, []byte(want)) == 1
}

func writeHTTPStatus(c net.Conn, status string) {
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", status)
}
