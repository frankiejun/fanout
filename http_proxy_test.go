package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// runServeMixed 起一对 net.Pipe，服务端跑分流入，dial 把目标回环给测试侧。
// 返回客户端 conn 与 dial 侧收到的目标地址通道。
func runServeMixed(t *testing.T, cred *SocksCred) (net.Conn, chan string) {
	t.Helper()
	sConn, cConn := net.Pipe()
	targets := make(chan string, 1)
	dial := func(network, addr string) (net.Conn, error) {
		targets <- addr
		up, down := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, down)
		}()
		return up, nil
	}
	go serveMixed(sConn, cred, dial)
	return cConn, targets
}

func readStatusLine(t *testing.T, c net.Conn) string {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("读状态行失败: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func TestHTTPConnectSuccess(t *testing.T) {
	c, targets := runServeMixed(t, &SocksCred{User: "alice", Pass: "s3cret"})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+basicAuth("alice", "s3cret")+"\r\n\r\n")
	if err != nil {
		t.Fatalf("写 CONNECT 失败: %v", err)
	}
	if got := readStatusLine(t, c); !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("应回 200，得到 %q", got)
	}
	select {
	case target := <-targets:
		if target != "example.com:443" {
			t.Fatalf("拨号目标不对: %s", target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial 没被调用")
	}
}

func TestHTTPConnectRejectsWrongPass(t *testing.T) {
	c, targets := runServeMixed(t, &SocksCred{User: "alice", Pass: "s3cret"})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+basicAuth("alice", "wrong")+"\r\n\r\n")
	if err != nil {
		t.Fatalf("写 CONNECT 失败: %v", err)
	}
	if got := readStatusLine(t, c); !strings.HasPrefix(got, "HTTP/1.1 407") {
		t.Fatalf("应回 407，得到 %q", got)
	}
	select {
	case target := <-targets:
		t.Fatalf("认证失败不应拨号，却拨了 %s", target)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHTTPConnectRequiresAuth(t *testing.T) {
	c, _ := runServeMixed(t, &SocksCred{User: "alice", Pass: "s3cret"})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("写 CONNECT 失败: %v", err)
	}
	if got := readStatusLine(t, c); !strings.HasPrefix(got, "HTTP/1.1 407") {
		t.Fatalf("无认证头应回 407，得到 %q", got)
	}
}

func TestHTTPConnectRejectsGet(t *testing.T) {
	c, _ := runServeMixed(t, &SocksCred{User: "alice", Pass: "s3cret"})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := io.WriteString(c, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("写 GET 失败: %v", err)
	}
	if got := readStatusLine(t, c); !strings.HasPrefix(got, "HTTP/1.1 400") {
		t.Fatalf("GET 应回 400，得到 %q", got)
	}
}

func TestHTTPConnectBadTarget(t *testing.T) {
	c, _ := runServeMixed(t, &SocksCred{User: "alice", Pass: "s3cret"})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := io.WriteString(c, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: "+basicAuth("alice", "s3cret")+"\r\n\r\n")
	if err != nil {
		t.Fatalf("写 CONNECT 失败: %v", err)
	}
	if got := readStatusLine(t, c); !strings.HasPrefix(got, "HTTP/1.1 400") {
		t.Fatalf("无端口目标应回 400，得到 %q", got)
	}
}

// 分流不能把 SOCKS5 搞坏：首字节 0x05 仍走原握手流程。
func TestMixedStillServesSocks5(t *testing.T) {
	c, _ := runServeMixed(t, &SocksCred{User: "alice", Pass: "s3cret"})
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if code := socksClientAuth(t, c, "alice", "s3cret"); code != 0 {
		t.Fatalf("分流后 SOCKS5 认证应通过，得到状态 %d", code)
	}
}

func TestCheckHTTPAuth(t *testing.T) {
	cred := &SocksCred{User: "alice", Pass: "s3cret"}
	if !checkHTTPAuth(basicAuth("alice", "s3cret"), cred) {
		t.Error("正确凭据应通过")
	}
	if !checkHTTPAuth("basic "+strings.TrimPrefix(basicAuth("alice", "s3cret"), "Basic "), cred) {
		t.Error("scheme 应大小写不敏感")
	}
	for _, bad := range []string{
		"",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong")),
		"Basic " + base64.StdEncoding.EncodeToString([]byte("bob:s3cret")),
		"Bearer xyz",
		"Basic !!!not-base64!!!",
	} {
		if checkHTTPAuth(bad, cred) {
			t.Errorf("应拒绝 %q", bad)
		}
	}
	// 无凭据配置时不要求认证
	if !checkHTTPAuth("", &SocksCred{}) {
		t.Error("无凭据时应放行")
	}
}
