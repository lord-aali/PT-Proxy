package client

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/dpi/common"
	"github.com/lord-aali/PT-Proxy/dpi/server"
)

// Same-process dial into a reverse-published port. This is what a carrier
// does when its target is an external address that names the reverse bind.
func TestReverseSameProcessEcho(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	revLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	revAddr := revLn.Addr().String()
	revLn.Close()

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	encKey := []byte("reverse-test-key")
	srv, err := server.NewServer(server.Config{
		HTTPAddr:      httpAddr,
		EncryptionKey: encKey,
		LogTag:        "dpi-rev-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Run(); err != nil {
		t.Fatal(err)
	}

	enc, err := common.NewEncryptor(encKey)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(httpAddr)
	tr, err := NewTransport(TransportConfig{
		ServerURL: "http://" + httpAddr,
		Encryptor: enc,
		DialIP:    host,
		Uplink:    common.UplinkStream,
		LogTag:    "dpi-rev-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyServer(ProxyConfig{Transport: tr, LogTag: "dpi-rev-proxy"})
	if err := proxy.RunReverse(revAddr, echoLn.Addr().String()); err != nil {
		t.Fatal(err)
	}

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err = net.DialTimeout("tcp", revAddr, time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reverse port %s never accepted: %v", revAddr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer conn.Close()

	payload := []byte("ping-reverse")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo via reverse: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

// A fast same-process writer can push many segments before the reverse
// client has accepted its local leg. None of those bytes may be dropped.
func TestReverseKeepsBytesBeforeLocalAccept(t *testing.T) {
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		c, err := localLn.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	revAddr := freePort(t)
	httpAddr := freePort(t)
	encKey := []byte("reverse-burst-key")
	srv, err := server.NewServer(server.Config{
		HTTPAddr:      httpAddr,
		EncryptionKey: encKey,
		LogTag:        "dpi-burst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Run(); err != nil {
		t.Fatal(err)
	}
	enc, err := common.NewEncryptor(encKey)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _ := net.SplitHostPort(httpAddr)
	tr, err := NewTransport(TransportConfig{
		ServerURL: "http://" + httpAddr,
		Encryptor: enc,
		DialIP:    host,
		Uplink:    common.UplinkStream,
		LogTag:    "dpi-burst-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyServer(ProxyConfig{Transport: tr, LogTag: "dpi-burst-proxy"})
	if err := proxy.RunReverse(revAddr, localLn.Addr().String()); err != nil {
		t.Fatal(err)
	}

	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err = net.DialTimeout("tcp", revAddr, time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	const n = 40
	for i := 0; i < n; i++ {
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(8 * time.Millisecond)
	}

	var local net.Conn
	select {
	case local = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("reverse client never dialed local")
	}
	defer local.Close()
	_ = local.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(local, buf); err != nil {
		t.Fatalf("local got incomplete burst: %v", err)
	}
	for i := 0; i < n; i++ {
		if buf[i] != byte(i) {
			t.Fatalf("byte %d = %d", i, buf[i])
		}
	}
}
