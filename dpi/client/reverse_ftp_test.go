package client

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/dpi/common"
	"github.com/lord-aali/PT-Proxy/dpi/server"
	ftpclient "github.com/lord-aali/PT-Proxy/ftp/client"
	ftpserver "github.com/lord-aali/PT-Proxy/ftp/server"
	"github.com/lord-aali/PT-Proxy/proxy/socks5"
	"golang.org/x/net/proxy"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func socksDial(proxyAddr, dest string, budget time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, budget)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(budget)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		conn.Close()
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	port, err := strconv.Atoi(portStr)
	if err != nil || ip == nil {
		conn.Close()
		return nil, io.ErrUnexpectedEOF
	}
	req := []byte{5, 1, 0, 1}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	ack := make([]byte, 10)
	if _, err := io.ReadFull(conn, ack); err != nil {
		conn.Close()
		return nil, err
	}
	if ack[1] != 0 {
		conn.Close()
		return nil, io.ErrUnexpectedEOF
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// SOCKS handshake through a reverse-published port, same process, with the
// DPI server target pointed at a different address (as in the VPS config).
func TestReverseSameProcessSOCKS(t *testing.T) {
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

	socksAddr, err := socks5.Serve("127.0.0.1:0", "", "", "rev-socks")
	if err != nil {
		t.Fatal(err)
	}
	other, err := socks5.Serve("127.0.0.1:0", "", "", "other-socks")
	if err != nil {
		t.Fatal(err)
	}

	revAddr := freePort(t)
	httpAddr := freePort(t)
	encKey := []byte("reverse-socks-key")
	srv, err := server.NewServer(server.Config{
		HTTPAddr:      httpAddr,
		EncryptionKey: encKey,
		Target:        other,
		LogTag:        "dpi-rev-socks",
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
		LogTag:    "dpi-rev-socks-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := NewProxyServer(ProxyConfig{Transport: tr, LogTag: "dpi-rev-socks-proxy"})
	if err := proxySrv.RunReverse(revAddr, socksAddr); err != nil {
		t.Fatal(err)
	}

	var dialer proxy.Dialer
	deadline := time.Now().Add(8 * time.Second)
	for {
		dialer, err = proxy.SOCKS5("tcp", revAddr, nil, proxy.Direct)
		if err != nil {
			t.Fatal(err)
		}
		c, derr := dialer.Dial("tcp", echoLn.Addr().String())
		if derr == nil {
			payload := []byte("socks-via-reverse")
			if _, err := c.Write(payload); err != nil {
				c.Close()
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, buf); err != nil {
				c.Close()
				t.Fatalf("socks via reverse: %v", err)
			}
			c.Close()
			if string(buf) != string(payload) {
				t.Fatalf("got %q", buf)
			}
			// Second connection. A stuck accept loop fails here.
			c2, err := dialer.Dial("tcp", echoLn.Addr().String())
			if err != nil {
				t.Fatalf("second socks via reverse: %v", err)
			}
			defer c2.Close()
			if _, err := c2.Write(payload); err != nil {
				t.Fatal(err)
			}
			_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c2, buf); err != nil {
				t.Fatalf("second echo: %v", err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reverse socks %s: %v", revAddr, derr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// FTP server target is the reverse-published port. The FTP client is a raw
// forward, so bytes written to it must reach the echo behind the reverse socks.
func TestFTPTargetReverseSOCKS(t *testing.T) {
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

	socksAddr, err := socks5.Serve("127.0.0.1:0", "", "", "ftp-rev-socks")
	if err != nil {
		t.Fatal(err)
	}
	revAddr := freePort(t)
	httpAddr := freePort(t)
	encKey := []byte("ftp-reverse-key")
	srv, err := server.NewServer(server.Config{
		HTTPAddr:      httpAddr,
		EncryptionKey: encKey,
		LogTag:        "dpi-ftp-rev",
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
		LogTag:    "dpi-ftp-rev-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := NewProxyServer(ProxyConfig{Transport: tr, LogTag: "dpi-ftp-rev-proxy"})
	if err := proxySrv.RunReverse(revAddr, socksAddr); err != nil {
		t.Fatal(err)
	}

	up := freePort(t)
	down := freePort(t)
	ftpListen := freePort(t)
	appListen := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	srvDone := make(chan struct{})
	cliDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = ftpserver.Run(ctx, ftpserver.Config{
			Listen:        ftpListen,
			User:          "tunnel",
			Pass:          "secret",
			Key:           "change-me-shared-key",
			PasvIP:        "127.0.0.1",
			UploadPorts:   portOf(t, up),
			DownloadPorts: portOf(t, down),
			LogTag:        "ftp-srv",
			Target:        revAddr,
		})
	}()
	go func() {
		defer close(cliDone)
		_ = ftpclient.Run(ctx, ftpclient.Config{
			Listen:           appListen,
			FTP:              ftpListen,
			User:             "tunnel",
			Pass:             "secret",
			Key:              "change-me-shared-key",
			UploadChannels:   1,
			DownloadChannels: 1,
			LogTag:           "ftp-cli",
		})
	}()
	defer func() {
		cancel()
		<-srvDone
		<-cliDone
	}()

	var conn net.Conn
	deadline := time.Now().Add(15 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		conn, last = socksDial(appListen, echoLn.Addr().String(), 4*time.Second)
		if last == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if last != nil {
		t.Fatalf("ftp via reverse socks: %v", last)
	}
	defer conn.Close()
	payload := []byte("ftp-via-reverse")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo via ftp+reverse: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q", buf)
	}
}
