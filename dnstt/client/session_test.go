package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/dnstt/dns"
	"github.com/lord-aali/PT-Proxy/dnstt/server"
)

func TestDirectRoundTrip(t *testing.T) {
	directRoundTrip(t, 0)
}

func TestDirectAAAARoundTrip(t *testing.T) {
	directRoundTrip(t, dns.RRTypeAAAA)
}

func TestDirectARoundTrip(t *testing.T) {
	directRoundTrip(t, dns.RRTypeA)
}

func directRoundTrip(t *testing.T, qtype uint16) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := pc.LocalAddr().String()
	pc.Close()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		err := server.Serve(ctx, server.Config{
			Listen:  udpAddr,
			Domain:  domain,
			EncKey:  "test-enc-key",
			Target:  echo.Addr().String(),
			UDPSize: 1232,
		})
		if err != nil && ctx.Err() == nil {
			t.Errorf("server: %v", err)
		}
	}()

	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localAddr := local.Addr().String()
	local.Close()
	go func() {
		_ = Serve(ctx, Config{
			Listen: localAddr,
			Domain: domain,
			EncKey: "test-enc-key",
			Remote: udpAddr,
			QType:  qtype,
		})
	}()

	deadline := time.Now().Add(20 * time.Second)
	var conn net.Conn
	for {
		conn, err = net.DialTimeout("tcp", localAddr, time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial local: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := []byte("ping-through-dns")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q", buf)
	}
}

func TestIsLocalClose(t *testing.T) {
	err := &net.OpError{Op: "read", Err: syscall.ECONNRESET}
	if !isLocalClose(err) {
		t.Fatal("ECONNRESET should be a local hangup")
	}
}

// TestDirectBulk pushes several streams at once, each larger than the old
// 128-packet queue. A browser does this. The transfer has to finish by the
// window blocking the writers, not by discarding DNS queries.
func TestDirectBulk(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := pc.LocalAddr().String()
	pc.Close()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		err := server.Serve(ctx, server.Config{
			Listen:  udpAddr,
			Domain:  domain,
			EncKey:  "test-enc-key",
			Target:  echo.Addr().String(),
			UDPSize: 1232,
		})
		if err != nil && ctx.Err() == nil {
			t.Errorf("server: %v", err)
		}
	}()

	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	localAddr := local.Addr().String()
	local.Close()
	go func() {
		_ = Serve(ctx, Config{
			Listen: localAddr,
			Domain: domain,
			EncKey: "test-enc-key",
			Remote: udpAddr,
		})
	}()

	const streams = 4
	payload := bytes.Repeat([]byte("abcdefgh"), 4*1024) // 32 KiB each
	var wg sync.WaitGroup
	errCh := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(20 * time.Second)
			var conn net.Conn
			var err error
			for {
				conn, err = net.DialTimeout("tcp", localAddr, time.Second)
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					errCh <- err
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
			writeErr := make(chan error, 1)
			go func() {
				_, err := conn.Write(payload)
				writeErr <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				errCh <- err
				return
			}
			if err := <-writeErr; err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, payload) {
				errCh <- io.ErrShortBuffer
				return
			}
			errCh <- nil
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}
