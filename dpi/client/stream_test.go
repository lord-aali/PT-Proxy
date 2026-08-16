package client

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/dpi/common"
	"github.com/lord-aali/PT-Proxy/dpi/server"
)

func TestStreamUplinkEcho(t *testing.T) {
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

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	encKey := []byte("stream-test-key")
	srv, err := server.NewServer(server.Config{
		HTTPAddr:      httpAddr,
		EncryptionKey: encKey,
		LogTag:        "dpi-test",
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
	host, port, _ := net.SplitHostPort(httpAddr)
	tr, err := NewTransport(TransportConfig{
		ServerURL: "http://" + httpAddr,
		Encryptor: enc,
		DialIP:    host,
		Uplink:    common.UplinkStream,
		LogTag:    "dpi-client-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = port

	done := make(chan struct{})
	go func() {
		defer close(done)
		connID, err := tr.Connect("tcp", echoLn.Addr().String())
		if err != nil {
			t.Errorf("connect: %v", err)
			return
		}
		payload := []byte("hello-stream")
		if err := tr.SendData(connID, payload); err != nil {
			t.Errorf("send: %v", err)
			return
		}
		r, err := tr.DownloadStream(nil, connID)
		if err != nil {
			t.Errorf("download: %v", err)
			return
		}
		defer r.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Errorf("read: %v", err)
			return
		}
		if string(buf) != string(payload) {
			t.Errorf("got %q want %q", buf, payload)
		}
		_ = tr.CloseConn(connID)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream uplink timed out (deadlock or dropped frames)")
	}
}
