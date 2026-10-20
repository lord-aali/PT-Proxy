package core

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	f := Frame{Type: TypeOpenTCP, ConnID: 42, Data: []byte("127.0.0.1:80")}
	b, err := EncodeFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != f.Type || out.ConnID != f.ConnID || string(out.Data) != string(f.Data) {
		t.Fatalf("mismatch: %+v vs %+v", out, f)
	}
}

func TestFramePadded(t *testing.T) {
	f := Frame{Type: TypeData, ConnID: 7, Data: []byte("hello")}
	b, err := EncodeFramePadded(f, 10)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeFrame(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Data) != "hello" {
		t.Fatalf("got %q", out.Data)
	}
}

func TestCryptoRoundTrip(t *testing.T) {
	enc, err := NewEncryptor([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := enc.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "payload" {
		t.Fatalf("got %q", pt)
	}
}

func TestLinkHandshakeServe(t *testing.T) {
	c1, c2 := net.Pipe()
	enc, err := NewEncryptor([]byte("shared"))
	if err != nil {
		t.Fatal(err)
	}
	srvLink := NewLink(c1, enc, 0, 0)
	cliLink := NewLink(c2, enc, 0, 0)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		_, _ = c.Write(bytes.ToUpper(buf[:n]))
	}()

	done := make(chan struct{})
	go func() {
		Serve(srvLink, ServerConfig{Target: ln.Addr().String()})
		close(done)
	}()

	if err := HandshakeClient(cliLink); err != nil {
		t.Fatal(err)
	}
	sess := NewClientSession(cliLink, "")
	conn, err := sess.OpenTCP("ignored")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ABC" {
		t.Fatalf("got %q", buf[:n])
	}
	_ = sess.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}
