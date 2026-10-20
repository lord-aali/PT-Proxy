package gre

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
)

func TestSeqParity(t *testing.T) {
	c := &Link{role: roleClient}
	s := &Link{role: roleServer}
	if c.nextSeq() != 1 || c.nextSeq() != 3 {
		t.Fatal("client seq")
	}
	if s.nextSeq() != 2 || s.nextSeq() != 4 {
		t.Fatal("server seq")
	}
	if !c.isOwn(Packet{HasSeq: true, Seq: 1}) || c.isOwn(Packet{HasSeq: true, Seq: 2}) {
		t.Fatal("client echo check")
	}
	if !s.isOwn(Packet{HasSeq: true, Seq: 4}) || s.isOwn(Packet{HasSeq: true, Seq: 3}) {
		t.Fatal("server echo check")
	}
}

// loopConn delivers every Write back to the sender and to the peer, the way a
// Windows raw socket does on loopback.
type loopConn struct {
	self chan []byte
	peer *loopConn
	once sync.Once
}

func newLoopPair() (*loopConn, *loopConn) {
	a := &loopConn{self: make(chan []byte, 16)}
	b := &loopConn{self: make(chan []byte, 16)}
	a.peer = b
	b.peer = a
	return a, b
}

func (c *loopConn) Write(p []byte) (int, error) {
	b := append([]byte(nil), p...)
	c.self <- b
	c.peer.self <- b
	return len(p), nil
}

func (c *loopConn) Read(p []byte) (int, error) {
	b, ok := <-c.self
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (c *loopConn) Close() error {
	c.once.Do(func() { close(c.self) })
	return nil
}

func (c *loopConn) LocalAddr() net.Addr              { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *loopConn) RemoteAddr() net.Addr             { return c.LocalAddr() }
func (c *loopConn) SetDeadline(time.Time) error      { return nil }
func (c *loopConn) SetReadDeadline(time.Time) error  { return nil }
func (c *loopConn) SetWriteDeadline(time.Time) error { return nil }
func (c *loopConn) ReadFrom([]byte) (int, net.Addr, error) {
	n, err := c.Read(make([]byte, 0))
	return n, c.LocalAddr(), err
}
func (c *loopConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func TestHandshakeSkipsLoopbackEcho(t *testing.T) {
	enc, err := core.NewEncryptor([]byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	a, b := newLoopPair()
	srv := NewLink(b, nil, enc, 1, 0, 0, false, true)
	srv.role = roleServer
	cli := NewLink(a, nil, enc, 1, 0, 0, false, true)
	cli.role = roleClient
	cli.readWait = 2 * time.Second

	done := make(chan struct{})
	go func() {
		defer close(done)
		core.Serve(srv, core.ServerConfig{})
	}()

	if err := core.HandshakeClient(cli); err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}
