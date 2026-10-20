package core

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Serve runs a server session over fc until the link closes.
func Serve(fc FrameConn, cfg ServerConfig) {
	eng := NewServerEngine(cfg, fc.WriteFrame)
	defer eng.Close()
	defer fc.Close()
	for {
		fr, err := fc.ReadFrame()
		if err != nil {
			return
		}
		eng.Handle(fr)
	}
}

type ClientSession struct {
	fc          FrameConn
	nextID      atomic.Uint32
	mu          sync.Mutex
	flows       map[uint32]chan Frame
	dnsWait     map[uint32]chan []byte
	reverseWait chan string
	reverseAddr string
	eng         *Engine
}

func HandshakeClient(fc FrameConn) error {
	if err := fc.WriteFrame(Frame{Type: TypeHello, Data: []byte{Version}}); err != nil {
		return err
	}
	fr, err := fc.ReadFrame()
	if err != nil {
		return err
	}
	if fr.Type != TypeHelloOK {
		return fmt.Errorf("unexpected hello reply %d", fr.Type)
	}
	return nil
}

func NewClientSession(fc FrameConn, reverseAddr string) *ClientSession {
	s := &ClientSession{
		fc:          fc,
		flows:       make(map[uint32]chan Frame),
		dnsWait:     make(map[uint32]chan []byte),
		reverseWait: make(chan string, 1),
		reverseAddr: reverseAddr,
	}
	s.nextID.Store(1)
	s.eng = NewClientEngine(reverseAddr, fc.WriteFrame)
	go s.readLoop()
	return s
}

func (s *ClientSession) Close() error {
	if s.eng != nil {
		s.eng.Close()
	}
	return s.fc.Close()
}

func (s *ClientSession) readLoop() {
	for {
		fr, err := s.fc.ReadFrame()
		if err != nil {
			s.mu.Lock()
			for _, ch := range s.flows {
				close(ch)
			}
			s.flows = map[uint32]chan Frame{}
			for _, ch := range s.dnsWait {
				close(ch)
			}
			s.dnsWait = map[uint32]chan []byte{}
			s.mu.Unlock()
			return
		}
		switch fr.Type {
		case TypeHelloOK:
			select {
			case s.reverseWait <- string(fr.Data):
			default:
			}
		case TypeDNSResp:
			s.mu.Lock()
			ch := s.dnsWait[fr.ConnID]
			delete(s.dnsWait, fr.ConnID)
			s.mu.Unlock()
			if ch != nil {
				select {
				case ch <- fr.Data:
				default:
				}
			}
		case TypeReverseOpen:
			if s.eng != nil {
				s.eng.Handle(fr)
			}
		case TypeData, TypeClose:
			s.mu.Lock()
			ch := s.flows[fr.ConnID]
			s.mu.Unlock()
			if ch != nil {
				// Must not drop: blocking deliver keeps proxy data intact.
				ch <- fr
			} else if s.eng != nil {
				s.eng.Handle(fr)
			}
		}
	}
}

func (s *ClientSession) OpenTCP(addr string) (net.Conn, error) {
	id := s.nextID.Add(1)
	ch := make(chan Frame, 64)
	s.mu.Lock()
	s.flows[id] = ch
	s.mu.Unlock()
	if err := s.fc.WriteFrame(Frame{Type: TypeOpenTCP, ConnID: id, Data: []byte(addr)}); err != nil {
		return nil, err
	}
	return &flowConn{s: s, id: id, ch: ch}, nil
}

func (s *ClientSession) OpenUDP(addr string) (net.Conn, error) {
	id := s.nextID.Add(1)
	ch := make(chan Frame, 64)
	s.mu.Lock()
	s.flows[id] = ch
	s.mu.Unlock()
	if err := s.fc.WriteFrame(Frame{Type: TypeOpenUDP, ConnID: id, Data: []byte(addr)}); err != nil {
		return nil, err
	}
	return &flowConn{s: s, id: id, ch: ch}, nil
}

func (s *ClientSession) DNS(query []byte) ([]byte, error) {
	id := s.nextID.Add(1)
	ch := make(chan []byte, 1)
	s.mu.Lock()
	s.dnsWait[id] = ch
	s.mu.Unlock()
	if err := s.fc.WriteFrame(Frame{Type: TypeDNSReq, ConnID: id, Data: query}); err != nil {
		return nil, err
	}
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, io.EOF
		}
		return resp, nil
	case <-time.After(15 * time.Second):
		s.mu.Lock()
		delete(s.dnsWait, id)
		s.mu.Unlock()
		return nil, fmt.Errorf("dns timeout")
	}
}

func (s *ClientSession) RequestReverse(listen string) (string, error) {
	if err := s.fc.WriteFrame(Frame{Type: TypeReverseBind, Data: []byte(listen)}); err != nil {
		return "", err
	}
	select {
	case bound := <-s.reverseWait:
		return bound, nil
	case <-time.After(15 * time.Second):
		return "", fmt.Errorf("reverse bind timeout")
	}
}

type flowConn struct {
	s    *ClientSession
	id   uint32
	ch   chan Frame
	rbuf []byte
}

func (c *flowConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	fr, ok := <-c.ch
	if !ok {
		return 0, io.EOF
	}
	if fr.Type == TypeClose {
		return 0, io.EOF
	}
	n := copy(p, fr.Data)
	if n < len(fr.Data) {
		c.rbuf = append([]byte(nil), fr.Data[n:]...)
	}
	return n, nil
}

func (c *flowConn) Write(p []byte) (int, error) {
	data := make([]byte, len(p))
	copy(data, p)
	if err := c.s.fc.WriteFrame(Frame{Type: TypeData, ConnID: c.id, Data: data}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *flowConn) Close() error {
	_ = c.s.fc.WriteFrame(Frame{Type: TypeClose, ConnID: c.id})
	c.s.mu.Lock()
	ch := c.s.flows[c.id]
	delete(c.s.flows, c.id)
	c.s.mu.Unlock()
	if ch != nil {
		// Unblock Read without closing the channel (avoids panic if readLoop is sending).
		select {
		case ch <- Frame{Type: TypeClose, ConnID: c.id}:
		default:
		}
	}
	return nil
}

func (c *flowConn) LocalAddr() net.Addr                { return stubAddr("carrier") }
func (c *flowConn) RemoteAddr() net.Addr               { return stubAddr("carrier") }
func (c *flowConn) SetDeadline(t time.Time) error      { return nil }
func (c *flowConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *flowConn) SetWriteDeadline(t time.Time) error { return nil }

type stubAddr string

func (s stubAddr) Network() string { return string(s) }
func (s stubAddr) String() string  { return string(s) }
