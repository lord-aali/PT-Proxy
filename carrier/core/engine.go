package core

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/common/dualbind"
)

type ServerConfig struct {
	Target      string
	SkipUDP     bool
	DNSNetwork  string
	DNSUpstream string
}

type flow struct {
	conn net.Conn
	udp  *net.UDPConn
}

func closeFlow(f *flow) {
	if f == nil {
		return
	}
	if f.conn != nil {
		_ = f.conn.Close()
	}
	if f.udp != nil {
		_ = f.udp.Close()
	}
}

// Writer emits a frame toward the peer (HTTP body, FTP channel, TCP link, …).
type Writer func(Frame) error

// Engine is the shared inner proxy session used by tcp/udp carriers and by
// DPI/FTP adapters that keep their own outer camouflage.
type Engine struct {
	cfg     ServerConfig
	write   Writer
	flows   map[uint32]*flow
	mu      sync.Mutex
	revLn   net.Listener
	revMu   sync.Mutex
	nextRev atomic.Uint32
	client  bool // when true, ReverseOpen dials ReverseAddr
	revAddr string
}

func NewServerEngine(cfg ServerConfig, write Writer) *Engine {
	e := &Engine{cfg: cfg, write: write, flows: make(map[uint32]*flow)}
	e.nextRev.Store(1 << 30)
	return e
}

func NewClientEngine(reverseAddr string, write Writer) *Engine {
	return &Engine{
		write:   write,
		flows:   make(map[uint32]*flow),
		client:  true,
		revAddr: reverseAddr,
	}
}

func (e *Engine) Close() {
	e.mu.Lock()
	for _, f := range e.flows {
		closeFlow(f)
	}
	e.flows = map[uint32]*flow{}
	e.mu.Unlock()
	e.revMu.Lock()
	if e.revLn != nil {
		_ = e.revLn.Close()
		e.revLn = nil
	}
	e.revMu.Unlock()
}

func (e *Engine) unregister(id uint32) {
	e.mu.Lock()
	if f, ok := e.flows[id]; ok {
		delete(e.flows, id)
		closeFlow(f)
	}
	e.mu.Unlock()
}

// Handle processes one inbound frame. Safe for concurrent calls from multiple
// outer channels as long as Write is synchronized by the caller if needed.
func (e *Engine) Handle(fr Frame) {
	if e.client {
		e.handleClient(fr)
		return
	}
	e.handleServer(fr)
}

func (e *Engine) handleServer(fr Frame) {
	switch fr.Type {
	case TypeHello:
		_ = e.write(Frame{Type: TypeHelloOK})
	case TypePad:
		return
	case TypeOpenTCP:
		dialAddr := string(fr.Data)
		if e.cfg.Target != "" {
			dialAddr = e.cfg.Target
		}
		c, err := net.DialTimeout("tcp", dialAddr, 30*time.Second)
		if err != nil {
			_ = e.write(Frame{Type: TypeClose, ConnID: fr.ConnID})
			return
		}
		e.mu.Lock()
		e.flows[fr.ConnID] = &flow{conn: c}
		e.mu.Unlock()
		go e.pumpTCP(fr.ConnID, c)
	case TypeOpenUDP:
		if e.cfg.SkipUDP {
			_ = e.write(Frame{Type: TypeClose, ConnID: fr.ConnID})
			return
		}
		dialAddr := string(fr.Data)
		if e.cfg.Target != "" {
			dialAddr = e.cfg.Target
		}
		ua, err := net.ResolveUDPAddr("udp", dialAddr)
		if err != nil {
			_ = e.write(Frame{Type: TypeClose, ConnID: fr.ConnID})
			return
		}
		c, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			_ = e.write(Frame{Type: TypeClose, ConnID: fr.ConnID})
			return
		}
		e.mu.Lock()
		e.flows[fr.ConnID] = &flow{udp: c}
		e.mu.Unlock()
		go e.pumpUDP(fr.ConnID, c)
	case TypeData:
		e.mu.Lock()
		f := e.flows[fr.ConnID]
		e.mu.Unlock()
		if f == nil {
			return
		}
		if f.conn != nil {
			_, _ = f.conn.Write(fr.Data)
		} else if f.udp != nil {
			_, _ = f.udp.Write(fr.Data)
		}
	case TypeClose:
		e.unregister(fr.ConnID)
	case TypeDNSReq:
		resp, err := ResolveDNS(e.cfg.DNSNetwork, e.cfg.DNSUpstream, fr.Data)
		if err != nil {
			return
		}
		_ = e.write(Frame{Type: TypeDNSResp, ConnID: fr.ConnID, Data: resp})
	case TypeReverseBind:
		listen := string(fr.Data)
		e.revMu.Lock()
		if e.revLn != nil {
			_ = e.revLn.Close()
		}
		ln, _, bound, err := dualbind.Listen(listen)
		if err != nil {
			e.revMu.Unlock()
			return
		}
		e.revLn = ln
		e.revMu.Unlock()
		_ = e.write(Frame{Type: TypeHelloOK, Data: []byte(bound)})
		go e.acceptReverse(ln)
	}
}

func (e *Engine) handleClient(fr Frame) {
	switch fr.Type {
	case TypeReverseOpen:
		if e.revAddr == "" {
			return
		}
		go e.dialReverse(fr.ConnID)
	case TypeData:
		e.mu.Lock()
		f := e.flows[fr.ConnID]
		e.mu.Unlock()
		if f != nil && f.conn != nil {
			_, _ = f.conn.Write(fr.Data)
		}
	case TypeClose:
		e.unregister(fr.ConnID)
	}
}

func (e *Engine) dialReverse(id uint32) {
	c, err := net.DialTimeout("tcp", e.revAddr, 30*time.Second)
	if err != nil {
		_ = e.write(Frame{Type: TypeClose, ConnID: id})
		return
	}
	e.mu.Lock()
	e.flows[id] = &flow{conn: c}
	e.mu.Unlock()
	e.pumpTCP(id, c)
}

func (e *Engine) acceptReverse(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		id := e.nextRev.Add(1)
		e.mu.Lock()
		e.flows[id] = &flow{conn: c}
		e.mu.Unlock()
		if err := e.write(Frame{Type: TypeReverseOpen, ConnID: id}); err != nil {
			e.unregister(id)
			return
		}
		go e.pumpTCP(id, c)
	}
}

func (e *Engine) pumpTCP(id uint32, c net.Conn) {
	defer e.unregister(id)
	defer c.Close()
	buf := make([]byte, 32*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			if werr := e.write(Frame{Type: TypeData, ConnID: id, Data: data}); werr != nil {
				return
			}
		}
		if err != nil {
			_ = e.write(Frame{Type: TypeClose, ConnID: id})
			return
		}
	}
}

func (e *Engine) pumpUDP(id uint32, c *net.UDPConn) {
	defer e.unregister(id)
	defer c.Close()
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			if werr := e.write(Frame{Type: TypeData, ConnID: id, Data: data}); werr != nil {
				return
			}
		}
		if err != nil {
			_ = e.write(Frame{Type: TypeClose, ConnID: id})
			return
		}
	}
}

// AttachFlow registers an already-open remote conn (used by adapters mid-migration).
func (e *Engine) AttachFlow(id uint32, c net.Conn) {
	e.mu.Lock()
	e.flows[id] = &flow{conn: c}
	e.mu.Unlock()
	go e.pumpTCP(id, c)
}

// WriteData writes payload to a registered flow.
func (e *Engine) WriteData(id uint32, data []byte) error {
	e.mu.Lock()
	f := e.flows[id]
	e.mu.Unlock()
	if f == nil {
		return io.ErrClosedPipe
	}
	if f.conn != nil {
		_, err := f.conn.Write(data)
		return err
	}
	if f.udp != nil {
		_, err := f.udp.Write(data)
		return err
	}
	return io.ErrClosedPipe
}
