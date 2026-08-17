package client

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/common/dualbind"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/things-go/go-socks5"
)

// socksLogger adapts PTLog to the socks5.Logger interface.
type socksLogger struct {
	lg      ptlog.PTLog
	verbose bool
}

func (sl *socksLogger) Printf(format string, v ...interface{}) {
	if sl.verbose {
		sl.lg.Debug(fmt.Sprintf(format, v...))
	}
}

func (sl *socksLogger) Errorf(format string, v ...interface{}) {
	sl.lg.Error(fmt.Sprintf(format, v...))
}

// ProxyServer runs SOCKS and/or HTTP proxy listeners.
type ProxyServer struct {
	transport   *Transport
	socksAddr   string
	httpAddr    string
	dnsUpstream string
	dnsNetwork  string
	listeners   []net.Listener
	log         ptlog.PTLog
	verbose     bool
	skipUDP     bool
}

// ProxyConfig holds proxy configuration.
type ProxyConfig struct {
	Transport   *Transport
	SOCKSAddr   string
	HTTPAddr    string
	DNSUpstream string // IP:port, e.g. "1.1.1.1:53"
	DNSNetwork  string // "tcp" or "udp"
	Verbose     bool
	LogTag      string
	SkipUDP     bool
}

// NewProxyServer creates a proxy server.
func NewProxyServer(cfg ProxyConfig) *ProxyServer {
	return &ProxyServer{
		transport:   cfg.Transport,
		socksAddr:   cfg.SOCKSAddr,
		httpAddr:    cfg.HTTPAddr,
		dnsUpstream: cfg.DNSUpstream,
		dnsNetwork:  cfg.DNSNetwork,
		log:         ptlog.PTLog{LogTag: cfg.LogTag},
		verbose:     cfg.Verbose,
		skipUDP:     cfg.SkipUDP,
	}
}

func (p *ProxyServer) debugf(format string, v ...interface{}) {
	if p.verbose {
		p.log.Debug(fmt.Sprintf(format, v...))
	}
}

// Run starts the proxy listeners.
func (p *ProxyServer) Run() error {
	if p.socksAddr != "" {
		go p.serveSOCKS()
	}

	if p.httpAddr != "" {
		ln, err := net.Listen("tcp", p.httpAddr)
		if err != nil {
			return err
		}
		p.listeners = append(p.listeners, ln)
		go p.serveHTTP(ln)
		p.log.Info("HTTP proxy on", p.httpAddr)
	}

	return nil
}

// RunTCP listens for raw TCP and pipes each connection through the tunnel
// (server external-service mode).
func (p *ProxyServer) RunTCP() error {
	addr := p.socksAddr
	if addr == "" {
		addr = p.httpAddr
	}
	if addr == "" {
		return fmt.Errorf("no listen address")
	}
	ln, udp, bound, err := dualbind.Listen(addr)
	if err != nil {
		return err
	}
	p.listeners = append(p.listeners, ln)
	p.log.Info("forward listen", bound)
	if udp != nil && !p.skipUDP {
		go p.handleUDPForward(udp)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleTCPForward(conn)
		}
	}()
	return nil
}

func (p *ProxyServer) handleUDPForward(pc *net.UDPConn) {
	for {
		if err := p.runUDPForwardOnce(pc); err != nil {
			p.log.Error("udp forward:", err)
		}
		time.Sleep(time.Second)
	}
}

func (p *ProxyServer) runUDPForwardOnce(pc *net.UDPConn) error {
	buf := make([]byte, 65535)
	var last *net.UDPAddr
	var lastMu sync.Mutex
	connID, err := p.transport.Connect("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	tunnel, err := newTunnelConn(p.transport, connID, p.log, p.verbose)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	errCh := make(chan error, 2)
	go func() {
		b := make([]byte, 65535)
		for {
			n, err := tunnel.Read(b)
			if n > 0 {
				lastMu.Lock()
				dst := last
				lastMu.Unlock()
				if dst != nil {
					_, _ = pc.WriteToUDP(b[:n], dst)
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				errCh <- err
				return
			}
			lastMu.Lock()
			last = from
			lastMu.Unlock()
			if _, err := tunnel.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return <-errCh
}

func (p *ProxyServer) RunReverse(listen, local string) error {
	p.transport.ReverseLocal = local
	go p.reverseMaintain(listen, local)
	p.log.Info("reverse requested", listen, "->", local)
	return nil
}

func (p *ProxyServer) reverseMaintain(listen, local string) {
	for {
		if err := p.transport.SendReverseBind(listen); err != nil {
			p.log.Error("reverse bind:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		p.log.Info("reverse bind ok", listen, "->", local)
		// Wait until stream sessions die, then re-bind.
		for p.transport.HasLiveSession() {
			time.Sleep(3 * time.Second)
		}
		time.Sleep(time.Second)
	}
}

func (p *ProxyServer) handleTCPForward(conn net.Conn) {
	defer conn.Close()
	connID, err := p.transport.Connect("tcp", "127.0.0.1:0")
	if err != nil {
		p.log.Error("external connect:", err)
		return
	}
	tunnel, err := newTunnelConn(p.transport, connID, p.log, p.verbose)
	if err != nil {
		p.log.Error("external tunnel:", err)
		_ = p.transport.CloseConn(connID)
		return
	}
	defer tunnel.Close()
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(tunnel, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, tunnel)
		errCh <- err
	}()
	<-errCh
}

func (p *ProxyServer) serveSOCKS() {
	resolver := newTunneledResolver(p.transport, p.dnsNetwork, p.dnsUpstream, p.log, p.verbose)
	server := socks5.NewServer(
		socks5.WithResolver(resolver),
		socks5.WithDial(tunnelDialContext(p.transport, p.log, p.verbose)),
		socks5.WithLogger(&socksLogger{lg: p.log, verbose: p.verbose}),
	)

	p.log.Info("SOCKS5 proxy on", p.socksAddr, "uses tunneled DNS ("+p.dnsNetwork, "->", p.dnsUpstream+")")
	if err := server.ListenAndServe("tcp", p.socksAddr); err != nil {
		p.log.Fatal("SOCKS5:", err)
	}
}

// tunnelConn implements net.Conn over the HTTP tunnel.
type tunnelConn struct {
	transport *Transport
	connID    uint32
	reader    io.ReadCloser
	readBuf   []byte
	readCh    chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
	writeCh   chan writeReq
	log       ptlog.PTLog
	verbose   bool
}

type writeReq struct {
	data []byte
	ack  chan error
}

func newTunnelConn(transport *Transport, connID uint32, lg ptlog.PTLog, verbose bool) (net.Conn, error) {
	tc := &tunnelConn{
		transport: transport,
		connID:    connID,
		readCh:    make(chan []byte, 16),
		writeCh:   make(chan writeReq, 64),
		closeCh:   make(chan struct{}),
		closeOnce: sync.Once{},
		log:       lg,
		verbose:   verbose,
	}
	stream, err := transport.DownloadStream(nil, connID)
	if err != nil {
		return nil, err
	}
	tc.reader = stream
	go tc.pumpRead()
	go tc.pumpWrite()
	tc.debug("New tunnel connection created")
	return tc, nil
}

func (tc *tunnelConn) debug(v ...any) {
	if tc.verbose {
		tc.log.Debug(v...)
	}
}

func (tc *tunnelConn) pumpRead() {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-tc.closeCh:
			return
		default:
		}
		n, err := tc.reader.Read(buf)
		if n > 0 {
			tc.debug("Read", n, "bytes from stream")
			dup := make([]byte, n)
			copy(dup, buf[:n])
			select {
			case tc.readCh <- dup:
			case <-tc.closeCh:
				return
			}
		}
		if err != nil {
			tc.debug("Stream read error:", err)
			select {
			case <-tc.closeCh:
			default:
				close(tc.readCh)
			}
			return
		}
	}
}

func (tc *tunnelConn) Read(b []byte) (int, error) {
	if len(tc.readBuf) > 0 {
		n := copy(b, tc.readBuf)
		tc.readBuf = tc.readBuf[n:]
		tc.debug("Read", n, "bytes from buffer")
		return n, nil
	}
	data, ok := <-tc.readCh
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	if n < len(data) {
		tc.readBuf = data[n:]
	}
	tc.debug("Read", n, "bytes from channel")
	return n, nil
}

func (tc *tunnelConn) Write(b []byte) (int, error) {
	data := make([]byte, len(b))
	copy(data, b)
	req := writeReq{
		data: data,
		ack:  make(chan error, 1),
	}
	select {
	case tc.writeCh <- req:
	case <-tc.closeCh:
		return 0, io.EOF
	}

	select {
	case err := <-req.ack:
		if err != nil {
			return 0, err
		}
	case <-tc.closeCh:
		return 0, io.EOF
	}
	return len(b), nil
}

func (tc *tunnelConn) pumpWrite() {
	const (
		maxBatchBytes = 64 * 1024
		flushDelay    = 5 * time.Millisecond
	)
	var (
		batch bytes.Buffer
		acks  []chan error
		timer *time.Timer
	)

	flush := func(err error) {
		for _, ack := range acks {
			ack <- err
			close(ack)
		}
		acks = acks[:0]
		batch.Reset()
		if timer != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer = nil
		}
	}

	sendBatch := func() bool {
		if batch.Len() == 0 {
			return true
		}
		tc.debug("Writing batched", batch.Len(), "bytes")
		if err := tc.transport.SendData(tc.connID, batch.Bytes()); err != nil {
			flush(err)
			tc.Close()
			return false
		}
		flush(nil)
		return true
	}

	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}

		select {
		case req := <-tc.writeCh:
			batch.Write(req.data)
			acks = append(acks, req.ack)
			if batch.Len() >= maxBatchBytes {
				if !sendBatch() {
					return
				}
				continue
			}
			if timer == nil {
				timer = time.NewTimer(flushDelay)
			}
		case <-timerC:
			if !sendBatch() {
				return
			}
		case <-tc.closeCh:
			if batch.Len() > 0 {
				_ = sendBatch()
			}
			return
		}
	}
}

func (tc *tunnelConn) Close() error {
	tc.closeOnce.Do(func() {
		tc.debug("Closing connection")
		close(tc.closeCh)
		tc.transport.CloseConn(tc.connID)
		if tc.reader != nil {
			tc.reader.Close()
		}
	})
	return nil
}

func (tc *tunnelConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (tc *tunnelConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (tc *tunnelConn) SetDeadline(t time.Time) error      { return nil }
func (tc *tunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (tc *tunnelConn) SetWriteDeadline(t time.Time) error { return nil }

// serveHTTP handles HTTP CONNECT proxy.
func (p *ProxyServer) serveHTTP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.debugf("HTTP accept error: %v", err)
			return
		}
		go p.handleHTTPProxy(conn)
	}
}

func (p *ProxyServer) handleHTTPProxy(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	req, err := http.ReadRequest(br)
	if err != nil {
		p.debugf("HTTP proxy read request error: %v", err)
		return
	}

	p.debugf("Request to %s", req.Host)

	if req.Method != http.MethodConnect {
		p.debugf("Unsupported method: %s", req.Method)
		resp := &http.Response{
			StatusCode: http.StatusMethodNotAllowed,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(conn)
		return
	}

	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	connID, err := p.transport.Connect("tcp", host)
	if err != nil {
		p.log.Error("Failed to connect to", host+":", err)
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(conn)
		return
	}
	p.debugf("Tunnel established for %s", host)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := resp.Write(conn); err != nil {
		p.log.Error("Failed to write CONNECT OK:", err)
		return
	}

	tunnel, err := newTunnelConn(p.transport, connID, p.log, p.verbose)
	if err != nil {
		p.log.Error("Failed to create tunnel connection:", err)
		return
	}
	defer tunnel.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(tunnel, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, tunnel)
		errCh <- err
	}()

	err = <-errCh
	p.debugf("Proxy connection closed for %s: %v", host, err)
}

// ParseProxyAuth extracts credentials from Proxy-Authorization header.
func ParseProxyAuth(auth string) (user, pass string, ok bool) {
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(dec), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
