// common/ftpclient.go — FTP/FTPS connection pool.
package common

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// ─── Single FTP connection ────────────────────────────────────────────────────

type FTPConn struct {
	mu     sync.Mutex
	ctrl   *textproto.Conn
	raw    net.Conn
	addr   string
	user   string
	pass   string
	useTLS bool
	tlsCfg *tls.Config
	dead   bool
	// Optional full host:port overrides for PASV data dials. When set, the
	// data connection is dialed to an override address (port match preferred;
	// otherwise a full override is used — for NAT where public≠internal ports).
	pasvOverrides []string
}

// DialFTP opens one authenticated FTP/FTPS control connection.
func DialFTP(addr, user, pass string, useTLS bool, tlsCfg *tls.Config) (*FTPConn, error) {
	return dialOne(addr, user, pass, useTLS, tlsCfg)
}

func dialOne(addr, user, pass string, useTLS bool, tlsCfg *tls.Config) (*FTPConn, error) {
	raw, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	c := &FTPConn{addr: addr, user: user, pass: pass, useTLS: useTLS, tlsCfg: tlsCfg}

	if useTLS {
		tmp := textproto.NewConn(raw)
		if _, _, err := tmp.ReadResponse(220); err != nil {
			raw.Close()
			return nil, fmt.Errorf("banner: %w", err)
		}
		id, err := tmp.Cmd("AUTH TLS")
		if err != nil {
			raw.Close()
			return nil, err
		}
		tmp.StartResponse(id)
		tmp.EndResponse(id)
		if _, _, err := tmp.ReadResponse(234); err != nil {
			raw.Close()
			return nil, fmt.Errorf("AUTH TLS: %w", err)
		}
		host, _, _ := net.SplitHostPort(addr)
		cfg := tlsCfg
		if cfg == nil {
			cfg = &tls.Config{ServerName: host, InsecureSkipVerify: true} //nolint:gosec
		} else {
			cfg = cfg.Clone()
			cfg.ServerName = host
			cfg.InsecureSkipVerify = true //nolint:gosec
		}
		tlsConn := tls.Client(raw, cfg)
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		c.raw = tlsConn
		c.ctrl = textproto.NewConn(tlsConn)
		for _, cmd := range []struct {
			exp  int
			line string
		}{
			{331, "USER " + user},
			{230, "PASS " + pass},
			{200, "PBSZ 0"},
			{200, "PROT P"},
			{200, "TYPE I"},
		} {
			if err := c.simpleCmd(cmd.exp, cmd.line); err != nil {
				c.raw.Close()
				return nil, err
			}
		}
	} else {
		c.raw = raw
		c.ctrl = textproto.NewConn(raw)
		if _, _, err := c.ctrl.ReadResponse(220); err != nil {
			raw.Close()
			return nil, fmt.Errorf("banner: %w", err)
		}
		for _, cmd := range []struct {
			exp  int
			line string
		}{
			{331, "USER " + user},
			{230, "PASS " + pass},
			{200, "TYPE I"},
		} {
			if err := c.simpleCmd(cmd.exp, cmd.line); err != nil {
				raw.Close()
				return nil, err
			}
		}
	}
	return c, nil
}

func (c *FTPConn) simpleCmd(expect int, line string) error {
	id, err := c.ctrl.Cmd(line)
	if err != nil {
		return err
	}
	c.ctrl.StartResponse(id)
	defer c.ctrl.EndResponse(id)
	_, _, err = c.ctrl.ReadResponse(expect)
	return err
}

func (c *FTPConn) pasv() (net.Conn, error) {
	id, err := c.ctrl.Cmd("PASV")
	if err != nil {
		return nil, err
	}
	c.ctrl.StartResponse(id)
	defer c.ctrl.EndResponse(id)
	_, msg, err := c.ctrl.ReadResponse(227)
	if err != nil {
		return nil, err
	}
	addr, err := ParsePASV(msg)
	if err != nil {
		return nil, err
	}
	addr = applyPasvOverrides(addr, c.pasvOverrides)

	dc, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if c.useTLS && c.tlsCfg != nil {
		host, _, _ := net.SplitHostPort(addr)
		cfg := c.tlsCfg.Clone()
		cfg.ServerName = host
		tlsDC := tls.Client(dc, cfg)
		if err := tlsDC.Handshake(); err != nil {
			dc.Close()
			return nil, fmt.Errorf("data TLS: %w", err)
		}
		return tlsDC, nil
	}
	return dc, nil
}

// applyPasvOverrides picks a dial address from PASV + optional host:port overrides.
// When overrides are set, always dial an override host:port (never keep the PASV
// port under a rewritten host) so NAT-mapped public ports work.
func applyPasvOverrides(pasvAddr string, overrides []string) string {
	var usable []string
	for _, o := range overrides {
		if o != "" {
			usable = append(usable, o)
		}
	}
	if len(usable) == 0 {
		return pasvAddr
	}
	_, pasvPort, err := net.SplitHostPort(pasvAddr)
	if err == nil {
		for _, o := range usable {
			_, op, err := net.SplitHostPort(o)
			if err == nil && op == pasvPort {
				return o
			}
		}
	}
	// Ports don't match (NAT remap): use a full override as-is.
	if len(usable) == 1 {
		return usable[0]
	}
	return usable[rand.Intn(len(usable))]
}

// SetPasvAddrOverrides sets full host:port dial overrides for PASV data connections.
// When set, data dials use these addresses instead of the PASV host:port.
func (c *FTPConn) SetPasvAddrOverrides(addrs ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pasvOverrides = c.pasvOverrides[:0]
	for _, a := range addrs {
		if a != "" {
			c.pasvOverrides = append(c.pasvOverrides, a)
		}
	}
}

// Cmd runs one FTP command expecting a single reply code (control channel only).
func (c *FTPConn) Cmd(expect int, line string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return fmt.Errorf("dead")
	}
	if err := c.simpleCmd(expect, line); err != nil {
		c.dead = true
		return err
	}
	return nil
}

func (c *FTPConn) Upload(name string, blob []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return fmt.Errorf("connection dead")
	}
	dc, err := c.pasv()
	if err != nil {
		c.dead = true
		return err
	}
	defer dc.Close()
	id, err := c.ctrl.Cmd("STOR %s", name)
	if err != nil {
		c.dead = true
		return err
	}
	c.ctrl.StartResponse(id)
	defer c.ctrl.EndResponse(id)
	if _, _, err := c.ctrl.ReadResponse(150); err != nil {
		c.dead = true
		return err
	}
	if _, err := dc.Write(blob); err != nil {
		c.dead = true
		return err
	}
	// Must close the data connection to signal EOF to the server.
	dc.Close()

	// Now wait for the server to confirm transfer complete.
	if _, _, err := c.ctrl.ReadResponse(226); err != nil {
		c.dead = true
		return err
	}
	return nil
}

func (c *FTPConn) List(pattern string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return nil, fmt.Errorf("connection dead")
	}
	dc, err := c.pasv()
	if err != nil {
		c.dead = true
		return nil, err
	}
	defer dc.Close()

	id, err := c.ctrl.Cmd("NLST %s", pattern)
	if err != nil {
		c.dead = true
		return nil, err
	}
	c.ctrl.StartResponse(id)
	defer c.ctrl.EndResponse(id)

	if _, _, err := c.ctrl.ReadResponse(150); err != nil {
		// This could be a "no files found" message, which is not an error.
	}

	raw, err := io.ReadAll(dc)
	if err != nil {
		c.dead = true
		return nil, err
	}
	dc.Close()

	if _, _, err := c.ctrl.ReadResponse(226); err != nil {
		Log.Warn("NLST post-transfer ReadResponse(226):", err)
	}

	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if l := strings.TrimSpace(line); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

func (c *FTPConn) Download(name string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return nil, fmt.Errorf("connection dead")
	}
	dc, err := c.pasv()
	if err != nil {
		c.dead = true
		return nil, err
	}
	defer dc.Close()
	id, err := c.ctrl.Cmd("RETR %s", name)
	if err != nil {
		c.dead = true
		return nil, err
	}
	c.ctrl.StartResponse(id)
	defer c.ctrl.EndResponse(id)
	if _, _, err := c.ctrl.ReadResponse(150); err != nil {
		c.dead = true
		return nil, err
	}
	data, err := io.ReadAll(dc)
	if err != nil {
		c.dead = true
		return nil, err
	}
	dc.Close()
	if _, _, err := c.ctrl.ReadResponse(226); err != nil {
		// Not fatal, we have the data.
		Log.Warn("RETR ReadResponse(226):", err)
	}
	return data, nil
}

func (c *FTPConn) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return
	}
	if err := c.simpleCmd(250, "DELE "+name); err != nil {
		Log.Warn("DELE failed:", err)
	}
}

func (c *FTPConn) Noop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return fmt.Errorf("dead")
	}
	err := c.simpleCmd(200, "NOOP")
	if err != nil {
		c.dead = true
	}
	return err
}

// CWD changes the remote working directory (used for tunnel PASV context).
func (c *FTPConn) CWD(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return fmt.Errorf("dead")
	}
	if err := c.simpleCmd(250, "CWD "+path); err != nil {
		c.dead = true
		return err
	}
	return nil
}

// PasvAddr issues PASV and returns the advertised host:port without dialing.
func (c *FTPConn) PasvAddr() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead {
		return "", fmt.Errorf("dead")
	}
	id, err := c.ctrl.Cmd("PASV")
	if err != nil {
		c.dead = true
		return "", err
	}
	c.ctrl.StartResponse(id)
	defer c.ctrl.EndResponse(id)
	_, msg, err := c.ctrl.ReadResponse(227)
	if err != nil {
		c.dead = true
		return "", err
	}
	return ParsePASV(msg)
}

// Close closes the control connection.
func (c *FTPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dead = true
	if c.raw != nil {
		return c.raw.Close()
	}
	return nil
}

func (c *FTPConn) IsDead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dead
}

// ─── Sub-pool: a fixed-size group of connections with round-robin pick ────────

type subPool struct {
	addr   string
	user   string
	pass   string
	useTLS bool
	tlsCfg *tls.Config
	mu     sync.Mutex
	conns  []*FTPConn
	rr     int
	label  string // "upload" or "poll" — for log messages
}

func newSubPool(addr, user, pass, label string, size int, useTLS bool, tlsCfg *tls.Config) (*subPool, error) {
	p := &subPool{
		addr: addr, user: user, pass: pass,
		useTLS: useTLS, tlsCfg: tlsCfg,
		conns: make([]*FTPConn, size),
		label: label,
	}
	// Dial first connection synchronously to catch bad credentials early.
	c, err := dialOne(addr, user, pass, useTLS, tlsCfg)
	if err != nil {
		return nil, err
	}
	p.conns[0] = c
	for i := 1; i < size; i++ {
		go p.reconnect(i, time.Second)
	}
	go p.watchdog()
	return p, nil
}

func (p *subPool) reconnect(idx int, backoff time.Duration) {
	for {
		time.Sleep(backoff + time.Duration(rand.Int63n(int64(backoff)+1)))
		c, err := dialOne(p.addr, p.user, p.pass, p.useTLS, p.tlsCfg)
		if err != nil {
			Log.Warn(fmt.Sprintf("[%s-pool] reconnect[%d]: %v (retry in %v)", p.label, idx, err, backoff))
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}
		p.mu.Lock()
		p.conns[idx] = c
		p.mu.Unlock()
		Log.Info(fmt.Sprintf("[%s-pool] connection[%d] ready", p.label, idx))
		return
	}
}

func (p *subPool) watchdog() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	check := time.NewTicker(5 * time.Second)
	noop := time.NewTicker(25 * time.Second)
	defer check.Stop()
	defer noop.Stop()
	for {
		select {
		case <-check.C:
			p.mu.Lock()
			for i, c := range p.conns {
				if c == nil || c.IsDead() {
					p.conns[i] = nil
					go p.reconnect(i, time.Second)
				}
			}
			p.mu.Unlock()
		case <-noop.C:
			p.mu.Lock()
			snapshot := make([]*FTPConn, len(p.conns))
			copy(snapshot, p.conns)
			p.mu.Unlock()
			for _, c := range snapshot {
				if c == nil {
					continue
				}
				go func(fc *FTPConn) {
					time.Sleep(time.Duration(rng.Int63n(int64(5 * time.Second))))
					fc.Noop() //nolint:errcheck
				}(c)
			}
		}
	}
}

func (p *subPool) pick() *FTPConn {
	for attempt := 0; attempt < 60; attempt++ {
		p.mu.Lock()
		n := len(p.conns)
		for i := 0; i < n; i++ {
			idx := (p.rr + i) % n
			c := p.conns[idx]
			if c != nil && !c.IsDead() {
				p.rr = (idx + 1) % n
				p.mu.Unlock()
				return c
			}
		}
		p.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func (p *subPool) upload(name string, blob []byte) error {
	const maxRetry = 3
	var lastErr error
	for i := 0; i < maxRetry; i++ {
		c := p.pick()
		if c == nil {
			return fmt.Errorf("no live connection in %s pool", p.label)
		}
		if err := c.Upload(name, blob); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("upload failed after %d attempts: %w", maxRetry, lastErr)
}

func (p *subPool) list(pattern string) ([]string, error) {
	c := p.pick()
	if c == nil {
		return nil, fmt.Errorf("no live connection in %s pool", p.label)
	}
	return c.List(pattern)
}

func (p *subPool) download(name string) ([]byte, error) {
	c := p.pick()
	if c == nil {
		return nil, fmt.Errorf("no live connection in %s pool", p.label)
	}
	return c.Download(name)
}

func (p *subPool) delete(name string) {
	if c := p.pick(); c != nil {
		c.Delete(name)
	}
}

// ─── SessionPool: single shared pool for v3 compatibility ─────────────────────

type SessionPool struct {
	pool *subPool
}

// NewSessionPool creates a single shared connection pool.
func NewSessionPool(addr, user, pass string, uploadConns, pollConns int, useTLS bool, tlsCfg *tls.Config) (*SessionPool, error) {
	totalConns := uploadConns + pollConns
	if totalConns == 0 {
		totalConns = 4 // Default fallback
	}
	pool, err := newSubPool(addr, user, pass, "shared", totalConns, useTLS, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("shared pool: %w", err)
	}
	return &SessionPool{pool: pool}, nil
}

func (p *SessionPool) Upload(name string, blob []byte) error {
	return p.pool.upload(name, blob)
}

func (p *SessionPool) List(pattern string) ([]string, error) {
	return p.pool.list(pattern)
}

func (p *SessionPool) Download(name string) ([]byte, error) {
	return p.pool.download(name)
}

func (p *SessionPool) Delete(name string) {
	p.pool.delete(name)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func ParsePASV(msg string) (string, error) {
	s := strings.LastIndex(msg, "(")
	e := strings.LastIndex(msg, ")")
	if s < 0 || e < 0 {
		return "", fmt.Errorf("PASV parse: %q", msg)
	}
	parts := strings.Split(msg[s+1:e], ",")
	if len(parts) != 6 {
		return "", fmt.Errorf("PASV fields: %v", parts)
	}
	host := strings.Join(parts[:4], ".")
	var p1, p2 int
	fmt.Sscanf(parts[4], "%d", &p1)
	fmt.Sscanf(parts[5], "%d", &p2)
	return fmt.Sprintf("%s:%d", host, p1*256+p2), nil
}
