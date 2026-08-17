// ftptunnel-server — dual persistent TCP channels + FTP façade
package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/common/dualbind"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/ftp/common"
)

// Config holds FTP tunnel server settings (from PT Proxy JSON config).
type Config struct {
	Listen        string // FTP listen address
	User          string
	Pass          string
	Key           string
	PasvIP        string
	UploadPorts   string
	DownloadPorts string
	TLS           bool
	Cert          string
	CertKey       string
	Debug         bool
	LogTag        string
	Target        string
	SkipUDP       bool
}

var (
	cfgFTPAddr       = "0.0.0.0:21"
	cfgUser          = "tunnel"
	cfgPass          = "secret"
	cfgKey           = "change-me-please"
	cfgPasvIP        string
	cfgUploadPorts   = "8080-8800"
	cfgDownloadPorts = "8080-8800"
	cfgTLS           bool
	cfgCert          = "cert.pem"
	cfgCertKey       = "key.pem"
	cfgDebug         bool
	cfgTarget        string
	cfgSkipUDP       bool

	lg ptlog.PTLog
)

const metricsInterval = 60 * time.Second

var (
	aesKey      []byte
	tlsCfg      *tls.Config
	uploadRange common.PortRange
	downRange   common.PortRange

	upPool   *dataPool
	downPool *dataPool
)

func dbg(format string, a ...interface{}) {
	if cfgDebug {
		lg.Debug(fmt.Sprintf(format, a...))
	}
}

// ─── Session map ──────────────────────────────────────────────────────────────

type session struct {
	token     string
	mu        sync.Mutex
	ups       map[uint16]*common.Channel
	downs     map[uint16]*common.Channel
	revConnID atomic.Uint32
	revLn     net.Listener
	revUDP    *net.UDPConn
}

var (
	sessMu   sync.RWMutex
	sessions = make(map[string]*session)
)

func getOrCreateSession(token string) *session {
	sessMu.Lock()
	defer sessMu.Unlock()
	if s, ok := sessions[token]; ok {
		return s
	}
	s := &session{
		token: token,
		ups:   make(map[uint16]*common.Channel),
		downs: make(map[uint16]*common.Channel),
	}
	sessions[token] = s
	return s
}

func getSession(token string) *session {
	sessMu.RLock()
	defer sessMu.RUnlock()
	return sessions[token]
}

func (s *session) bind(ch *common.Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch.Dir() == common.DirUpload {
		if old, ok := s.ups[ch.Index()]; ok {
			old.Close()
		}
		s.ups[ch.Index()] = ch
	} else {
		if old, ok := s.downs[ch.Index()]; ok {
			old.Close()
		}
		s.downs[ch.Index()] = ch
	}
}

func (s *session) downloadFor(connID uint32) *common.Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.downs) == 0 {
		return nil
	}
	// Affinity: ConnID % M among registered indices
	idxs := make([]uint16, 0, len(s.downs))
	for i := range s.downs {
		idxs = append(idxs, i)
	}
	// Prefer contiguous 0..n-1 if present
	n := uint32(len(s.downs))
	want := uint16(connID % n)
	if ch, ok := s.downs[want]; ok {
		return ch
	}
	return s.downs[idxs[0]]
}

func (s *session) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.ups {
		ch.Close()
	}
	for _, ch := range s.downs {
		ch.Close()
	}
	s.ups = make(map[uint16]*common.Channel)
	s.downs = make(map[uint16]*common.Channel)
}

// ─── Data port pools ──────────────────────────────────────────────────────────

type dataPool struct {
	label      string
	r          common.PortRange
	dir        byte
	mu         sync.Mutex
	shared     net.Listener
	sharedPort int
	decoyPend  chan net.Conn // when set, next Accept is handed to decoy FTP data
}

func newDataPool(label string, r common.PortRange, dir byte) *dataPool {
	return &dataPool{label: label, r: r, dir: dir}
}

func (p *dataPool) ensureShared(ctx context.Context) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.shared != nil {
		return p.sharedPort, nil
	}
	ln, port, err := common.ListenInRange(p.r)
	if err != nil {
		return 0, err
	}
	p.shared = ln
	p.sharedPort = port
	go p.acceptLoop(ctx, ln)
	lg.Info(fmt.Sprintf("[%s] shared listener 0.0.0.0:%d", p.label, port))
	return port, nil
}

func (p *dataPool) clearDecoy(ch chan net.Conn) {
	p.mu.Lock()
	if p.decoyPend == ch {
		p.decoyPend = nil
	}
	p.mu.Unlock()
}

func (p *dataPool) acceptLoop(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				lg.Error(fmt.Sprintf("[%s] accept: %v", p.label, err))
				continue
			}
		}
		p.mu.Lock()
		pend := p.decoyPend
		p.mu.Unlock()
		if pend != nil {
			select {
			case pend <- c:
				continue
			default:
			}
		}
		go handleDataConn(c)
	}
}

// advertise returns port for 227; starts accept as needed.
func (p *dataPool) advertise(ctx context.Context) (int, error) {
	if p.r.Single() {
		return p.ensureShared(ctx)
	}
	// Range: ephemeral listener per PASV, accept one (or few) into handleDataConn
	ln, port, err := common.ListenInRange(p.r)
	if err != nil {
		return 0, err
	}
	go func() {
		defer ln.Close()
		if tl, ok := ln.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(60 * time.Second))
		}
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleDataConn(c)
	}()
	return port, nil
}

// reserveDecoy advertises a reachable data port and routes the next Accept to FTP decoy.
func (p *dataPool) reserveDecoy(ctx context.Context) (port int, wait func() (net.Conn, error), cancel func(), err error) {
	if p.r.Single() {
		port, err = p.ensureShared(ctx)
		if err != nil {
			return 0, nil, nil, err
		}
		ch := make(chan net.Conn, 1)
		p.mu.Lock()
		p.decoyPend = ch
		p.mu.Unlock()

		wait = func() (net.Conn, error) {
			defer p.clearDecoy(ch)
			select {
			case c := <-ch:
				return c, nil
			case <-time.After(60 * time.Second):
				return nil, fmt.Errorf("decoy accept timeout")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		cancel = func() {
			p.clearDecoy(ch)
			select {
			case c := <-ch:
				c.Close()
			default:
			}
		}
		return port, wait, cancel, nil
	}

	ln, port, err := common.ListenInRange(p.r)
	if err != nil {
		return 0, nil, nil, err
	}
	wait = func() (net.Conn, error) {
		defer ln.Close()
		if tl, ok := ln.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(60 * time.Second))
		}
		return ln.Accept()
	}
	cancel = func() { _ = ln.Close() }
	return port, wait, cancel, nil
}

// reserveDecoyAny arms decoy accept on both upload and download pools so the
// client can dial either public override port (NAT) and still complete LIST/RETR.
func reserveDecoyAny(ctx context.Context) (port int, wait func() (net.Conn, error), cancel func(), err error) {
	if !upPool.r.Single() || !downPool.r.Single() {
		// Fall back to one pool when using port ranges.
		pool := downPool
		return pool.reserveDecoy(ctx)
	}
	upPort, err := upPool.ensureShared(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	downPort, err := downPool.ensureShared(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	ch := make(chan net.Conn, 1)
	upPool.mu.Lock()
	upPool.decoyPend = ch
	upPool.mu.Unlock()
	downPool.mu.Lock()
	downPool.decoyPend = ch
	downPool.mu.Unlock()

	wait = func() (net.Conn, error) {
		defer func() {
			upPool.clearDecoy(ch)
			downPool.clearDecoy(ch)
		}()
		select {
		case c := <-ch:
			return c, nil
		case <-time.After(60 * time.Second):
			return nil, fmt.Errorf("decoy accept timeout")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	cancel = func() {
		upPool.clearDecoy(ch)
		downPool.clearDecoy(ch)
		select {
		case c := <-ch:
			c.Close()
		default:
		}
	}
	// Advertise download port in 227 (cosmetic when client uses overrides).
	_ = upPort
	return downPort, wait, cancel, nil
}

func handleDataConn(raw net.Conn) {
	conn, err := common.MaybeTLSServer(raw, tlsCfg)
	if err != nil {
		lg.Error("data TLS:", err)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	h, err := common.ReadHello(conn, aesKey)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		lg.Error("hello:", err)
		conn.Close()
		return
	}
	if h.Dir != common.DirUpload && h.Dir != common.DirDownload {
		lg.Error(fmt.Sprintf("hello: bad dir %q", h.Dir))
		conn.Close()
		return
	}
	if h.Token == "" {
		conn.Close()
		return
	}
	ch := common.WrapChannel(conn, aesKey, h.Dir, h.Index)
	sess := getOrCreateSession(h.Token)
	sess.bind(ch)
	lg.Info(fmt.Sprintf("channel bound token=%s dir=%c idx=%d from %s", h.Token, h.Dir, h.Index, raw.RemoteAddr()))
	if h.Dir == common.DirUpload {
		go readUploadLoop(sess, ch)
	}
	// download channels: server only writes
}

func readUploadLoop(sess *session, ch *common.Channel) {
	defer func() {
		ch.Close()
		sess.mu.Lock()
		if cur, ok := sess.ups[ch.Index()]; ok && cur == ch {
			delete(sess.ups, ch.Index())
		}
		empty := len(sess.ups) == 0
		sess.mu.Unlock()
		// Only tear down flows when no upload channels remain for this session.
		if empty {
			tcpRemoveAll(sess.token)
		}
	}()
	for {
		frames, err := ch.ReadFrames()
		if err != nil {
			lg.Error(fmt.Sprintf("upload read token=%s idx=%d: %v", sess.token, ch.Index(), err))
			return
		}
		for _, f := range frames {
			processFrame(sess.token, f)
		}
	}
}

// ─── Upstream TCP / UDP (same as before) ──────────────────────────────────────

func connKey(token string, connID uint32) string {
	return fmt.Sprintf("%s:%d", token, connID)
}

type tcpUpstream struct {
	key     string
	token   string
	connID  uint32
	conn    net.Conn
	sendSeq atomic.Uint32
}

var (
	tcpUpMu sync.RWMutex
	tcpUps  = make(map[string]*tcpUpstream)
)

func tcpDial(token string, connID uint32, target string) (*tcpUpstream, error) {
	key := connKey(token, connID)
	tcpUpMu.Lock()
	defer tcpUpMu.Unlock()
	if u, ok := tcpUps[key]; ok {
		return u, nil
	}
	if ext := strings.TrimSpace(cfgTarget); ext != "" {
		target = ext
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}
	u := &tcpUpstream{key: key, token: token, connID: connID, conn: conn}
	tcpUps[key] = u
	lg.Info(fmt.Sprintf("[tcp %s] → %s", key, target))
	go pumpTCP(u)
	return u, nil
}

func tcpRemove(key string) {
	tcpUpMu.Lock()
	if u, ok := tcpUps[key]; ok {
		u.conn.Close()
		delete(tcpUps, key)
	}
	tcpUpMu.Unlock()
}

func tcpRemoveAll(token string) {
	prefix := token + ":"
	tcpUpMu.Lock()
	for key, u := range tcpUps {
		if strings.HasPrefix(key, prefix) {
			u.conn.Close()
			delete(tcpUps, key)
		}
	}
	tcpUpMu.Unlock()
	udpRemoveAll(token)
}

func pumpTCP(u *tcpUpstream) {
	defer tcpRemove(u.key)
	buf := make([]byte, common.MaxFrameData)
	for {
		n, err := u.conn.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			common.GlobalMetrics.BytesDown.Add(int64(n))
			seq := u.sendSeq.Add(1)
			writeDown(u.token, []*common.Frame{{ConnID: u.connID, Type: common.TypeData, Seq: seq, Data: data}})
		}
		if err != nil {
			seq := u.sendSeq.Add(1)
			writeDown(u.token, []*common.Frame{{ConnID: u.connID, Type: common.TypeClose, Seq: seq}})
			return
		}
	}
}

type udpUpstream struct {
	key      string
	token    string
	connID   uint32
	conn     *net.UDPConn
	target   *net.UDPAddr // when set (tagged service), always dial this; ignore frame addr
	lastSeen atomic.Int64
}

var (
	udpUpMu sync.RWMutex
	udpUps  = make(map[string]*udpUpstream)
)

func udpGetOrCreate(token string, connID uint32) (*udpUpstream, error) {
	key := connKey(token, connID)
	udpUpMu.Lock()
	defer udpUpMu.Unlock()
	if u, ok := udpUps[key]; ok {
		return u, nil
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	u := &udpUpstream{key: key, token: token, connID: connID, conn: conn}
	if ext := strings.TrimSpace(cfgTarget); ext != "" {
		dst, err := net.ResolveUDPAddr("udp", ext)
		if err != nil {
			conn.Close()
			return nil, err
		}
		u.target = dst
	}
	u.lastSeen.Store(time.Now().UnixNano())
	udpUps[key] = u
	go pumpUDP(u)
	return u, nil
}

func udpRemove(key string) {
	udpUpMu.Lock()
	if u, ok := udpUps[key]; ok {
		u.conn.Close()
		delete(udpUps, key)
	}
	udpUpMu.Unlock()
}

func udpRemoveAll(token string) {
	prefix := token + ":"
	udpUpMu.Lock()
	for key, u := range udpUps {
		if strings.HasPrefix(key, prefix) {
			u.conn.Close()
			delete(udpUps, key)
		}
	}
	udpUpMu.Unlock()
}

func pumpUDP(u *udpUpstream) {
	defer udpRemove(u.key)
	buf := make([]byte, 65536)
	for {
		_ = u.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, raddr, err := u.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		u.lastSeen.Store(time.Now().UnixNano())
		data := common.EncodeUDPData(raddr.String(), buf[:n])
		common.GlobalMetrics.BytesDown.Add(int64(n))
		writeDown(u.token, []*common.Frame{{ConnID: u.connID, Type: common.TypeUDPData, Data: data}})
	}
}

func processFrame(token string, f *common.Frame) {
	dbg("frame conn=%d type=0x%02x seq=%d len=%d token=%s", f.ConnID, f.Type, f.Seq, len(f.Data), token)
	common.GlobalMetrics.FramesRecv.Add(1)
	key := connKey(token, f.ConnID)

	switch f.Type {
	case common.TypeReverseBind:
		listen := string(f.Data)
		go ftpRunReverse(token, listen)
	case common.TypeOpen:
		target := string(f.Data)
		if target == "udp://" {
			if cfgSkipUDP {
				lg.Error(fmt.Sprintf("[udp %s] not supported for http target", key))
				writeDown(token, []*common.Frame{{ConnID: f.ConnID, Type: common.TypeClose}})
				return
			}
			if _, err := udpGetOrCreate(token, f.ConnID); err != nil {
				lg.Error(fmt.Sprintf("[udp %s] create: %v", key, err))
			}
			return
		}
		if _, err := tcpDial(token, f.ConnID, target); err != nil {
			lg.Error(fmt.Sprintf("[tcp %s] dial %s: %v", key, target, err))
			writeDown(token, []*common.Frame{{ConnID: f.ConnID, Type: common.TypeClose}})
		}
	case common.TypeData:
		tcpUpMu.RLock()
		u, ok := tcpUps[key]
		tcpUpMu.RUnlock()
		if !ok {
			return
		}
		common.GlobalMetrics.BytesUp.Add(int64(len(f.Data)))
		if _, err := u.conn.Write(f.Data); err != nil {
			tcpRemove(key)
		}
	case common.TypeUDPData:
		addr, payload, err := common.DecodeUDPData(f.Data)
		if err != nil {
			return
		}
		u, err := udpGetOrCreate(token, f.ConnID)
		if err != nil {
			return
		}
		u.lastSeen.Store(time.Now().UnixNano())
		raddr := u.target
		if raddr == nil {
			raddr, err = net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return
			}
		}
		common.GlobalMetrics.BytesUp.Add(int64(len(payload)))
		_, _ = u.conn.WriteTo(payload, raddr)
	case common.TypeClose:
		tcpRemove(key)
		udpRemove(key)
	case common.TypeHB:
		writeDown(token, []*common.Frame{{ConnID: 0, Type: common.TypeHBAck, Seq: f.Seq}})
	case common.TypeDNSReq:
		go func() {
			host := string(f.Data)
			addrs, err := net.LookupHost(host)
			var resp []byte
			if err != nil || len(addrs) == 0 {
				resp = []byte{}
			} else {
				resp = []byte(strings.Join(addrs, ","))
			}
			writeDown(token, []*common.Frame{{ConnID: f.ConnID, Type: common.TypeDNSResp, Seq: f.Seq, Data: resp}})
		}()
	}
}

func writeDown(token string, frames []*common.Frame) {
	sess := getSession(token)
	if sess == nil {
		return
	}
	var connID uint32
	if len(frames) > 0 {
		connID = frames[0].ConnID
	}
	ch := sess.downloadFor(connID)
	if ch == nil {
		dbg("no download channel for token=%s", token)
		return
	}
	if err := ch.WriteFrames(frames); err != nil {
		lg.Error("writeDown:", err)
		return
	}
	common.GlobalMetrics.FramesSent.Add(int64(len(frames)))
}

// ─── Decoy files ───────────────────────────────────────────────────────────────

var decoyFiles = map[string][]byte{
	"index.html":    []byte("<!DOCTYPE html><html><body><h1>Welcome</h1></body></html>\n"),
	"style.css":     []byte("body{font-family:sans-serif;margin:2rem}\n"),
	"app.js":        []byte("console.log('ok');\n"),
	"favicon.ico":   {0, 0, 1, 0},
	"robots.txt":    []byte("User-agent: *\nDisallow:\n"),
	"manifest.json": []byte(`{"name":"site","short_name":"site"}` + "\n"),
}

// ─── Embedded FTP server ──────────────────────────────────────────────────────

var banners = []string{
	"(vsFTPd 3.0.5)",
	"ProFTPD 1.3.8 Server (FTP Server) [%s]",
	"FileZilla Server 1.8.2",
	"Microsoft FTP Service",
}

type ftpSess struct {
	conn        net.Conn
	rw          *bufio.ReadWriter
	authed      bool
	userOK      bool
	pasvLn      net.Listener
	decoyWait   func() (net.Conn, error)
	decoyCancel func()
	tlsUpgrade  bool
	dataProtP   bool
	cwd         string
	rng         *rand.Rand
	ctx         context.Context
}

func newFTPSess(ctx context.Context, conn net.Conn) *ftpSess {
	return &ftpSess{
		ctx:  ctx,
		conn: conn,
		rw:   bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		cwd:  "/",
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *ftpSess) sendf(code int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(s.rw, "%d %s\r\n", code, msg)
	s.rw.Flush()
}

func (s *ftpSess) sendMulti(code int, lines []string) {
	for i, l := range lines {
		if i < len(lines)-1 {
			fmt.Fprintf(s.rw, "%d-%s\r\n", code, l)
		} else {
			fmt.Fprintf(s.rw, "%d %s\r\n", code, l)
		}
	}
	s.rw.Flush()
}

func (s *ftpSess) pasvIP() string {
	ip := cfgPasvIP
	if ip == "" {
		host, _, _ := net.SplitHostPort(s.conn.LocalAddr().String())
		ip = host
	}
	if ip == "" || ip == "::" || ip == "0.0.0.0" {
		ip = "127.0.0.1"
	}
	// PASV is IPv4-only; unwrap IPv4-mapped
	if strings.HasPrefix(ip, "::ffff:") {
		ip = strings.TrimPrefix(ip, "::ffff:")
	}
	return ip
}

func (s *ftpSess) send227(port int) {
	ip := s.pasvIP()
	ipStr := strings.ReplaceAll(ip, ".", ",")
	s.sendf(227, "Entering Passive Mode (%s,%d,%d).", ipStr, port/256, port%256)
}

func (s *ftpSess) clearPasv() {
	if s.decoyCancel != nil {
		s.decoyCancel()
		s.decoyCancel = nil
		s.decoyWait = nil
	}
	if s.pasvLn != nil {
		s.pasvLn.Close()
		s.pasvLn = nil
	}
}

func (s *ftpSess) openData() (net.Conn, error) {
	var dc net.Conn
	var err error
	if s.decoyWait != nil {
		wait := s.decoyWait
		s.decoyWait = nil
		s.decoyCancel = nil
		dc, err = wait()
	} else if s.pasvLn != nil {
		dc, err = s.pasvLn.Accept()
		s.pasvLn.Close()
		s.pasvLn = nil
	} else {
		return nil, fmt.Errorf("no PASV pending")
	}
	if err != nil {
		return nil, err
	}
	if s.dataProtP && tlsCfg != nil {
		tlsDC := tls.Server(dc, tlsCfg)
		if err := tlsDC.Handshake(); err != nil {
			dc.Close()
			return nil, fmt.Errorf("data TLS: %w", err)
		}
		return tlsDC, nil
	}
	return dc, nil
}

func (s *ftpSess) handlePASV() {
	s.clearPasv()
	cwd := strings.Trim(s.cwd, "/")
	switch cwd {
	case common.PathUpload:
		port, err := upPool.advertise(s.ctx)
		if err != nil {
			s.sendf(425, "Cannot open data connection.")
			lg.Error("upload PASV:", err)
			return
		}
		s.send227(port)
		return
	case common.PathDownload:
		port, err := downPool.advertise(s.ctx)
		if err != nil {
			s.sendf(425, "Cannot open data connection.")
			lg.Error("download PASV:", err)
			return
		}
		s.send227(port)
		return
	}

	// Decoy / listing PASV — accept on upload+download shared ports (NAT overrides).
	port, wait, cancel, err := reserveDecoyAny(s.ctx)
	if err != nil {
		s.sendf(425, "Cannot open data connection.")
		lg.Error("decoy PASV:", err)
		return
	}
	s.decoyWait = wait
	s.decoyCancel = cancel
	s.send227(port)
}

func (s *ftpSess) serve() {
	defer func() {
		s.conn.Close()
		s.clearPasv()
	}()

	b := banners[s.rng.Intn(len(banners))]
	if strings.Contains(b, "%s") {
		h, _, _ := net.SplitHostPort(s.conn.LocalAddr().String())
		b = fmt.Sprintf(b, h)
	}
	s.sendf(220, b)

	for {
		line, err := s.rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch cmd {
		case "AUTH":
			if strings.ToUpper(arg) == "TLS" && tlsCfg != nil {
				s.sendf(234, "AUTH TLS OK.")
				tlsConn := tls.Server(s.conn, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					lg.Error("ctrl TLS:", err)
					return
				}
				s.conn = tlsConn
				s.rw = bufio.NewReadWriter(bufio.NewReader(tlsConn), bufio.NewWriter(tlsConn))
				s.tlsUpgrade = true
			} else {
				s.sendf(502, "Unsupported AUTH type.")
			}
		case "PBSZ":
			s.sendf(200, "PBSZ=0")
		case "PROT":
			if strings.ToUpper(arg) == "P" {
				s.dataProtP = true
				s.sendf(200, "Protection level set to P.")
			} else {
				s.dataProtP = false
				s.sendf(200, "Protection level set to C.")
			}
		case "USER":
			if arg == cfgUser {
				s.userOK = true
				s.sendf(331, "Please specify the password.")
			} else {
				s.sendf(530, "Login incorrect.")
			}
		case "PASS":
			if s.userOK && arg == cfgPass {
				s.authed = true
				s.sendf(230, "Login successful.")
			} else {
				s.sendf(530, "Login incorrect.")
			}
		case "SYST":
			s.sendf(215, "UNIX Type: L8")
		case "FEAT":
			s.sendMulti(211, []string{"Features:", " EPRT", " EPSV", " MDTM",
				" PASV", " REST STREAM", " SIZE", " TVFS", " UTF8", "End"})
		case "OPTS":
			s.sendf(200, "Always in UTF8 mode.")
		case "PWD":
			s.sendf(257, "\"/%s\" is the current directory.", strings.Trim(s.cwd, "/"))
		case "CWD":
			path := strings.Trim(arg, "/")
			if path == "" {
				s.cwd = "/"
			} else {
				s.cwd = "/" + path
			}
			s.sendf(250, "Directory successfully changed.")
		case "CDUP":
			s.cwd = "/"
			s.sendf(250, "Directory successfully changed.")
		case "MKD":
			s.sendf(257, "\"/%s\" created.", arg)
		case "SIZE":
			if data, ok := decoyFiles[arg]; ok {
				s.sendf(213, "%d", len(data))
			} else {
				s.sendf(213, "%d", s.rng.Intn(500000)+1000)
			}
		case "MDTM":
			s.sendf(213, time.Now().UTC().Format("20060102150405"))
		case "NOOP":
			s.sendf(200, "NOOP ok.")
		case "TYPE":
			s.sendf(200, "Switching to Binary mode.")
		case "REST":
			s.sendf(350, "Restart position accepted (%s).", arg)
		case "PASV":
			if !s.authed {
				s.sendf(530, "Please login with USER and PASS.")
				continue
			}
			s.handlePASV()
		case "STOR":
			s.sendf(250, "Transfer complete.")
		case "NLST", "LIST":
			if !s.authed {
				s.sendf(530, "Please login with USER and PASS.")
				continue
			}
			dc, err := s.openData()
			if err != nil {
				s.sendf(425, "Use PASV first.")
				continue
			}
			s.sendf(150, "Here comes the directory listing.")
			for name := range decoyFiles {
				if cmd == "LIST" {
					fmt.Fprintf(dc, "-rw-r--r-- 1 ftp ftp %d Jan 1 00:00 %s\r\n", len(decoyFiles[name]), name)
				} else {
					fmt.Fprintf(dc, "%s\r\n", name)
				}
			}
			dc.Close()
			s.sendf(226, "Directory send OK.")
		case "RETR":
			if !s.authed {
				s.sendf(530, "Please login with USER and PASS.")
				continue
			}
			name := strings.TrimPrefix(arg, "/")
			data, ok := decoyFiles[name]
			if !ok {
				s.sendf(550, "Failed to open file.")
				continue
			}
			dc, err := s.openData()
			if err != nil {
				s.sendf(425, "Use PASV first.")
				continue
			}
			s.sendf(150, "Opening BINARY mode data connection for %s (%d bytes).", arg, len(data))
			dc.Write(data)
			dc.Close()
			s.sendf(226, "Transfer complete.")
		case "DELE":
			s.sendf(250, "Delete operation successful.")
		case "QUIT":
			s.sendf(221, "Goodbye.")
			return
		default:
			s.sendf(502, "Unknown command.")
		}
	}
}

func applyConfig(c Config) {
	lg = ptlog.PTLog{LogTag: c.LogTag}
	common.SetLog(lg)
	if c.Listen != "" {
		cfgFTPAddr = c.Listen
	}
	if c.User != "" {
		cfgUser = c.User
	}
	if c.Pass != "" {
		cfgPass = c.Pass
	}
	if c.Key != "" {
		cfgKey = c.Key
	}
	cfgPasvIP = c.PasvIP
	if c.UploadPorts != "" {
		cfgUploadPorts = c.UploadPorts
	}
	if c.DownloadPorts != "" {
		cfgDownloadPorts = c.DownloadPorts
	}
	cfgTLS = c.TLS
	if c.Cert != "" {
		cfgCert = c.Cert
	}
	if c.CertKey != "" {
		cfgCertKey = c.CertKey
	}
	cfgDebug = c.Debug
	cfgTarget = strings.TrimSpace(c.Target)
	cfgSkipUDP = c.SkipUDP
}

func ftpRunReverse(token, listen string) {
	sess := getOrCreateSession(token)
	sess.mu.Lock()
	if sess.revLn != nil {
		_ = sess.revLn.Close()
		sess.revLn = nil
	}
	if sess.revUDP != nil {
		_ = sess.revUDP.Close()
		sess.revUDP = nil
	}
	sess.mu.Unlock()

	ln, udp, bound, err := dualbind.Listen(listen)
	if err != nil {
		lg.Error("reverse bind:", err)
		return
	}
	sess.mu.Lock()
	sess.revLn = ln
	sess.revUDP = udp
	sess.mu.Unlock()
	lg.Info("ftp reverse listen", bound)
	if udp != nil {
		go func() {
			buf := make([]byte, 65535)
			id := uint32(0xfffffffe)
			for {
				n, from, err := udp.ReadFromUDP(buf)
				if err != nil {
					return
				}
				data := common.EncodeUDPData(from.String(), buf[:n])
				writeDown(token, []*common.Frame{{ConnID: id, Type: common.TypeUDPData, Data: data}})
			}
		}()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		id := sess.revConnID.Add(1)
		if id == 0 {
			id = sess.revConnID.Add(1)
		}
		go func(c net.Conn, id uint32) {
			defer c.Close()
			writeDown(token, []*common.Frame{{ConnID: id, Type: common.TypeReverseOpen}})
			if _, err := tcpAttach(token, id, c); err != nil {
				lg.Error("reverse tcp:", err)
			}
		}(c, id)
	}
}

func tcpAttach(token string, connID uint32, conn net.Conn) (*tcpUpstream, error) {
	key := connKey(token, connID)
	tcpUpMu.Lock()
	defer tcpUpMu.Unlock()
	u := &tcpUpstream{key: key, token: token, connID: connID, conn: conn}
	tcpUps[key] = u
	go pumpTCP(u)
	return u, nil
}

// Run starts the FTP tunnel server and blocks until ctx is cancelled.
func Run(ctx context.Context, c Config) error {
	applyConfig(c)
	aesKey = common.DeriveKey(cfgKey)

	var err error
	uploadRange, err = common.ParsePortRange(cfgUploadPorts)
	if err != nil {
		return fmt.Errorf("upload-ports: %w", err)
	}
	downRange, err = common.ParsePortRange(cfgDownloadPorts)
	if err != nil {
		return fmt.Errorf("download-ports: %w", err)
	}

	text := "FTP Tunnel Server:"
	text = fmt.Sprintf(text+"\n> Key fingerprint: %x", aesKey[:4])
	text = fmt.Sprintf(text+"\n> Upload ports   : %s", uploadRange)
	text = fmt.Sprintf(text+"\n> Download ports : %s", downRange)
	if cfgPasvIP != "" {
		text = fmt.Sprintf(text+"\n> PASV IP        : %s", cfgPasvIP)
	}
	lg.Info(text, "\n")

	if cfgTLS {
		cert, err := tls.LoadX509KeyPair(cfgCert, cfgCertKey)
		if err != nil {
			return fmt.Errorf("TLS certs: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		lg.Info("TLS enabled (FTPS + data channels)")
	}

	common.StartMetricsLogger(metricsInterval)

	upPool = newDataPool("upload", uploadRange, common.DirUpload)
	downPool = newDataPool("download", downRange, common.DirDownload)
	if uploadRange.Single() {
		if _, err := upPool.ensureShared(ctx); err != nil {
			return fmt.Errorf("upload listen: %w", err)
		}
	}
	if downRange.Single() {
		if _, err := downPool.ensureShared(ctx); err != nil {
			return fmt.Errorf("download listen: %w", err)
		}
	}

	ln, err := net.Listen("tcp", cfgFTPAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	lg.Info("FTP listening on", cfgFTPAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				lg.Info("Server shutting down.")
				return ctx.Err()
			default:
				lg.Error("accept:", err)
				continue
			}
		}
		go newFTPSess(ctx, conn).serve()
	}
}
