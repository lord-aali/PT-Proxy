// ftptunnel-client — dual persistent TCP channels + FTP PASV bootstrap
package client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/common/dualbind"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/ftp/common"
)

// Config holds FTP tunnel client settings (from PT Proxy JSON config).
type Config struct {
	Listen           string // local SOCKS5 listen address
	FTP              string // FTP/FTPS server host:port
	User             string
	Pass             string
	Key              string // AES-256 passphrase
	TLS              bool
	UploadChannels   int
	DownloadChannels int
	OverrideUpAddr   string
	OverrideDownAddr string
	Decoy            bool
	SocksUser        string
	SocksPass        string
	Debug            bool
	LogTag           string
	ReverseAddr      string
}

var (
	cfgListen    = "127.0.0.1:1080"
	cfgFTP       = "127.0.0.1:21"
	cfgUser      = "tunnel"
	cfgPass      = "secret"
	cfgKey       = "change-me-please"
	cfgTLS       bool
	cfgUpChans   = 1
	cfgDownChans = 1
	cfgUpAddr    string
	cfgDownAddr  string
	cfgDecoy     bool
	cfgSocksUser string
	cfgSocksPass string
	cfgDebug     bool
	cfgReverse   string

	lg ptlog.PTLog
)

const (
	batchDelay     = 2 * time.Millisecond
	hbInterval     = 10 * time.Second
	hbTimeout      = 30 * time.Second
	udpTimeout     = 3 * time.Minute
	writeTimeout   = 10 * time.Second
	metricsEvery   = 30 * time.Second
	decoyInterval  = 2 * time.Second
	decoyJitterMax = 1 * time.Second
	retryMin       = time.Second
	retryMax       = 30 * time.Second
)

func dbg(format string, a ...interface{}) {
	if cfgDebug {
		lg.Debug(fmt.Sprintf(format, a...))
	}
}

var (
	aesKey       []byte
	sessionToken string
	ftpCtrl      *common.FTPConn
	ftpMu        sync.Mutex
	useTLS       bool
	ftpHost      string

	connIDGen uint32
	lastHBAck atomic.Int64

	tcpMu  sync.RWMutex
	tcpMap = make(map[uint32]*tcpVConn)
	udpMu  sync.RWMutex
	udpMap = make(map[uint32]*udpSession)

	uploads   []*common.Channel
	downloads []*common.Channel
	chanMu    sync.RWMutex

	gb *batcher
)

type tcpVConn struct {
	id      uint32
	reorder *common.ReorderBuffer
	raw     chan *common.Frame
}

func newTCPVConn(id uint32) *tcpVConn {
	ch := make(chan *common.Frame, 1024)
	vc := &tcpVConn{id: id, raw: ch}
	vc.reorder = common.NewReorderBuffer(ch)
	return vc
}

func registerTCP(vc *tcpVConn) {
	tcpMu.Lock()
	tcpMap[vc.id] = vc
	tcpMu.Unlock()
	common.GlobalMetrics.ActiveTCP.Add(1)
}

func unregisterTCP(id uint32) {
	tcpMu.Lock()
	delete(tcpMap, id)
	tcpMu.Unlock()
	common.GlobalMetrics.ActiveTCP.Add(-1)
}

type udpSession struct {
	id       uint32
	local    *net.UDPConn
	lastSeen atomic.Int64
}

func registerUDP(s *udpSession) {
	udpMu.Lock()
	udpMap[s.id] = s
	udpMu.Unlock()
	common.GlobalMetrics.ActiveUDP.Add(1)
}

func unregisterUDP(id uint32) {
	udpMu.Lock()
	if s, ok := udpMap[id]; ok {
		s.local.Close()
		delete(udpMap, id)
	}
	udpMu.Unlock()
	common.GlobalMetrics.ActiveUDP.Add(-1)
}

// ─── Channel management ───────────────────────────────────────────────────────

func uploadChannel(connID uint32) *common.Channel {
	chanMu.RLock()
	defer chanMu.RUnlock()
	if len(uploads) == 0 {
		return nil
	}
	return uploads[connID%uint32(len(uploads))]
}

func dialTunnelChannel(ctx context.Context, dir byte, index uint16) (*common.Channel, error) {
	ftpMu.Lock()
	defer ftpMu.Unlock()
	if ftpCtrl == nil || ftpCtrl.IsDead() {
		c, err := redialFTP()
		if err != nil {
			return nil, err
		}
		ftpCtrl = c
	}

	path := common.PathUpload
	if dir == common.DirDownload {
		path = common.PathDownload
	}
	if err := ftpCtrl.CWD(path); err != nil {
		ftpCtrl.Close()
		ftpCtrl = nil
		return nil, fmt.Errorf("CWD %s: %w", path, err)
	}
	addr, err := ftpCtrl.PasvAddr()
	if err != nil {
		ftpCtrl.Close()
		ftpCtrl = nil
		return nil, fmt.Errorf("PASV: %w", err)
	}
	if dir == common.DirUpload && cfgUpAddr != "" {
		addr = cfgUpAddr
	} else if dir == common.DirDownload && cfgDownAddr != "" {
		addr = cfgDownAddr
	}

	raw, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	conn, err := common.MaybeTLSClient(raw, useTLS, ftpHost)
	if err != nil {
		return nil, err
	}
	h := common.Hello{Token: sessionToken, Dir: dir, Index: index}
	if err := common.WriteHello(conn, h, aesKey); err != nil {
		conn.Close()
		return nil, fmt.Errorf("hello: %w", err)
	}
	return common.WrapChannel(conn, aesKey, dir, index), nil
}

func redialFTP() (*common.FTPConn, error) {
	var tlsCfg *tls.Config
	if useTLS {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return common.DialFTP(cfgFTP, cfgUser, cfgPass, useTLS, tlsCfg)
}

func closeChannels(chs []*common.Channel) {
	for _, ch := range chs {
		if ch != nil {
			ch.Close()
		}
	}
}

func openAllChannels(ctx context.Context) error {
	nUp := cfgUpChans
	nDown := cfgDownChans
	if nUp < 1 {
		nUp = 1
	}
	if nDown < 1 {
		nDown = 1
	}
	ups := make([]*common.Channel, nUp)
	downs := make([]*common.Channel, nDown)
	for i := 0; i < nUp; i++ {
		ch, err := dialTunnelChannel(ctx, common.DirUpload, uint16(i))
		if err != nil {
			closeChannels(ups)
			return fmt.Errorf("upload[%d]: %w", i, err)
		}
		ups[i] = ch
		lg.Info("upload channel", i, "ready")
	}
	for i := 0; i < nDown; i++ {
		ch, err := dialTunnelChannel(ctx, common.DirDownload, uint16(i))
		if err != nil {
			closeChannels(ups)
			closeChannels(downs)
			return fmt.Errorf("download[%d]: %w", i, err)
		}
		downs[i] = ch
		lg.Info("download channel", i, "ready")
		go downloadReadLoop(ctx, ch, uint16(i))
	}
	chanMu.Lock()
	uploads = ups
	downloads = downs
	chanMu.Unlock()
	return nil
}

func sleepBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// connectWithRetry keeps dialing FTP + data channels until success or ctx cancel.
func connectWithRetry(ctx context.Context) error {
	backoff := retryMin
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ftpMu.Lock()
		if ftpCtrl != nil {
			ftpCtrl.Close()
			ftpCtrl = nil
		}
		c, err := redialFTP()
		if err != nil {
			ftpMu.Unlock()
			lg.Warn(fmt.Sprintf("FTP login: %v — retrying in %v", err, backoff))
			if !sleepBackoff(ctx, backoff) {
				return ctx.Err()
			}
			if backoff < retryMax {
				backoff *= 2
				if backoff > retryMax {
					backoff = retryMax
				}
			}
			continue
		}
		ftpCtrl = c
		ftpMu.Unlock()
		lg.Info("FTP control ready")

		if err := openAllChannels(ctx); err != nil {
			lg.Warn(fmt.Sprintf("channels: %v — retrying in %v", err, backoff))
			ftpMu.Lock()
			if ftpCtrl != nil {
				ftpCtrl.Close()
				ftpCtrl = nil
			}
			ftpMu.Unlock()
			if !sleepBackoff(ctx, backoff) {
				return ctx.Err()
			}
			if backoff < retryMax {
				backoff *= 2
				if backoff > retryMax {
					backoff = retryMax
				}
			}
			continue
		}
		return nil
	}
}

func downloadReadLoop(ctx context.Context, ch *common.Channel, index uint16) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		frames, err := ch.ReadFrames()
		if err != nil {
			lg.Warn(fmt.Sprintf("download[%d] read: %v — reconnecting", index, err))
			common.GlobalMetrics.Reconnects.Add(1)
			ch.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				nch, err := dialTunnelChannel(ctx, common.DirDownload, index)
				if err != nil {
					lg.Error(fmt.Sprintf("download[%d] reconnect: %v", index, err))
					continue
				}
				chanMu.Lock()
				if int(index) < len(downloads) {
					downloads[index] = nch
				}
				chanMu.Unlock()
				ch = nch
				lg.Info("download channel", index, "reconnected")
				break
			}
			continue
		}
		for _, f := range frames {
			dispatch(f)
		}
	}
}

func reconnectUpload(ctx context.Context, index uint16) {
	common.GlobalMetrics.Reconnects.Add(1)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		ch, err := dialTunnelChannel(ctx, common.DirUpload, index)
		if err != nil {
			lg.Error(fmt.Sprintf("upload[%d] reconnect: %v", index, err))
			time.Sleep(time.Second)
			continue
		}
		chanMu.Lock()
		if int(index) < len(uploads) {
			if uploads[index] != nil {
				uploads[index].Close()
			}
			uploads[index] = ch
		}
		chanMu.Unlock()
		lg.Info("upload channel", index, "reconnected")
		return
	}
}

func sendFrames(frames []*common.Frame) {
	if len(frames) == 0 {
		return
	}
	var connID uint32
	for _, f := range frames {
		if f.ConnID != 0 {
			connID = f.ConnID
			break
		}
	}
	ch := uploadChannel(connID)
	if ch == nil {
		lg.Error("send: no upload channel")
		return
	}
	if err := ch.WriteFrames(frames); err != nil {
		lg.Error("upload write:", err)
		go reconnectUpload(context.Background(), ch.Index())
		return
	}
	common.GlobalMetrics.FramesSent.Add(int64(len(frames)))
}

func sendNow(f *common.Frame) { go sendFrames([]*common.Frame{f}) }

type batcher struct {
	mu    sync.Mutex
	q     []*common.Frame
	delay time.Duration
	sig   chan struct{}
}

func newBatcher(d time.Duration) *batcher {
	b := &batcher{delay: d, sig: make(chan struct{}, 1)}
	go b.loop()
	return b
}

func (b *batcher) loop() {
	var timer <-chan time.Time
	for {
		select {
		case <-b.sig:
			if timer == nil {
				t := time.NewTimer(b.delay)
				timer = t.C
			}
		case <-timer:
			timer = nil
			b.flush()
		}
	}
}

func (b *batcher) add(f *common.Frame) {
	b.mu.Lock()
	b.q = append(b.q, f)
	b.mu.Unlock()
	select {
	case b.sig <- struct{}{}:
	default:
	}
}

func (b *batcher) flush() {
	b.mu.Lock()
	if len(b.q) == 0 {
		b.mu.Unlock()
		return
	}
	frames := b.q
	b.q = nil
	b.mu.Unlock()
	go sendFrames(frames)
}

func sendBatched(f *common.Frame) { gb.add(f) }

func dispatch(f *common.Frame) {
	common.GlobalMetrics.FramesRecv.Add(1)
	dbg("↓ conn=%d type=0x%02x seq=%d len=%d", f.ConnID, f.Type, f.Seq, len(f.Data))
	switch f.Type {
	case common.TypeData, common.TypeClose:
		tcpMu.RLock()
		vc, ok := tcpMap[f.ConnID]
		tcpMu.RUnlock()
		if ok {
			vc.reorder.Push(f)
		}
	case common.TypeUDPData:
		udpMu.RLock()
		sess, ok := udpMap[f.ConnID]
		udpMu.RUnlock()
		if !ok {
			return
		}
		addr, payload, err := common.DecodeUDPData(f.Data)
		if err != nil {
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return
		}
		common.GlobalMetrics.BytesDown.Add(int64(len(payload)))
		_, _ = sess.local.Write(append(buildSocksUDPHeader(raddr), payload...))
	case common.TypeDNSResp:
		tcpMu.RLock()
		vc, ok := tcpMap[f.ConnID]
		tcpMu.RUnlock()
		if ok {
			vc.reorder.Push(f)
		}
	case common.TypeHBAck:
		lastHBAck.Store(time.Now().UnixNano())
	case common.TypeReverseOpen:
		go handleReverseOpen(f.ConnID)
	}
}

func heartbeatLoop(ctx context.Context) {
	tick := time.NewTicker(hbInterval)
	defer tick.Stop()
	lastHBAck.Store(time.Now().UnixNano())
	var seq uint32
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			seq++
			sendNow(&common.Frame{ConnID: 0, Type: common.TypeHB, Seq: seq})
			if s := time.Since(time.Unix(0, lastHBAck.Load())); s > hbTimeout {
				lg.Warn("[hb] no ack for", s.Round(time.Second))
			}
		}
	}
}

func udpReaper(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := time.Now().UnixNano()
			udpMu.RLock()
			var exp []uint32
			for id, s := range udpMap {
				if time.Duration(now-s.lastSeen.Load()) > udpTimeout {
					exp = append(exp, id)
				}
			}
			udpMu.RUnlock()
			for _, id := range exp {
				lg.Debug("[udp] expired", id)
				sendNow(&common.Frame{ConnID: id, Type: common.TypeClose})
				unregisterUDP(id)
			}
		}
	}
}

func controlKeepalive(ctx context.Context) {
	tick := time.NewTicker(25 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			ftpMu.Lock()
			if ftpCtrl != nil {
				if err := ftpCtrl.Noop(); err != nil {
					ftpCtrl.Close()
					ftpCtrl = nil
				}
			}
			ftpMu.Unlock()
		}
	}
}

func decoyLoop(ctx context.Context) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var tlsCfg *tls.Config
	if useTLS {
		tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(decoyInterval + time.Duration(rng.Int63n(int64(decoyJitterMax)+1))):
		}
		// Control always uses the main FTP address (-ftp).
		c, err := common.DialFTP(cfgFTP, cfgUser, cfgPass, useTLS, tlsCfg)
		if err != nil {
			dbg("decoy dial: %v", err)
			continue
		}
		// Data dials use full override-up/down addresses (ignore PASV port — NAT remap).
		c.SetPasvAddrOverrides(cfgUpAddr, cfgDownAddr)
		dbg("decoy pasv overrides: up=%q down=%q", cfgUpAddr, cfgDownAddr)

		// Regular FTP control chatter on the main FTP port.
		_ = c.Cmd(215, "SYST")
		_ = c.Cmd(211, "FEAT")
		_ = c.Cmd(200, "TYPE I")
		_ = c.Cmd(257, "PWD")
		_ = c.CWD("/")
		_ = c.Cmd(200, "NOOP")

		names, err := c.List("*")
		if err != nil {
			dbg("decoy list: %v", err)
			c.Close()
			continue
		}
		if len(names) > 0 {
			name := names[rng.Intn(len(names))]
			_ = c.Cmd(213, "SIZE "+name)
			if _, err := c.Download(name); err != nil {
				dbg("decoy retr: %v", err)
			}
		}
		_ = c.Cmd(221, "QUIT")
		c.Close()
	}
}

// ─── SOCKS5 ───────────────────────────────────────────────────────────────────

func handleReverseOpen(connID uint32) {
	if cfgReverse == "" {
		return
	}
	c, err := net.Dial("tcp", cfgReverse)
	if err != nil {
		lg.Error("reverse dial:", err)
		return
	}
	pipeExisting(c, connID, "", false)
}

func serveTCPForward(ctx context.Context, addr string) error {
	ln, udp, bound, err := dualbind.Listen(addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	lg.InfoDelayed(time.Second, fmt.Sprintf("Client listening %s", bound))
	go func() {
		<-ctx.Done()
		ln.Close()
		if udp != nil {
			udp.Close()
		}
	}()
	if udp != nil {
		go handleUDPRaw(udp)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go handleTCPForward(c)
	}
}

func handleUDPRaw(pc *net.UDPConn) {
	buf := make([]byte, 65535)
	id := atomic.AddUint32(&connIDGen, 1)
	sendNow(&common.Frame{ConnID: id, Type: common.TypeOpen, Data: []byte("udp://")})
	var last *net.UDPAddr
	go func() {
		// replies arrive as TypeUDPData on this id via existing handler
		_ = last
	}()
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		last = from
		sendNow(&common.Frame{ConnID: id, Type: common.TypeUDPData, Data: common.EncodeUDPData(from.String(), buf[:n])})
	}
}

func handleTCPForward(conn net.Conn) {
	defer conn.Close()
	pipeTCP(conn, "127.0.0.1:0", false)
}

func serveSocks5(ctx context.Context, addr, user, pass string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	lg.InfoDelayed(time.Second, fmt.Sprintf("Client started listening on socks5 %s (auth=%v)", addr, user != ""))
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				lg.Error("accept:", err)
			}
			continue
		}
		go handleSocks5(c, user, pass)
	}
}

func handleSocks5(conn net.Conn, user, pass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf2 := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf2); err != nil || buf2[0] != 5 {
		return
	}
	methods := make([]byte, buf2[1])
	_, _ = io.ReadFull(conn, methods)

	if user != "" {
		_, _ = conn.Write([]byte{5, 2})
		ab := make([]byte, 2)
		if _, err := io.ReadFull(conn, ab); err != nil || ab[0] != 1 {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		ub := make([]byte, ab[1])
		_, _ = io.ReadFull(conn, ub)
		pb := make([]byte, 1)
		_, _ = io.ReadFull(conn, pb)
		pw := make([]byte, pb[0])
		_, _ = io.ReadFull(conn, pw)
		if string(ub) != user || string(pw) != pass {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		_, _ = conn.Write([]byte{1, 0})
	} else {
		_, _ = conn.Write([]byte{5, 0})
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 5 {
		return
	}
	cmd := hdr[1]

	var host string
	switch hdr[3] {
	case 0x01:
		b := make([]byte, 4)
		_, _ = io.ReadFull(conn, b)
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		_, _ = io.ReadFull(conn, lb)
		d := make([]byte, lb[0])
		_, _ = io.ReadFull(conn, d)
		host = string(d)
	case 0x04:
		b := make([]byte, 16)
		_, _ = io.ReadFull(conn, b)
		host = net.IP(b).String()
	default:
		_, _ = conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	portB := make([]byte, 2)
	_, _ = io.ReadFull(conn, portB)
	target := fmt.Sprintf("%s:%d", host, binary.BigEndian.Uint16(portB))
	_ = conn.SetDeadline(time.Time{})

	switch cmd {
	case 0x01:
		handleTCPConnect(conn, target)
	case 0x03:
		handleUDPAssociate(conn)
	default:
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func handleTCPConnect(conn net.Conn, target string) {
	pipeTCP(conn, target, true)
}

func pipeTCP(conn net.Conn, target string, socksReply bool) {
	connID := atomic.AddUint32(&connIDGen, 1)
	pipeExisting(conn, connID, target, socksReply)
}

func pipeExisting(conn net.Conn, connID uint32, target string, socksReply bool) {
	vc := newTCPVConn(connID)
	registerTCP(vc)
	defer unregisterTCP(connID)

	if target != "" {
		sendNow(&common.Frame{ConnID: connID, Type: common.TypeOpen, Seq: 0, Data: []byte(target)})
	}
	if socksReply {
		_, _ = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}
	lg.Info(fmt.Sprintf("[tcp:%d] CONNECT %s", connID, target))

	upDone := make(chan struct{})
	var seq uint32 = 1
	firstData := true

	go func() {
		defer close(upDone)
		buf := make([]byte, common.MaxFrameData)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				common.GlobalMetrics.BytesUp.Add(int64(n))
				f := &common.Frame{ConnID: connID, Type: common.TypeData, Seq: seq, Data: data}
				seq++
				if firstData {
					firstData = false
					sendNow(f)
				} else {
					sendBatched(f)
				}
			}
			if err != nil {
				sendNow(&common.Frame{ConnID: connID, Type: common.TypeClose, Seq: seq})
				return
			}
		}
	}()

	for {
		select {
		case <-upDone:
			return
		case f, ok := <-vc.raw:
			if !ok {
				return
			}
			switch f.Type {
			case common.TypeClose:
				return
			case common.TypeData:
				if len(f.Data) == 0 {
					continue
				}
				common.GlobalMetrics.BytesDown.Add(int64(len(f.Data)))
				_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if _, err := conn.Write(f.Data); err != nil {
					lg.Error(fmt.Sprintf("[tcp:%d] write: %v", connID, err))
					return
				}
				_ = conn.SetWriteDeadline(time.Time{})
			}
		}
	}
}

func handleUDPAssociate(conn net.Conn) {
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	connID := atomic.AddUint32(&connIDGen, 1)
	la := udpLn.LocalAddr().(*net.UDPAddr)
	sess := &udpSession{id: connID, local: udpLn}
	sess.lastSeen.Store(time.Now().UnixNano())
	registerUDP(sess)

	resp := make([]byte, 10)
	resp[0], resp[1], resp[2], resp[3] = 5, 0, 0, 1
	copy(resp[4:8], la.IP.To4())
	binary.BigEndian.PutUint16(resp[8:10], uint16(la.Port))
	_, _ = conn.Write(resp)
	lg.Info(fmt.Sprintf("[udp:%d] ASSOCIATE port %d", connID, la.Port))
	sendNow(&common.Frame{ConnID: connID, Type: common.TypeOpen, Seq: 0, Data: []byte("udp://")})

	go func() {
		defer unregisterUDP(connID)
		buf := make([]byte, 65536)
		for {
			n, _, err := udpLn.ReadFrom(buf)
			if err != nil {
				return
			}
			sess.lastSeen.Store(time.Now().UnixNano())
			dst, payload, err := parseSocksUDPRequest(buf[:n])
			if err != nil {
				continue
			}
			common.GlobalMetrics.BytesUp.Add(int64(len(payload)))
			sendNow(&common.Frame{ConnID: connID, Type: common.TypeUDPData,
				Data: common.EncodeUDPData(dst, payload)})
		}
	}()
	_, _ = io.Copy(io.Discard, conn)
	sendNow(&common.Frame{ConnID: connID, Type: common.TypeClose})
	lg.Info(fmt.Sprintf("[udp:%d] closed", connID))
}

func parseSocksUDPRequest(buf []byte) (string, []byte, error) {
	if len(buf) < 10 {
		return "", nil, fmt.Errorf("short")
	}
	switch buf[3] {
	case 0x01:
		return fmt.Sprintf("%s:%d", net.IP(buf[4:8]).String(), binary.BigEndian.Uint16(buf[8:10])), buf[10:], nil
	case 0x03:
		dl := int(buf[4])
		if len(buf) < 5+dl+2 {
			return "", nil, fmt.Errorf("domain short")
		}
		return fmt.Sprintf("%s:%d", string(buf[5:5+dl]), binary.BigEndian.Uint16(buf[5+dl:7+dl])), buf[7+dl:], nil
	case 0x04:
		if len(buf) < 22 {
			return "", nil, fmt.Errorf("ipv6 short")
		}
		return fmt.Sprintf("[%s]:%d", net.IP(buf[4:20]).String(), binary.BigEndian.Uint16(buf[20:22])), buf[22:], nil
	}
	return "", nil, fmt.Errorf("unknown ATYP %d", buf[3])
}

func buildSocksUDPHeader(src *net.UDPAddr) []byte {
	if ip4 := src.IP.To4(); ip4 != nil {
		h := make([]byte, 10)
		h[3] = 0x01
		copy(h[4:8], ip4)
		binary.BigEndian.PutUint16(h[8:10], uint16(src.Port))
		return h
	}
	h := make([]byte, 22)
	h[3] = 0x04
	copy(h[4:20], src.IP.To16())
	binary.BigEndian.PutUint16(h[20:22], uint16(src.Port))
	return h
}

func applyConfig(c Config) {
	lg = ptlog.PTLog{LogTag: c.LogTag}
	common.SetLog(lg)
	if c.Listen != "" {
		cfgListen = c.Listen
	}
	if c.FTP != "" {
		cfgFTP = c.FTP
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
	cfgTLS = c.TLS
	if c.UploadChannels > 0 {
		cfgUpChans = c.UploadChannels
	}
	if c.DownloadChannels > 0 {
		cfgDownChans = c.DownloadChannels
	}
	cfgUpAddr = c.OverrideUpAddr
	cfgDownAddr = c.OverrideDownAddr
	cfgDecoy = c.Decoy
	cfgSocksUser = c.SocksUser
	cfgSocksPass = c.SocksPass
	cfgDebug = c.Debug
	cfgReverse = c.ReverseAddr
}

// Run starts the FTP tunnel client and blocks until ctx is cancelled.
func Run(ctx context.Context, c Config) error {
	applyConfig(c)
	aesKey = common.DeriveKey(cfgKey)
	sessionToken = common.NewSessionToken()
	useTLS = cfgTLS

	var err error
	ftpHost, _, err = net.SplitHostPort(cfgFTP)
	if err != nil {
		return fmt.Errorf("invalid ftp address: %w", err)
	}
	if cfgUpAddr != "" {
		if _, _, err := net.SplitHostPort(cfgUpAddr); err != nil {
			return fmt.Errorf("invalid override-up-addr %q: %w", cfgUpAddr, err)
		}
	}
	if cfgDownAddr != "" {
		if _, _, err := net.SplitHostPort(cfgDownAddr); err != nil {
			return fmt.Errorf("invalid override-down-addr %q: %w", cfgDownAddr, err)
		}
	}
	text := "FTP Tunnel Client:"
	text = fmt.Sprintf(text+"\n> Session token  : %s", sessionToken)
	text = fmt.Sprintf(text+"\n> FTP server     : %s (tls=%v)", cfgFTP, useTLS)
	text = fmt.Sprintf(text+"\n> SOCKS5 listen  : %s", cfgListen)
	text = fmt.Sprintf(text+"\n> Channels       : up=%d down=%d", cfgUpChans, cfgDownChans)
	if cfgUpAddr != "" {
		text = fmt.Sprintf(text+"\n> Upload override : %s", cfgUpAddr)
	}
	if cfgDownAddr != "" {
		text = fmt.Sprintf(text+"\n> Download override: %s", cfgDownAddr)
	}
	text = fmt.Sprintf(text+"\n> Key fingerprint: %x", aesKey[:4])
	text = fmt.Sprintf(text+"\n> Decoy          : %v", cfgDecoy)
	lg.Info(text, "\n")

	common.StartMetricsLogger(metricsEvery)

	if err := connectWithRetry(ctx); err != nil {
		return fmt.Errorf("connect aborted: %w", err)
	}

	gb = newBatcher(batchDelay)

	go heartbeatLoop(ctx)
	go udpReaper(ctx)
	go controlKeepalive(ctx)
	if cfgDecoy {
		go decoyLoop(ctx)
	}
	errCh := make(chan error, 1)
	go func() {
		if cfgReverse != "" {
			sendNow(&common.Frame{ConnID: 0, Type: common.TypeReverseBind, Data: []byte(cfgListen)})
			<-ctx.Done()
			errCh <- nil
			return
		}
		errCh <- serveTCPForward(ctx, cfgListen)
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	lg.Info("Shutting down…")
	gb.flush()
	chanMu.Lock()
	for _, ch := range uploads {
		if ch != nil {
			ch.Close()
		}
	}
	for _, ch := range downloads {
		if ch != nil {
			ch.Close()
		}
	}
	chanMu.Unlock()
	ftpMu.Lock()
	if ftpCtrl != nil {
		ftpCtrl.Close()
	}
	ftpMu.Unlock()
	lg.Info("Done.")
	return ctx.Err()
}
