package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/dpi/common"
)

const (
	postAsyncWindow = 8
	maxSessions     = 2
)

// TransportConfig configures a DPI client transport.
type TransportConfig struct {
	ServerURL       string
	Encryptor       *common.Encryptor
	TLSConfig       *tls.Config
	FollowRedirects bool
	FrontHost       string
	DialIP          string
	Protocol        string
	Uplink          string // post-async (default) or stream
	LogTag          string
}

// Transport sends/receives encrypted data over HTTP to the server.
type Transport struct {
	baseURL    string
	scheme     string
	host       string
	frontHost  string
	dialIP     string
	encryptor  *common.Encryptor
	httpClient *http.Client
	protocol   string
	uplink     string
	log        ptlog.PTLog

	connIDGen uint32
	connIDMu  sync.Mutex

	postSem chan struct{}

	sessMu   sync.Mutex
	sessions []*muxSession
	active   int32 // pinned logical flows across sessions

	ReverseLocal string
}

// NewTransport creates a transport to the server.
func NewTransport(cfg TransportConfig) (*Transport, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL scheme must be http or https")
	}
	if cfg.DialIP == "" {
		return nil, fmt.Errorf("dial IP is required (from address host)")
	}
	proto, err := normalizeAppProtocol(cfg.Protocol)
	if err != nil {
		return nil, err
	}
	uplink := strings.TrimSpace(cfg.Uplink)
	if uplink == "" {
		uplink = common.UplinkPostAsync
	}
	if uplink != common.UplinkPostAsync && uplink != common.UplinkStream {
		return nil, fmt.Errorf("invalid uplink %q (expected post-async or stream)", uplink)
	}
	// Long-lived chunked streams are unreliable over HTTP/2 and many middleboxes;
	// pin stream mode to HTTP/1.1.
	if uplink == common.UplinkStream {
		proto = "h1"
	}

	tr := &Transport{
		baseURL:   cfg.ServerURL,
		scheme:    u.Scheme,
		host:      u.Host,
		frontHost: cfg.FrontHost,
		dialIP:    cfg.DialIP,
		encryptor: cfg.Encryptor,
		protocol:  proto,
		uplink:    uplink,
		log:       ptlog.PTLog{LogTag: cfg.LogTag},
		postSem:   make(chan struct{}, postAsyncWindow),
	}
	tr.connIDGen = 1

	transport := &http.Transport{
		MaxIdleConns:        256,
		IdleConnTimeout:     120 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 128,
		ForceAttemptHTTP2:   proto != "h1",
		TLSClientConfig:     cfg.TLSConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.Contains(addr, u.Hostname()) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					if u.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				addr = net.JoinHostPort(tr.dialIP, port)
			}
			dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	if proto == "h1" {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	tr.httpClient = &http.Client{Transport: transport}
	if !cfg.FollowRedirects {
		tr.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return tr, nil
}

// UplinkMode returns the configured uplink mode.
func (t *Transport) UplinkMode() string { return t.uplink }

// NextConnID returns a new connection ID.
func (t *Transport) NextConnID() uint32 {
	t.connIDMu.Lock()
	defer t.connIDMu.Unlock()
	id := t.connIDGen
	t.connIDGen++
	if t.connIDGen == 0 {
		t.connIDGen = 1
	}
	return id
}

func (t *Transport) buildPlain(msgType uint8, connID uint32, payload []byte) []byte {
	header := common.BuildStreamHeader(msgType, connID, uint32(len(payload)))
	return append(header, payload...)
}

// Connect establishes a tunneled connection to target.
func (t *Transport) Connect(network, address string) (uint32, error) {
	req := &common.ConnectRequest{Network: network, Address: address}
	payload := common.EncodeConnectRequest(req)
	connID := t.NextConnID()
	plain := t.buildPlain(common.MsgConnect, connID, payload)
	encrypted, err := t.encryptor.Encrypt(plain)
	if err != nil {
		return 0, err
	}

	if t.uplink == common.UplinkStream {
		sess, err := t.pickSession()
		if err != nil {
			return 0, err
		}
		sess.pin(connID)
		if err := sess.writeEncrypted(encrypted); err != nil {
			sess.unpin(connID)
			return 0, err
		}
		atomic.AddInt32(&t.active, 1)
		return connID, nil
	}

	uploadURL := t.baseURL + "/.well-known/cdn-cache/upload"
	body, status, err := t.doPost(uploadURL, encrypted, true)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("connect failed: %s", string(body))
	}
	if !bytes.Contains(body, []byte(`"status":"ok"`)) {
		return 0, fmt.Errorf("connect failed: %s", string(body))
	}
	atomic.AddInt32(&t.active, 1)
	return connID, nil
}

// SendData sends data to the server.
func (t *Transport) SendData(connID uint32, data []byte) error {
	plain := t.buildPlain(common.MsgData, connID, data)
	encrypted, err := t.encryptor.Encrypt(plain)
	if err != nil {
		return err
	}
	if t.uplink == common.UplinkStream {
		sess := t.sessionFor(connID)
		if sess == nil {
			return fmt.Errorf("no stream session for connID %d", connID)
		}
		return sess.writeEncrypted(encrypted)
	}
	return t.postAsyncFire(t.baseURL+"/api/v2/upload", encrypted)
}

// CloseConn tells the server to close the connection.
func (t *Transport) CloseConn(connID uint32) error {
	defer func() {
		atomic.AddInt32(&t.active, -1)
		t.maybeShrinkSessions()
	}()
	plain := t.buildPlain(common.MsgClose, connID, nil)
	encrypted, err := t.encryptor.Encrypt(plain)
	if err != nil {
		return err
	}
	if t.uplink == common.UplinkStream {
		sess := t.sessionFor(connID)
		if sess == nil {
			return nil
		}
		err := sess.writeEncrypted(encrypted)
		sess.unpin(connID)
		return err
	}
	return t.postAsyncFire(t.baseURL+"/api/v2/upload", encrypted)
}

// DownloadStream opens a reader for download data for connID.
func (t *Transport) DownloadStream(ctx context.Context, connID uint32) (io.ReadCloser, error) {
	if t.uplink == common.UplinkStream {
		sess := t.sessionFor(connID)
		if sess == nil {
			var err error
			sess, err = t.pickSession()
			if err != nil {
				return nil, err
			}
			sess.pin(connID)
		}
		return sess.openConnReader(connID), nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	downloadURL := fmt.Sprintf("%s/download/%d", t.baseURL, connID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	t.setBrowserHeaders(httpReq)
	httpReq.Header.Del("Accept-Encoding")
	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("download failed: %d", resp.StatusCode)
	}
	return &streamReader{resp: resp, encryptor: t.encryptor}, nil
}

func (t *Transport) doPost(uploadURL string, encrypted []byte, readBody bool) ([]byte, int, error) {
	httpReq, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(encrypted))
	if err != nil {
		return nil, 0, err
	}
	t.setBrowserHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
		redirectURL := resp.Header.Get("Location")
		if redirectURL[0] == '/' {
			redirectURL = t.scheme + "://" + t.host + redirectURL
		}
		t.baseURL = strings.TrimRight(redirectURL, "/")
		return t.doPost(t.baseURL+pathFromURL(uploadURL), encrypted, readBody)
	}
	if !readBody {
		io.Copy(io.Discard, resp.Body)
		return nil, resp.StatusCode, nil
	}
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

func pathFromURL(full string) string {
	if i := strings.Index(full, "/."); i >= 0 {
		return full[i:]
	}
	if i := strings.Index(full, "/api/"); i >= 0 {
		return full[i:]
	}
	u, err := url.Parse(full)
	if err != nil {
		return "/api/v2/upload"
	}
	return u.Path
}

// postAsyncFire posts without waiting for the response body.
func (t *Transport) postAsyncFire(uploadURL string, encrypted []byte) error {
	t.postSem <- struct{}{}
	done := make(chan error, 1)
	go func() {
		defer func() { <-t.postSem }()
		_, _, err := t.doPost(uploadURL, encrypted, false)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Millisecond):
		go func() { <-done }()
		return nil
	}
}

func (t *Transport) setBrowserHeaders(req *http.Request) {
	if t.frontHost != "" {
		req.Host = t.frontHost
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
}

func normalizeAppProtocol(protocol string) (string, error) {
	switch protocol {
	case "", "auto":
		return "auto", nil
	case "h1", "h2":
		return protocol, nil
	case "h3":
		return "", fmt.Errorf("protocol h3 is not implemented yet")
	default:
		return "", fmt.Errorf("invalid protocol %q (expected auto, h1, h2, or h3)", protocol)
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type streamReader struct {
	resp      *http.Response
	encryptor *common.Encryptor
	buf       []byte
	decrypted []byte
	off       int
}

func (sr *streamReader) Read(p []byte) (int, error) {
	for {
		if sr.off < len(sr.decrypted) {
			n := copy(p, sr.decrypted[sr.off:])
			sr.off += n
			return n, nil
		}
		sr.decrypted = nil
		sr.off = 0
		enc, err := common.ReadLengthPrefixed(sr.resp.Body)
		if err != nil {
			return 0, err
		}
		dec, err := sr.encryptor.Decrypt(enc)
		if err != nil {
			return 0, err
		}
		hdr, payload, err := common.ParseStreamHeader(dec)
		if err != nil {
			return 0, err
		}
		if hdr.MsgType == common.MsgData && int(hdr.PayloadLen) <= len(payload) {
			sr.decrypted = payload[:hdr.PayloadLen]
		}
	}
}

func (sr *streamReader) Close() error {
	if sr.resp != nil && sr.resp.Body != nil {
		return sr.resp.Body.Close()
	}
	return nil
}

func (t *Transport) SendReverseBind(listen string) error {
	sess, err := t.pickSession()
	if err != nil {
		return err
	}
	plain := t.buildPlain(common.MsgReverseBind, 0, []byte(listen))
	encrypted, err := t.encryptor.Encrypt(plain)
	if err != nil {
		return err
	}
	if err := sess.writeEncrypted(encrypted); err != nil {
		_, _, err = t.doPost(t.baseURL+"/.well-known/cdn-cache/upload", encrypted, true)
		return err
	}
	return nil
}

func (t *Transport) handleReverseOpen(connID uint32) {
	if t.ReverseLocal == "" {
		return
	}
	local, err := net.Dial("tcp", t.ReverseLocal)
	if err != nil {
		t.log.Error("reverse dial:", err)
		_ = t.CloseConn(connID)
		return
	}
	defer local.Close()
	tunnel, err := newTunnelConn(t, connID, t.log, false)
	if err != nil {
		local.Close()
		return
	}
	defer tunnel.Close()
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(tunnel, local); errCh <- err }()
	go func() { _, err := io.Copy(local, tunnel); errCh <- err }()
	<-errCh
}
