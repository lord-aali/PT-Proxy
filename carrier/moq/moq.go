package moq

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Eyevinn/moqtransport"
	"github.com/Eyevinn/moqtransport/quicmoq"
	"github.com/lord-aali/PT-Proxy/carrier/core"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/quic-go/quic-go"
)

const (
	alpn          = "moqt-16"
	namespaceName = "ptproxy"
	trackUp       = "up"
	trackDown     = "down"
	defaultListen = "0.0.0.0:4433"
)

// Config is one MoQ carrier endpoint. Listen is the server UDP bind.
// Address is the client dial target (host:port).
type Config struct {
	Listen      string
	Address     string
	Target      string
	EncKey      string
	ReverseAddr string
	SkipUDP     bool
	PadMax      int
	JitterMax   time.Duration
	LogTag      string
	DNSNetwork  string
	DNSUpstream string
}

func RunServer(cfg Config) error {
	listen := strings.TrimSpace(cfg.Listen)
	if listen == "" {
		listen = defaultListen
	}
	ln, err := listenQUIC(listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	lg.Info("carrier moq listen", ln.Addr().String(), "alpn", alpn)
	return serveListener(ln, cfg)
}

func RunClient(cfg Config) error {
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	addr, err := parseAddr(cfg.Address)
	if err != nil {
		return err
	}
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	for {
		err := runClientOnce(enc, cfg, addr, lg)
		if err != nil {
			lg.Error("moq:", err)
		}
		time.Sleep(time.Second)
	}
}

func listenQUIC(addr string) (*quic.Listener, error) {
	tlsConf, err := serverTLS()
	if err != nil {
		return nil, err
	}
	return quic.ListenAddr(addr, tlsConf, quicConfig())
}

func serveListener(ln *quic.Listener, cfg Config) error {
	enc, err := core.NewEncryptor([]byte(cfg.EncKey))
	if err != nil {
		return err
	}
	lg := ptlog.PTLog{LogTag: cfg.LogTag}
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go func(conn *quic.Conn) {
			if err := serveConn(conn, enc, cfg); err != nil {
				lg.Error("moq session:", err)
			}
		}(conn)
	}
}

func serveConn(conn *quic.Conn, enc *core.Encryptor, cfg Config) error {
	closeConn := closeOnce(conn)
	defer closeConn()
	link, err := attach(context.Background(), quicmoq.NewServer(conn), trackDown, trackUp, enc, cfg, closeConn)
	if err != nil {
		return err
	}
	core.Serve(link, core.ServerConfig{
		Target:      cfg.Target,
		SkipUDP:     cfg.SkipUDP,
		DNSNetwork:  cfg.DNSNetwork,
		DNSUpstream: cfg.DNSUpstream,
	})
	return nil
}

func runClientOnce(enc *core.Encryptor, cfg Config, addr string, lg ptlog.PTLog) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, clientTLS(), quicConfig())
	if err != nil {
		return err
	}
	closeConn := closeOnce(conn)
	link, err := attach(ctx, quicmoq.NewClient(conn), trackUp, trackDown, enc, cfg, closeConn)
	if err != nil {
		closeConn()
		return err
	}
	defer link.Close()
	link.readWait = 15 * time.Second
	if err := core.HandshakeClient(link); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	link.readWait = 0
	lg.Info("moq session open", addr)
	sess := core.NewClientSession(link, cfg.ReverseAddr)
	defer sess.Close()
	if cfg.ReverseAddr != "" {
		return core.RunClientSocks(sess, core.SocksConfig{
			Listen:      cfg.Listen,
			ReverseAddr: cfg.ReverseAddr,
			SkipUDP:     cfg.SkipUDP,
			LogTag:      cfg.LogTag,
		})
	}
	return core.RunClientForward(sess, cfg.Listen, "", cfg.SkipUDP, cfg.LogTag)
}

func attach(parent context.Context, conn moqtransport.Connection, publishTrack, subscribeTrack string, enc *core.Encryptor, cfg Config, closeFn func()) (*Link, error) {
	if parent == nil {
		parent = context.Background()
	}
	pubCh := make(chan moqtransport.Publisher, 1)
	session := &moqtransport.Session{
		Handler:             announceHandler(),
		SubscribeHandler:    subscribeHandler(publishTrack, pubCh),
		InitialMaxRequestID: 100,
	}
	setupCtx, cancel := context.WithTimeout(parent, 10*time.Second)
	err := session.RunContext(setupCtx, conn)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("moq setup: %w", err)
	}
	annCtx, annCancel := context.WithTimeout(parent, 5*time.Second)
	_ = session.Announce(annCtx, []string{namespaceName})
	annCancel()

	subCtx, subCancel := context.WithTimeout(parent, 10*time.Second)
	defer subCancel()
	track, err := session.Subscribe(subCtx, []string{namespaceName}, subscribeTrack,
		moqtransport.WithFilterType(moqtransport.FilterTypeAbsoluteStart),
		moqtransport.WithStartLocation(moqtransport.Location{Group: 0, Object: 0}),
	)
	if err != nil {
		return nil, fmt.Errorf("moq subscribe %s: %w", subscribeTrack, err)
	}
	pub, err := waitPublisher(subCtx, pubCh)
	if err != nil {
		return nil, err
	}
	sg, err := pub.OpenSubgroup(0, 0, 128)
	if err != nil {
		return nil, err
	}
	link := newLink(sg, pub, track, enc, cfg.PadMax, cfg.JitterMax, closeFn)
	go link.readLoop()
	return link, nil
}

func announceHandler() moqtransport.Handler {
	return moqtransport.HandlerFunc(func(w moqtransport.ResponseWriter, r *moqtransport.Message) {
		if r.Method == moqtransport.MessageAnnounce && len(r.Namespace) == 1 && r.Namespace[0] == namespaceName {
			_ = w.Accept()
			return
		}
		_ = w.Reject(0, "unsupported")
	})
}

func subscribeHandler(track string, out chan<- moqtransport.Publisher) moqtransport.SubscribeHandler {
	return moqtransport.SubscribeHandlerFunc(func(w *moqtransport.SubscribeResponseWriter, m *moqtransport.SubscribeMessage) {
		if len(m.Namespace) != 1 || m.Namespace[0] != namespaceName || m.Track != track {
			_ = w.Reject(moqtransport.ErrorCodeSubscribeTrackDoesNotExist, "unknown track")
			return
		}
		if err := w.Accept(); err != nil {
			return
		}
		select {
		case out <- w:
		default:
		}
	})
}

func waitPublisher(ctx context.Context, ch <-chan moqtransport.Publisher) (moqtransport.Publisher, error) {
	select {
	case p := <-ch:
		return p, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("moq peer subscribe: %w", ctx.Err())
	}
}

func parseAddr(address string) (string, error) {
	address = strings.TrimSpace(address)
	address = strings.TrimPrefix(address, "quic://")
	address = strings.TrimPrefix(address, "moq://")
	if address == "" || !strings.Contains(address, ":") {
		return "", fmt.Errorf("moq address required (host:port)")
	}
	return address, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		MaxIdleTimeout:                   2 * time.Minute,
		KeepAlivePeriod:                  15 * time.Second,
	}
}

func clientTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{alpn},
	}
}

func serverTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ptproxy-moq"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}, nil
}

func closeOnce(conn *quic.Conn) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = conn.CloseWithError(0, "closed")
		})
	}
}
