package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
	"github.com/lord-aali/PT-Proxy/dpi/common"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config holds server configuration.
type Config struct {
	HTTPAddr      string
	HTTPSAddr     string
	TLSCertFile   string
	TLSKeyFile    string
	ACMEEmail     string
	ACMEDomain    string
	SelfSigned    bool
	RedirectURL   string
	EncryptionKey []byte
	CertDir       string
	Protocol      string
	LogTag        string
	Target        string
	SkipUDP       bool
	ServeDir      string
	Backend       string
}

// Server is the proxy server.
type Server struct {
	cfg          Config
	log          ptlog.PTLog
	encryptor    *common.Encryptor
	listeners    []net.Listener
	handler      *tunnelHandler
	mux          *http.ServeMux
	clientLock   sync.RWMutex
	clients      map[uint32]*clientConn
	sessLock     sync.RWMutex
	sessions     map[string]*muxSession
	nextConnID   atomic.Uint32
	stopCh       chan struct{}
	fileServer   http.Handler
	reverseProxy *httputil.ReverseProxy
}

// NewServer creates a new server.
func NewServer(cfg Config) (*Server, error) {
	enc, err := common.NewEncryptor(cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encryptor: %w", err)
	}
	s := &Server{
		cfg:       cfg,
		log:       ptlog.PTLog{LogTag: cfg.LogTag},
		encryptor: enc,
		clients:   make(map[uint32]*clientConn),
		sessions:  make(map[string]*muxSession),
		stopCh:    make(chan struct{}),
	}
	s.handler = newTunnelHandler(s)
	s.mux = http.NewServeMux()

	if cfg.Backend != "" {
		u, err := url.Parse(cfg.Backend)
		if err != nil {
			return nil, fmt.Errorf("backend url: %w", err)
		}
		s.reverseProxy = httputil.NewSingleHostReverseProxy(u)
	}
	if cfg.ServeDir != "" {
		s.fileServer = http.FileServer(http.Dir(cfg.ServeDir))
	}

	s.mux.HandleFunc("/.well-known/cdn-cache/", s.handler.handleTunnel)
	s.mux.HandleFunc("/api/v2/upload", s.handler.handleTunnel)
	s.mux.HandleFunc("/api/v2/stream", s.handler.handleStreamUpload)
	s.mux.HandleFunc("/download/session/", s.handler.handleSessionDownload)
	s.mux.HandleFunc("/download/", s.handler.handleDownload)
	s.mux.HandleFunc("/", s.handleRoot)

	return s, nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RedirectURL != "" {
		http.Redirect(w, r, s.cfg.RedirectURL, http.StatusFound)
		return
	}
	if s.reverseProxy != nil {
		s.reverseProxy.ServeHTTP(w, r)
		return
	}
	if s.fileServer != nil {
		s.fileServer.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<!DOCTYPE html><html><head><title>Service</title></head><body><h1>Service Unavailable</h1></body></html>`))
}

func (s *Server) Run() error {
	if s.cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		s.listeners = append(s.listeners, ln)
		go s.serveHTTP(ln)
		s.log.Info("Server started listening on HTTP", s.cfg.HTTPAddr)
	}

	if s.cfg.HTTPSAddr != "" {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("tls config: %w", err)
		}
		ln, err := tls.Listen("tcp", s.cfg.HTTPSAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("https listen: %w", err)
		}
		s.listeners = append(s.listeners, ln)
		go s.serveHTTP(ln)
		s.log.Info("Server started listening on HTTPS", s.cfg.HTTPSAddr)
	}

	return nil
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	proto, err := normalizeAppProtocol(s.cfg.Protocol)
	if err != nil {
		return nil, err
	}

	if s.cfg.ACMEEmail != "" && s.cfg.ACMEDomain != "" {
		certDir := s.cfg.CertDir
		if certDir == "" {
			exe, _ := os.Executable()
			certDir = filepath.Dir(exe)
		}
		mgr := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.cfg.ACMEDomain),
			Cache:      autocert.DirCache(certDir),
		}
		return &tls.Config{
			GetCertificate: mgr.GetCertificate,
			NextProtos:     tlsNextProtos(proto, true),
		}, nil
	}

	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   tlsNextProtos(proto, false),
		}, nil
	}

	if s.cfg.SelfSigned {
		cert, key, err := generateSelfSigned()
		if err != nil {
			return nil, err
		}
		cc, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cc},
			NextProtos:   tlsNextProtos(proto, false),
		}, nil
	}

	return nil, fmt.Errorf("no TLS configuration (cert+key, ACME, or self-signed)")
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

func tlsNextProtos(protocol string, withACME bool) []string {
	switch protocol {
	case "h1":
		if withACME {
			return []string{"http/1.1", acme.ALPNProto}
		}
		return []string{"http/1.1"}
	default:
		if withACME {
			return []string{"h2", "http/1.1", acme.ALPNProto}
		}
		return []string{"h2", "http/1.1"}
	}
}

func (s *Server) serveHTTP(ln net.Listener) {
	server := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	server.Serve(ln)
}

func (s *Server) Shutdown(ctx context.Context) error {
	close(s.stopCh)
	for _, ln := range s.listeners {
		ln.Close()
	}
	return nil
}

func (s *Server) registerClient(connID uint32, c *clientConn) {
	s.clientLock.Lock()
	s.clients[connID] = c
	s.clientLock.Unlock()
}

func (s *Server) unregisterClient(connID uint32) {
	s.clientLock.Lock()
	delete(s.clients, connID)
	s.clientLock.Unlock()
}

func (s *Server) getClient(connID uint32) *clientConn {
	s.clientLock.RLock()
	defer s.clientLock.RUnlock()
	return s.clients[connID]
}

func (s *Server) nextID() uint32 {
	return s.nextConnID.Add(1)
}

// randomFilename generates a random filename with random extension for download streams.
func randomFilename() string {
	const ext = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = ext[b[i]%26]
	}
	extLen := 2 + int(b[0]%5)
	extBuf := make([]byte, extLen)
	rand.Read(extBuf)
	for i := range extBuf {
		extBuf[i] = ext[extBuf[i]%26]
	}
	return string(b) + "." + string(extBuf)
}
