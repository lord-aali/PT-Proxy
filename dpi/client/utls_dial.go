package client

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// utlsDialer provides TLS connections. Uses standard crypto/tls.
// For TLS fingerprint resistance, integrate github.com/refraction-networking/utls
// and use utls.UClient with HelloChrome_120 instead of tls.Client.
type utlsDialer struct {
	config *tls.Config
}

func newUTLSDialer(config *tls.Config) *utlsDialer {
	if config == nil {
		config = &tls.Config{}
	}
	return &utlsDialer{config: config}
}

func (d *utlsDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := d.config.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return tls.DialWithDialer(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}, network, addr, cfg)
}

var defaultDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}
