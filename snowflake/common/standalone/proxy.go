package standalone

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

// ProxyDialer returns a dial function for TCP, optionally via proxyURL
// (socks5://, socks5h://, http://, https://).
func ProxyDialer(proxyURL string) func(network, addr string) (net.Conn, error) {
	if proxyURL == "" {
		d := &net.Dialer{Timeout: 30 * time.Second}
		return func(network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return func(network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		d, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return func(network, addr string) (net.Conn, error) {
				return nil, err
			}
		}
		return func(network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}
	case "http", "https":
		return func(network, addr string) (net.Conn, error) {
			return dialHTTPProxy(u, addr)
		}
	default:
		return func(network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
		}
	}
}

func dialHTTPProxy(u *url.URL, addr string) (net.Conn, error) {
	proxyAddr := u.Host
	if !strings.Contains(proxyAddr, ":") {
		if u.Scheme == "https" {
			proxyAddr += ":443"
		} else {
			proxyAddr += ":80"
		}
	}
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if u.User != nil {
		password, _ := u.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+auth)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	return conn, nil
}

// WebSocketDialer builds a gorilla websocket.Dialer with optional upstream proxy.
func WebSocketDialer(proxyURL string, insecureTLS bool) *websocket.Dialer {
	dial := ProxyDialer(proxyURL)
	d := &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
		NetDial:          dial,
	}
	if insecureTLS {
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	return d
}
