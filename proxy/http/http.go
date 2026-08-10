package http

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// httpProxy is a HTTP connect proxy.
type httpProxy struct {
	hostPort string
	haveAuth bool
	username string
	password string
	forward  proxy.Dialer
}

func newHTTP(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(httpProxy)
	s.hostPort = uri.Host
	s.forward = forward
	if uri.User != nil {
		s.haveAuth = true
		s.username = uri.User.Username()
		s.password, _ = uri.User.Password()
	}

	return s, nil
}

func (s *httpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the http client connection.
	c, err := s.forward.Dial("tcp", s.hostPort)
	if err != nil {
		return nil, err
	}
	conn := new(httpConn)
	conn.httpConn = httputil.NewClientConn(c, nil) // nolint: staticcheck
	conn.remoteAddr, err = net.ResolveTCPAddr(network, addr)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}

	// HACK HACK HACK HACK.  http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		conn.httpConn.Close()
		return nil, err
	}
	req.Close = false
	if s.haveAuth {
		// SetBasicAuth doesn't quite do what is appropriate, because
		// the correct header is `Proxy-Authorization`.
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.username+":"+s.password)))
	}
	req.Header.Set("User-Agent", "")

	resp, err := conn.httpConn.Do(req)
	if err != nil && err != httputil.ErrPersistEOF { // nolint: staticcheck
		conn.httpConn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.httpConn.Close()
		return nil, fmt.Errorf("proxy error: %s", resp.Status)
	}

	conn.hijackedConn, conn.staleReader = conn.httpConn.Hijack()
	return conn, nil
}

type httpConn struct {
	remoteAddr   *net.TCPAddr
	httpConn     *httputil.ClientConn // nolint: staticcheck
	hijackedConn net.Conn
	staleReader  *bufio.Reader
}

func (c *httpConn) Read(b []byte) (int, error) {
	if c.staleReader != nil {
		if c.staleReader.Buffered() > 0 {
			return c.staleReader.Read(b)
		}
		c.staleReader = nil
	}
	return c.hijackedConn.Read(b)
}

func (c *httpConn) Write(b []byte) (int, error) {
	return c.hijackedConn.Write(b)
}

func (c *httpConn) Close() error {
	return c.hijackedConn.Close()
}

func (c *httpConn) LocalAddr() net.Addr {
	return c.hijackedConn.LocalAddr()
}

func (c *httpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *httpConn) SetDeadline(t time.Time) error {
	return c.hijackedConn.SetDeadline(t)
}

func (c *httpConn) SetReadDeadline(t time.Time) error {
	return c.hijackedConn.SetReadDeadline(t)
}

func (c *httpConn) SetWriteDeadline(t time.Time) error {
	return c.hijackedConn.SetWriteDeadline(t)
}

func init() {
	proxy.RegisterDialerType("http", newHTTP)
}
