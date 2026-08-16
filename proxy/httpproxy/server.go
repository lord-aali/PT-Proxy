package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

// Serve listens for HTTP CONNECT (and absolute-form HTTP) on addr.
func Serve(addr, tag string) (bound string, err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	bound = ln.Addr().String()
	lg := ptlog.PTLog{LogTag: tag}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				lg.Error("http proxy accept:", err)
				return
			}
			go handle(c, lg)
		}
	}()
	lg.Info("http proxy on", bound)
	return bound, nil
}

func handle(c net.Conn, lg ptlog.PTLog) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if strings.EqualFold(req.Method, http.MethodConnect) {
		host := req.Host
		if host == "" {
			host = req.URL.Host
		}
		remote, err := net.DialTimeout("tcp", host, 15*time.Second)
		if err != nil {
			fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer remote.Close()
		fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		copyBoth(c, remote)
		return
	}
	// Non-CONNECT: proxy a single HTTP request.
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	remote, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer remote.Close()
	if err := req.Write(remote); err != nil {
		return
	}
	io.Copy(c, remote)
}

func copyBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}
