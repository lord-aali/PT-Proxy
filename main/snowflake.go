package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	SfSocks5 "github.com/lord-aali/PT-Proxy/snowflake/common/socks5"
	SfStandalone "github.com/lord-aali/PT-Proxy/snowflake/common/standalone"
	SfWsConn "github.com/lord-aali/PT-Proxy/snowflake/common/websocketconn"
)

const (
	snowflakeDefaultWsListen = "0.0.0.0:8080"
	snowflakeDefaultSocks    = "127.0.0.1:0"
)

// launchSnowflakeServer starts a standalone snowflake WebSocket relay with a
// local SOCKS5 exit, from a config entry. The server manages its own listeners
// internally, so none are surfaced to the terminal monitor.
func launchSnowflakeServer(c configuration.JsonServerConfigImpl, tag string) bool {
	lg := ptlog.PTLog{LogTag: tag}

	wsAddr := dpiOrDefault(c.Listen, snowflakeDefaultWsListen)
	tcpAddr, err := net.ResolveTCPAddr("tcp", wsAddr)
	if err != nil {
		lg.Error("snowflake server invalid listen address:", err)
		return false
	}

	srv, httpServer, err := SfStandalone.NewServer(tcpAddr)
	if err != nil {
		lg.Error("snowflake server init failed:", err)
		return false
	}

	socksLn, err := net.Listen("tcp", dpiOrDefault(c.SocksBind, snowflakeDefaultSocks))
	if err != nil {
		lg.Error("snowflake server socks listen failed:", err)
		return false
	}
	srv.ServerSocksAddr = socksLn.Addr().String()
	go serveSnowflakeSOCKS(socksLn, lg)

	useTLS := c.TlsCertFile != "" && c.TlsKeyFile != ""
	go func() {
		var serveErr error
		if useTLS {
			httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			serveErr = httpServer.ListenAndServeTLS(c.TlsCertFile, c.TlsKeyFile)
		} else {
			serveErr = httpServer.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			lg.Error("snowflake server http error:", serveErr)
		}
	}()

	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	lg.Info("Server started listening ("+scheme+"://"+wsAddr+"/ socks exit:", srv.ServerSocksAddr+")")
	return true
}

// serveSnowflakeSOCKS is the server's local SOCKS5 exit loop: it accepts a
// SOCKS5 CONNECT from the tunnel and bridges it to the real destination.
func serveSnowflakeSOCKS(ln net.Listener, lg ptlog.PTLog) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			lg.Error("snowflake socks accept:", err)
			return
		}
		go func(c net.Conn) {
			target, err := SfSocks5.HandshakeServer(c)
			if err != nil {
				c.Close()
				return
			}
			remote, err := net.Dial(target.Network, target.Addr())
			if err != nil {
				_ = SfSocks5.ReplyConnectFailed(c)
				c.Close()
				return
			}
			if err := SfSocks5.ReplyConnectSuccess(c); err != nil {
				remote.Close()
				c.Close()
				return
			}
			SfStandalone.CopyLoop(c, remote)
			remote.Close()
		}(conn)
	}
}

// launchSnowflakeClient connects to a standalone snowflake server over
// WebSocket and exposes a local SOCKS5 proxy (and optional tunnel forward).
func launchSnowflakeClient(c configuration.JsonClientConfigImpl, tag string) bool {
	lg := ptlog.PTLog{LogTag: tag}

	if c.Address == "" {
		lg.Error("snowflake client requires a server address (ws:// or wss:// URL)")
		return false
	}

	skipTLSVerify := c.Insecure
	wsDialer := SfStandalone.WebSocketDialer(c.Proxy, skipTLSVerify)

	// SNI override for wss:// (SNI camouflage / domain fronting). Fall back to
	// front-host when sni is unset so the Host header and ServerName match.
	serverName := c.Sni
	if serverName == "" {
		serverName = c.FrontHost
	}
	if serverName != "" || skipTLSVerify {
		if wsDialer.TLSClientConfig == nil {
			wsDialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if serverName != "" {
			wsDialer.TLSClientConfig.ServerName = serverName
		}
		if skipTLSVerify {
			wsDialer.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	// Optional custom Host header. gorilla/websocket maps the "Host" header key
	// onto the request Host, which enables domain fronting.
	wsHeader := http.Header{}
	if c.FrontHost != "" {
		wsHeader.Set("Host", c.FrontHost)
	}

	dialWS := func() (net.Conn, error) {
		ws, _, err := wsDialer.Dial(c.Address, wsHeader)
		if err != nil {
			return nil, err
		}
		return SfWsConn.New(ws), nil
	}

	sess, _, err := SfStandalone.NewClientSession(SfStandalone.WrapWebSocketDial(dialWS))
	if err != nil {
		lg.Error("snowflake client session failed:", err)
		return false
	}

	socksAddr, err := SfStandalone.ServeLocalSOCKS(dpiOrDefault(c.Listen, snowflakeDefaultSocks), sess)
	if err != nil {
		lg.Error("snowflake client local socks failed:", err)
		return false
	}

	if c.ForwardBind != "" {
		forwardAddr, err := SfStandalone.ServeTunnelForward(c.ForwardBind, sess)
		if err != nil {
			lg.Error("snowflake client tunnel forward failed:", err)
			return false
		}
		lg.InfoDelayed(time.Second, "Client started listening (socks:", socksAddr.String(), "tunneled-server-socks:", forwardAddr.String()+")")
		return true
	}

	if skipTLSVerify {
		lg.InfoDelayed(time.Second, "Client started listening (socks:", socksAddr.String(), "tls: skip-verify)")
	} else {
		lg.InfoDelayed(time.Second, "Client started listening (socks:", socksAddr.String()+")")
	}
	return true
}
