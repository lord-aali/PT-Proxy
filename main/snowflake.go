package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/lord-aali/PT-Proxy/common/configuration"
	"github.com/lord-aali/PT-Proxy/common/dualbind"
	"github.com/lord-aali/PT-Proxy/common/muxpipe"
	"github.com/lord-aali/PT-Proxy/common/ptlog"
	SfStandalone "github.com/lord-aali/PT-Proxy/snowflake/common/standalone"
	SfWsConn "github.com/lord-aali/PT-Proxy/snowflake/common/websocketconn"
)

const snowflakeDefaultWsListen = "0.0.0.0:8080"

func launchSnowflakeServer(c configuration.JsonServerConfigImpl, tag, target string, skipUDP bool) bool {
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
	srv.Target = target
	srv.SkipUDP = skipUDP

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
	lg.Info("Server started listening (" + scheme + "://" + wsAddr + "/)")
	return true
}

func launchSnowflakeClient(c configuration.JsonClientConfigImpl, tag, reverseAddr string, skipUDP bool) bool {
	lg := ptlog.PTLog{LogTag: tag}

	if c.Address == "" {
		lg.Error("snowflake client requires a server address (ws:// or wss:// URL)")
		return false
	}

	skipTLSVerify := c.Insecure
	wsDialer := SfStandalone.WebSocketDialer(c.Proxy, skipTLSVerify)
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

	if reverseAddr != "" {
		go snowflakeRunReverse(lg, dialWS, c.Listen, reverseAddr, skipUDP)
		lg.InfoDelayed(time.Second, "snowflake reverse-tag", c.ReverseTag, "remote listen", c.Listen)
		return true
	}

	listen := dpiOrDefault(c.Listen, "127.0.0.1:1080")
	ln, udp, bound, err := dualbind.Listen(listen)
	if err != nil {
		lg.Error("snowflake listen:", err)
		return false
	}
	lg.InfoDelayed(time.Second, "Client started listening", bound, "forward via snowflake")
	go snowflakeRunForward(lg, dialWS, ln, udp)
	return true
}

func snowflakeRunForward(lg ptlog.PTLog, dialWS func() (net.Conn, error), ln net.Listener, udp *net.UDPConn) {
	for {
		sess, closer, err := SfStandalone.NewClientSession(SfStandalone.WrapWebSocketDial(dialWS))
		if err != nil {
			lg.Error("snowflake session:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		muxpipe.RunForwardClient(sess, ln, udp)
		_ = sess.Close()
		if closer != nil {
			_ = closer.Close()
		}
		time.Sleep(time.Second)
	}
}

func snowflakeRunReverse(lg ptlog.PTLog, dialWS func() (net.Conn, error), listen, reverseAddr string, skipUDP bool) {
	for {
		sess, closer, err := SfStandalone.NewClientSession(SfStandalone.WrapWebSocketDial(dialWS))
		if err != nil {
			lg.Error("snowflake session:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		bound, err := muxpipe.RequestReverseBind(sess, listen)
		if err != nil || bound == "" {
			lg.Error("snowflake reverse bind:", err)
			_ = sess.Close()
			if closer != nil {
				_ = closer.Close()
			}
			time.Sleep(2 * time.Second)
			continue
		}
		lg.Info("snowflake reverse published on", bound, "->", reverseAddr)
		muxpipe.RunReverseClient(sess, reverseAddr, skipUDP)
		_ = sess.Close()
		if closer != nil {
			_ = closer.Close()
		}
		time.Sleep(time.Second)
	}
}
