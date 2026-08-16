package standalone

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lord-aali/PT-Proxy/common/muxpipe"
	"github.com/lord-aali/PT-Proxy/snowflake/common/encapsulation"
	"github.com/lord-aali/PT-Proxy/snowflake/common/turbotunnel"
	"github.com/lord-aali/PT-Proxy/snowflake/common/websocketconn"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Upgrader for WebSocket connections.
var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

const clientMapTimeout = 1 * time.Minute

// Server runs the WebSocket turbotunnel server and KCP/smux accept loop.
type Server struct {
	pconn        *turbotunnel.QueuePacketConn
	smuxSessions map[turbotunnel.ClientID]*smux.Session
	smuxMu       sync.RWMutex
	Target       string
	SkipUDP      bool
}

// NewServer creates a standalone snowflake server.
func NewServer(addr *net.TCPAddr) (*Server, *http.Server, error) {
	s := &Server{
		pconn:        turbotunnel.NewQueuePacketConn(addr, clientMapTimeout),
		smuxSessions: make(map[turbotunnel.ClientID]*smux.Session),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serveHTTP)
	server := &http.Server{
		Addr:        addr.String(),
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
	}
	ln, err := kcp.ServeConn(nil, 0, 0, s.pconn)
	if err != nil {
		return nil, nil, err
	}
	go s.acceptKCP(ln)
	return s, server, nil
}

func (s *Server) acceptKCP(ln *kcp.Listener) {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			log.Printf("AcceptKCP: %v", err)
			return
		}
		configureKCP(conn)
		go s.acceptSmux(conn)
	}
}

func (s *Server) acceptSmux(conn *kcp.UDPSession) {
	defer conn.Close()
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = 10 * time.Minute
	sess, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Printf("smux.Server: %v", err)
		return
	}

	clientID, ok := conn.RemoteAddr().(turbotunnel.ClientID)
	if ok {
		s.smuxMu.Lock()
		if old, exists := s.smuxSessions[clientID]; exists {
			old.Close()
		}
		s.smuxSessions[clientID] = sess
		s.smuxMu.Unlock()
		defer func() {
			s.smuxMu.Lock()
			delete(s.smuxSessions, clientID)
			s.smuxMu.Unlock()
			sess.Close()
		}()
	}

	muxpipe.Serve(sess, s.Target, s.SkipUDP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	conn := websocketconn.New(ws)
	defer conn.Close()

	var token [len(turbotunnel.Token)]byte
	if _, err := io.ReadFull(conn, token[:]); err != nil {
		return
	}
	if !bytes.Equal(token[:], turbotunnel.Token[:]) {
		return
	}
	var clientID turbotunnel.ClientID
	if _, err := io.ReadFull(conn, clientID[:]); err != nil {
		return
	}

	errCh := make(chan error, 2)
	go func() {
		for {
			p, err := encapsulation.ReadData(conn)
			if err != nil {
				errCh <- err
				return
			}
			s.pconn.QueueIncoming(p, clientID)
		}
	}()
	go func() {
		bw := bufio.NewWriter(conn)
		for p := range s.pconn.OutgoingQueue(clientID) {
			_, err := encapsulation.WriteData(bw, p)
			if err == nil {
				err = bw.Flush()
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	<-errCh
}
