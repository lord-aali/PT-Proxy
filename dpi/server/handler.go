package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/dpi/common"
)

const dialTimeout = 30 * time.Second

type tunnelHandler struct {
	server *Server
}

func newTunnelHandler(s *Server) *tunnelHandler {
	return &tunnelHandler{server: s}
}

// muxSession holds a shared downlink for stream-mode clients.
type muxSession struct {
	id      string
	mu      sync.Mutex
	writer  http.ResponseWriter
	flusher http.Flusher
	ready   chan struct{}
	closed  bool
}

func (s *Server) getOrCreateSession(id string) *muxSession {
	s.sessLock.Lock()
	defer s.sessLock.Unlock()
	if sess, ok := s.sessions[id]; ok {
		return sess
	}
	sess := &muxSession{id: id, ready: make(chan struct{})}
	s.sessions[id] = sess
	return sess
}

func (s *Server) removeSession(id string) {
	s.sessLock.Lock()
	delete(s.sessions, id)
	s.sessLock.Unlock()
}

func (ms *muxSession) attach(w http.ResponseWriter, f http.Flusher) {
	ms.mu.Lock()
	ms.writer = w
	ms.flusher = f
	ms.mu.Unlock()
	select {
	case <-ms.ready:
	default:
		close(ms.ready)
	}
}

func (ms *muxSession) writeFrame(encryptor *common.Encryptor, plaintext []byte) error {
	<-ms.ready
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.closed || ms.writer == nil {
		return io.ErrClosedPipe
	}
	encrypted, err := encryptor.EncryptStream(plaintext)
	if err != nil {
		return err
	}
	if err := common.WriteLengthPrefixed(ms.writer, encrypted); err != nil {
		return err
	}
	ms.flusher.Flush()
	return nil
}

func (ms *muxSession) close() {
	ms.mu.Lock()
	ms.closed = true
	ms.mu.Unlock()
}

// handleTunnel handles one-shot POST uploads.
func (h *tunnelHandler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", 400)
		return
	}
	r.Body.Close()

	if len(body) == 0 {
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	decrypted, err := h.server.encryptor.DecryptStream(body)
	if err != nil {
		h.server.log.Error("Decrypt error:", err)
		http.Error(w, "Bad Request", 400)
		return
	}
	h.dispatchPlain(w, decrypted, "", true)
}

// handleStreamUpload reads length-prefixed encrypted frames from a long POST body.
func (h *tunnelHandler) handleStreamUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionID := r.Header.Get("X-Session-Id")
	if sessionID == "" {
		http.Error(w, "Bad Request", 400)
		return
	}
	_ = h.server.getOrCreateSession(sessionID)

	// HTTP/1.1 handlers must opt into reading the request body after writing
	// the response; without this the POST body never arrives and stream hangs.
	_ = http.NewResponseController(w).EnableFullDuplex()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	for {
		enc, err := common.ReadLengthPrefixed(r.Body)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				h.server.log.Error("stream upload read:", err)
			}
			break
		}
		decrypted, err := h.server.encryptor.DecryptStream(enc)
		if err != nil {
			h.server.log.Error("stream decrypt:", err)
			continue
		}
		h.dispatchPlain(nil, decrypted, sessionID, false)
	}
}

func (h *tunnelHandler) dispatchPlain(w http.ResponseWriter, decrypted []byte, sessionID string, writeHTTP bool) {
	hdr, payload, err := common.ParseStreamHeader(decrypted)
	if err != nil {
		if writeHTTP && w != nil {
			http.Error(w, "Bad Request", 400)
		}
		return
	}
	if int(hdr.PayloadLen) > len(payload) {
		if writeHTTP && w != nil {
			http.Error(w, "Bad Request", 400)
		}
		return
	}
	payload = payload[:hdr.PayloadLen]

	switch hdr.MsgType {
	case common.MsgConnect:
		req, err := common.DecodeConnectRequest(payload)
		if err != nil {
			h.server.log.Error("Decode connect:", err)
			if writeHTTP && w != nil {
				http.Error(w, "Bad Request", 400)
			}
			return
		}
		h.server.log.Info("Connect ->", req.Address)
		h.handleConnect(w, hdr.ConnID, req, sessionID, writeHTTP)
	case common.MsgData:
		conn := h.server.getClient(hdr.ConnID)
		if conn == nil {
			if writeHTTP && w != nil {
				w.Write([]byte(`{"status":"ok"}`))
			}
			return
		}
		if _, err := conn.remote.Write(payload); err != nil {
			h.server.log.Error("Write to target failed connID="+fmt.Sprintf("%d", hdr.ConnID)+":", err)
			conn.remote.Close()
			h.server.unregisterClient(hdr.ConnID)
		}
		if writeHTTP && w != nil {
			w.Write([]byte(`{"status":"ok"}`))
		}
	case common.MsgClose:
		conn := h.server.getClient(hdr.ConnID)
		if conn != nil {
			conn.remote.Close()
			h.server.unregisterClient(hdr.ConnID)
		}
		if writeHTTP && w != nil {
			w.Write([]byte(`{"status":"ok"}`))
		}
	default:
		if writeHTTP && w != nil {
			w.Write([]byte(`{"status":"ok"}`))
		}
	}
}

func (h *tunnelHandler) handleConnect(w http.ResponseWriter, connID uint32, req *common.ConnectRequest, sessionID string, writeHTTP bool) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	remote, err := dialer.Dial(req.Network, req.Address)
	if err != nil {
		h.server.log.Error("Dial", req.Network, req.Address+":", err)
		if writeHTTP && w != nil {
			w.Write([]byte(`{"status":"error","msg":"connect failed"}`))
		}
		if sessionID != "" {
			sess := h.server.getOrCreateSession(sessionID)
			plain := common.BuildStreamHeader(common.MsgClose, connID, 0)
			_ = sess.writeFrame(h.server.encryptor, plain)
		}
		return
	}

	var sess *muxSession
	if sessionID != "" {
		sess = h.server.getOrCreateSession(sessionID)
	}

	cc := &clientConn{
		connID:     connID,
		remote:     remote,
		server:     h.server,
		targetAddr: req.Address,
		dataCh:     make(chan []byte, 16),
		session:    sess,
	}
	h.server.registerClient(connID, cc)

	go func() {
		defer h.server.unregisterClient(connID)
		defer remote.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				if cc.session != nil {
					plain := append(common.BuildStreamHeader(common.MsgData, connID, uint32(len(data))), data...)
					if err := cc.session.writeFrame(h.server.encryptor, plain); err != nil {
						break
					}
				} else {
					select {
					case cc.dataCh <- data:
					case <-h.server.stopCh:
						return
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					h.server.log.Error("Read error from", cc.targetAddr, "(connID="+fmt.Sprintf("%d", connID)+"):", err)
				}
				break
			}
		}
		if cc.session != nil {
			plain := common.BuildStreamHeader(common.MsgClose, connID, 0)
			_ = cc.session.writeFrame(h.server.encryptor, plain)
		} else {
			close(cc.dataCh)
		}
	}()

	if writeHTTP && w != nil {
		w.Write([]byte(`{"status":"ok","conn_id":` + fmt.Sprintf("%d", connID) + `}`))
	}
}

// handleSessionDownload is the shared mux downlink for stream mode.
func (h *tunnelHandler) handleSessionDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	sessionID := strings.TrimPrefix(r.URL.Path, "/download/session/")
	if sessionID == "" {
		sessionID = r.Header.Get("X-Session-Id")
	}
	if sessionID == "" {
		http.Error(w, "Not Found", 404)
		return
	}

	sess := h.server.getOrCreateSession(sessionID)
	_ = http.NewResponseController(w).EnableFullDuplex()
	filename := randomFilename()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", 500)
		return
	}
	flusher.Flush()
	sess.attach(w, flusher)
	h.server.log.Info("Session download", sessionID)

	<-r.Context().Done()
	sess.close()
	h.server.removeSession(sessionID)
}

// handleDownload streams encrypted data to the client for one connID.
func (h *tunnelHandler) handleDownload(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/download/session/") {
		h.handleSessionDownload(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	connIDStr := strings.TrimPrefix(r.URL.Path, "/download/")
	if connIDStr == "" {
		http.Error(w, "Not Found", 404)
		return
	}

	var connID uint32
	if _, err := fmt.Sscanf(connIDStr, "%d", &connID); err != nil {
		http.Error(w, "Not Found", 404)
		return
	}

	conn := h.server.getClient(connID)
	if conn == nil {
		http.Error(w, "Not Found", 404)
		return
	}
	h.server.log.Info("Download connID="+fmt.Sprintf("%d", connID), "->", conn.targetAddr)

	filename := randomFilename()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", 500)
		return
	}
	flusher.Flush()

	for {
		select {
		case data, ok := <-conn.dataCh:
			if !ok {
				return
			}
			payload := append(
				common.BuildStreamHeader(common.MsgData, connID, uint32(len(data))),
				data...,
			)
			encrypted, err := h.server.encryptor.EncryptStream(payload)
			if err != nil {
				return
			}
			if err := common.WriteLengthPrefixed(w, encrypted); err != nil {
				return
			}
			flusher.Flush()
		case <-h.server.stopCh:
			return
		case <-r.Context().Done():
			return
		}
	}
}

type clientConn struct {
	connID     uint32
	remote     net.Conn
	server     *Server
	targetAddr string
	dataCh     chan []byte
	session    *muxSession
}
