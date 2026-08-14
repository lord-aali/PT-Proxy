package client

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/lord-aali/PT-Proxy/dpi/common"
)

type muxSession struct {
	id        string
	tr        *Transport
	uplinkW   *io.PipeWriter
	uplinkErr atomic.Value // error
	mu        sync.Mutex
	pinned    map[uint32]struct{}
	readers   map[uint32]*connPipe
	closed    bool
}

type connPipe struct {
	ch     chan []byte
	closed chan struct{}
}

func (t *Transport) pickSession() (*muxSession, error) {
	t.sessMu.Lock()
	active := atomic.LoadInt32(&t.active)
	needSecond := active >= 8 && len(t.sessions) < maxSessions
	for _, s := range t.sessions {
		if s != nil && !s.isClosed() {
			if !needSecond || s.pinCount() < int(active)/2+1 {
				t.sessMu.Unlock()
				return s, nil
			}
		}
	}
	if len(t.sessions) >= maxSessions {
		for _, s := range t.sessions {
			if s != nil && !s.isClosed() {
				t.sessMu.Unlock()
				return s, nil
			}
		}
	}
	t.sessMu.Unlock()

	s, err := t.startSession()
	if err != nil {
		return nil, err
	}

	t.sessMu.Lock()
	defer t.sessMu.Unlock()
	if len(t.sessions) >= maxSessions {
		for _, existing := range t.sessions {
			if existing != nil && !existing.isClosed() {
				s.close()
				return existing, nil
			}
		}
	}
	t.sessions = append(t.sessions, s)
	return s, nil
}

func (t *Transport) sessionFor(connID uint32) *muxSession {
	t.sessMu.Lock()
	defer t.sessMu.Unlock()
	for _, s := range t.sessions {
		if s != nil && s.hasPin(connID) {
			return s
		}
	}
	return nil
}

func (t *Transport) maybeShrinkSessions() {
	t.sessMu.Lock()
	defer t.sessMu.Unlock()
	if len(t.sessions) <= 1 {
		return
	}
	kept := t.sessions[:0]
	for i, s := range t.sessions {
		if s == nil || s.isClosed() {
			continue
		}
		if i > 0 && s.pinCount() == 0 {
			s.close()
			continue
		}
		kept = append(kept, s)
	}
	t.sessions = kept
}

func (t *Transport) startSession() (*muxSession, error) {
	id := newSessionID()
	s := &muxSession{
		id:      id,
		tr:      t,
		pinned:  make(map[uint32]struct{}),
		readers: make(map[uint32]*connPipe),
	}

	downReady := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, t.baseURL+"/download/session/"+id, nil)
		if err != nil {
			downReady <- err
			return
		}
		t.setBrowserHeaders(req)
		req.Header.Del("Accept-Encoding")
		req.Header.Set("X-Session-Id", id)
		resp, err := t.httpClient.Do(req)
		if err != nil {
			downReady <- err
			return
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			downReady <- fmt.Errorf("session download status %d", resp.StatusCode)
			return
		}
		downReady <- nil
		defer resp.Body.Close()
		for {
			enc, err := common.ReadLengthPrefixed(resp.Body)
			if err != nil {
				s.close()
				return
			}
			dec, err := t.encryptor.Decrypt(enc)
			if err != nil {
				continue
			}
			hdr, payload, err := common.ParseStreamHeader(dec)
			if err != nil {
				continue
			}
			switch hdr.MsgType {
			case common.MsgData:
				if int(hdr.PayloadLen) > len(payload) {
					continue
				}
				data := make([]byte, hdr.PayloadLen)
				copy(data, payload[:hdr.PayloadLen])
				s.deliver(hdr.ConnID, data)
			case common.MsgClose:
				s.unpin(hdr.ConnID)
			}
		}
	}()

	if err := <-downReady; err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	s.uplinkW = pw
	go func() {
		req, err := http.NewRequest(http.MethodPost, t.baseURL+"/api/v2/stream", pr)
		if err != nil {
			pr.CloseWithError(err)
			s.fail(err)
			return
		}
		t.setBrowserHeaders(req)
		req.Header.Del("Accept-Encoding")
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("X-Session-Id", id)
		req.ContentLength = -1
		resp, err := t.httpClient.Do(req)
		if err != nil {
			s.fail(err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			s.fail(fmt.Errorf("stream uplink status %d", resp.StatusCode))
			return
		}
		s.close()
	}()

	return s, nil
}

func (s *muxSession) fail(err error) {
	s.uplinkErr.Store(err)
	s.close()
}

func (s *muxSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *muxSession) pinCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pinned)
}

func (s *muxSession) hasPin(connID uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pinned[connID]
	return ok
}

func (s *muxSession) pin(connID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned[connID] = struct{}{}
	if _, ok := s.readers[connID]; !ok {
		s.readers[connID] = &connPipe{ch: make(chan []byte, 32), closed: make(chan struct{})}
	}
}

func (s *muxSession) unpin(connID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pinned, connID)
	if p, ok := s.readers[connID]; ok {
		select {
		case <-p.closed:
		default:
			close(p.closed)
			close(p.ch)
		}
		delete(s.readers, connID)
	}
}

func (s *muxSession) writeEncrypted(encrypted []byte) error {
	if err, ok := s.uplinkErr.Load().(error); ok && err != nil {
		return err
	}
	s.mu.Lock()
	w := s.uplinkW
	closed := s.closed
	s.mu.Unlock()
	if closed || w == nil {
		return io.ErrClosedPipe
	}
	return common.WriteLengthPrefixed(w, encrypted)
}

func (s *muxSession) openConnReader(connID uint32) io.ReadCloser {
	s.mu.Lock()
	p, ok := s.readers[connID]
	if !ok {
		p = &connPipe{ch: make(chan []byte, 32), closed: make(chan struct{})}
		s.readers[connID] = p
		s.pinned[connID] = struct{}{}
	}
	s.mu.Unlock()
	return &demuxReader{pipe: p}
}

func (s *muxSession) deliver(connID uint32, data []byte) {
	s.mu.Lock()
	p := s.readers[connID]
	s.mu.Unlock()
	if p == nil {
		return
	}
	select {
	case p.ch <- data:
	case <-p.closed:
	}
}

func (s *muxSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	w := s.uplinkW
	s.uplinkW = nil
	for id, p := range s.readers {
		select {
		case <-p.closed:
		default:
			close(p.closed)
			close(p.ch)
		}
		delete(s.readers, id)
	}
	s.pinned = map[uint32]struct{}{}
	s.mu.Unlock()
	if w != nil {
		w.Close()
	}
}

type demuxReader struct {
	pipe   *connPipe
	buf    []byte
	closed bool
}

func (d *demuxReader) Read(p []byte) (int, error) {
	if len(d.buf) > 0 {
		n := copy(p, d.buf)
		d.buf = d.buf[n:]
		return n, nil
	}
	select {
	case data, ok := <-d.pipe.ch:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			d.buf = data[n:]
		}
		return n, nil
	case <-d.pipe.closed:
		return 0, io.EOF
	}
}

func (d *demuxReader) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	return nil
}
