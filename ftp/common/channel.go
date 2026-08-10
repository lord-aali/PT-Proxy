// Package common — persistent channel I/O, hello, and port ranges.
package common

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DirUpload   byte = 'u'
	DirDownload byte = 'd'

	PathUpload   = "out"
	PathDownload = "in"

	MaxBatchWire = 4 * 1024 * 1024
)

// Hello is the first message on each persistent data channel.
type Hello struct {
	Token string
	Dir   byte
	Index uint16
}

func EncodeHello(h Hello) []byte {
	tb := []byte(h.Token)
	out := make([]byte, 1+len(tb)+1+2)
	out[0] = byte(len(tb))
	copy(out[1:], tb)
	out[1+len(tb)] = h.Dir
	binary.BigEndian.PutUint16(out[1+len(tb)+1:], h.Index)
	return out
}

func DecodeHello(data []byte) (Hello, error) {
	if len(data) < 1 {
		return Hello{}, fmt.Errorf("hello too short")
	}
	n := int(data[0])
	if len(data) < 1+n+1+2 {
		return Hello{}, fmt.Errorf("hello truncated")
	}
	return Hello{
		Token: string(data[1 : 1+n]),
		Dir:   data[1+n],
		Index: binary.BigEndian.Uint16(data[1+n+1:]),
	}, nil
}

// WriteBatch writes a length-prefixed AES-GCM batch to w.
func WriteBatch(w io.Writer, frames []*Frame, key []byte) error {
	blob, err := EncodeBatch(frames, key)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(blob)
	return err
}

// ReadBatch reads one length-prefixed AES-GCM batch from r.
func ReadBatch(r io.Reader, key []byte) ([]*Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxBatchWire {
		return nil, fmt.Errorf("invalid batch length %d", n)
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(r, blob); err != nil {
		return nil, err
	}
	return DecodeBatch(blob, key)
}

// WriteHello sends a TypeHello frame as a single batch.
func WriteHello(w io.Writer, h Hello, key []byte) error {
	return WriteBatch(w, []*Frame{{Type: TypeHello, Data: EncodeHello(h)}}, key)
}

// ReadHello reads and validates the first hello batch.
func ReadHello(r io.Reader, key []byte) (Hello, error) {
	frames, err := ReadBatch(r, key)
	if err != nil {
		return Hello{}, err
	}
	if len(frames) != 1 || frames[0].Type != TypeHello {
		return Hello{}, fmt.Errorf("expected hello frame")
	}
	return DecodeHello(frames[0].Data)
}

// Channel is a persistent encrypted stream (one physical TCP per direction index).
type Channel struct {
	writeMu sync.Mutex
	conn    net.Conn
	key     []byte
	dir     byte
	idx     uint16
}

func WrapChannel(conn net.Conn, key []byte, dir byte, idx uint16) *Channel {
	return &Channel{conn: conn, key: key, dir: dir, idx: idx}
}

func (c *Channel) Dir() byte      { return c.dir }
func (c *Channel) Index() uint16  { return c.idx }
func (c *Channel) Conn() net.Conn { return c.conn }

func (c *Channel) WriteFrames(frames []*Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("channel closed")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	err := WriteBatch(c.conn, frames, c.key)
	_ = c.conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *Channel) ReadFrames() ([]*Frame, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("channel closed")
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	frames, err := ReadBatch(c.conn, c.key)
	_ = c.conn.SetReadDeadline(time.Time{})
	return frames, err
}

func (c *Channel) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// MaybeTLSClient wraps conn with TLS if enabled (InsecureSkipVerify always true).
func MaybeTLSClient(conn net.Conn, useTLS bool, serverName string) (net.Conn, error) {
	if !useTLS {
		return conn, nil
	}
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// MaybeTLSServer wraps conn with TLS if cfg != nil.
func MaybeTLSServer(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	if cfg == nil {
		return conn, nil
	}
	tc := tls.Server(conn, cfg)
	if err := tc.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// ─── Port ranges ──────────────────────────────────────────────────────────────

type PortRange struct {
	Lo, Hi int
}

func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PortRange{}, fmt.Errorf("empty port range")
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return PortRange{}, fmt.Errorf("invalid port range %q", s)
		}
		return PortRange{Lo: lo, Hi: hi}, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return PortRange{}, fmt.Errorf("invalid port %q", s)
	}
	return PortRange{Lo: p, Hi: p}, nil
}

func (r PortRange) Single() bool { return r.Lo == r.Hi }

func (r PortRange) String() string {
	if r.Single() {
		return strconv.Itoa(r.Lo)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// ListenInRange binds 0.0.0.0 to a free port in r (random start for ranges).
func ListenInRange(r PortRange) (net.Listener, int, error) {
	if r.Single() {
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", r.Lo))
		if err != nil {
			return nil, 0, err
		}
		return ln, r.Lo, nil
	}
	n := r.Hi - r.Lo + 1
	start := int(time.Now().UnixNano() % int64(n))
	for i := 0; i < n; i++ {
		p := r.Lo + (start+i)%n
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
		if err == nil {
			return ln, p, nil
		}
	}
	return nil, 0, fmt.Errorf("no free port in %s", r)
}
