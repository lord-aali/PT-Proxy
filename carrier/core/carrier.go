package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"time"
)

type Carrier interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// FrameConn is a bidirectional encrypted frame stream (TCP length-prefixed or UDP datagram).
type FrameConn interface {
	ReadFrame() (Frame, error)
	WriteFrame(Frame) error
	Close() error
}

type Link struct {
	rw     io.ReadWriteCloser
	enc    *Encryptor
	mu     sync.Mutex
	padMax int
	jitter time.Duration
}

func NewLink(rw io.ReadWriteCloser, enc *Encryptor, padMax int, jitter time.Duration) *Link {
	return &Link{rw: rw, enc: enc, padMax: padMax, jitter: jitter}
}

func (l *Link) Close() error { return l.rw.Close() }

func (l *Link) WriteFrame(f Frame) error {
	pad := 0
	if l.padMax > 0 {
		pad = rand.Intn(l.padMax + 1)
	}
	plain, err := EncodeFramePadded(f, pad)
	if err != nil {
		return err
	}
	ct, err := l.enc.Encrypt(plain)
	if err != nil {
		return err
	}
	if len(ct) > MaxCipherLen {
		return fmt.Errorf("cipher too large")
	}
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if _, err := l.rw.Write(hdr[:]); err != nil {
		return err
	}
	_, err = l.rw.Write(ct)
	return err
}

func (l *Link) ReadFrame() (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(l.rw, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxCipherLen {
		return Frame{}, fmt.Errorf("bad frame len %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(l.rw, buf); err != nil {
		return Frame{}, err
	}
	plain, err := l.enc.Decrypt(buf)
	if err != nil {
		return Frame{}, err
	}
	return DecodeFrame(plain)
}
