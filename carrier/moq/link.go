package moq

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/Eyevinn/moqtransport"
	"github.com/lord-aali/PT-Proxy/carrier/core"
)

// Link is a core.FrameConn over one MoQ subscription in each direction.
// Each object payload is one encrypted carrier frame, so the QUIC and MoQT
// framing on the wire stays a normal media session.
type Link struct {
	sg       *moqtransport.Subgroup
	pub      moqtransport.Publisher
	track    *moqtransport.RemoteTrack
	enc      *core.Encryptor
	padMax   int
	jitter   time.Duration
	readWait time.Duration
	closeFn  func()

	writeMu sync.Mutex
	nextObj uint64

	mu     sync.Mutex
	queue  [][]byte
	closed bool
	notify chan struct{}
}

func newLink(sg *moqtransport.Subgroup, pub moqtransport.Publisher, track *moqtransport.RemoteTrack, enc *core.Encryptor, padMax int, jitter time.Duration, closeFn func()) *Link {
	return &Link{
		sg:      sg,
		pub:     pub,
		track:   track,
		enc:     enc,
		padMax:  padMax,
		jitter:  jitter,
		closeFn: closeFn,
		notify:  make(chan struct{}, 1),
	}
}

func (l *Link) readLoop() {
	for {
		obj, err := l.track.ReadObject(context.Background())
		if err != nil {
			l.shutdown()
			return
		}
		if obj == nil || len(obj.Payload) == 0 {
			continue
		}
		b := append([]byte(nil), obj.Payload...)
		l.mu.Lock()
		if !l.closed {
			l.queue = append(l.queue, b)
		}
		l.mu.Unlock()
		select {
		case l.notify <- struct{}{}:
		default:
		}
	}
}

func (l *Link) shutdown() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	select {
	case l.notify <- struct{}{}:
	default:
	}
}

func (l *Link) Close() error {
	l.shutdown()
	if l.sg != nil {
		_ = l.sg.Close()
	}
	if l.pub != nil {
		_ = l.pub.CloseWithError(0, "closed")
	}
	if l.track != nil {
		_ = l.track.Close()
	}
	if l.closeFn != nil {
		l.closeFn()
	}
	return nil
}

func (l *Link) WriteFrame(f core.Frame) error {
	pad := 0
	if l.padMax > 0 {
		pad = rand.Intn(l.padMax + 1)
	}
	plain, err := core.EncodeFramePadded(f, pad)
	if err != nil {
		return err
	}
	ct, err := l.enc.Encrypt(plain)
	if err != nil {
		return err
	}
	if len(ct) > core.MaxCipherLen {
		return fmt.Errorf("moq frame too large")
	}
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	id := l.nextObj
	l.nextObj++
	_, err = l.sg.WriteObject(id, ct)
	return err
}

func (l *Link) ReadFrame() (core.Frame, error) {
	wait := l.readWait
	var deadline time.Time
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}
	for {
		l.mu.Lock()
		for len(l.queue) == 0 && !l.closed {
			l.mu.Unlock()
			if wait > 0 {
				remain := time.Until(deadline)
				if remain <= 0 {
					return core.Frame{}, fmt.Errorf("moq read timeout")
				}
				select {
				case <-l.notify:
				case <-time.After(remain):
					return core.Frame{}, fmt.Errorf("moq read timeout")
				}
			} else {
				<-l.notify
			}
			l.mu.Lock()
		}
		if len(l.queue) == 0 && l.closed {
			l.mu.Unlock()
			return core.Frame{}, io.EOF
		}
		ct := l.queue[0]
		l.queue = l.queue[1:]
		l.mu.Unlock()

		plain, err := l.enc.Decrypt(ct)
		if err != nil {
			continue
		}
		return core.DecodeFrame(plain)
	}
}
