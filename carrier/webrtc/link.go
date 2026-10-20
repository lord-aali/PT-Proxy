package webrtc

import (
	"fmt"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
	pion "github.com/pion/webrtc/v4"
)

const maxMessage = 60 * 1024

// Link is a core.FrameConn over one WebRTC data channel. Each SCTP message is
// one encrypted carrier frame, so the outer ICE/DTLS/SCTP fingerprint stays intact.
type Link struct {
	dc       *pion.DataChannel
	enc      *core.Encryptor
	padMax   int
	jitter   time.Duration
	readWait time.Duration

	mu     sync.Mutex
	queue  [][]byte
	closed bool
	notify chan struct{}
}

func newLink(dc *pion.DataChannel, enc *core.Encryptor, padMax int, jitter time.Duration) *Link {
	l := &Link{
		dc:     dc,
		enc:    enc,
		padMax: padMax,
		jitter: jitter,
		notify: make(chan struct{}, 1),
	}
	dc.OnMessage(func(msg pion.DataChannelMessage) {
		if msg.IsString || len(msg.Data) == 0 {
			return
		}
		b := append([]byte(nil), msg.Data...)
		l.mu.Lock()
		if !l.closed {
			l.queue = append(l.queue, b)
		}
		l.mu.Unlock()
		select {
		case l.notify <- struct{}{}:
		default:
		}
	})
	dc.OnClose(func() { l.shutdown() })
	return l
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
	if l.dc != nil {
		return l.dc.Close()
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
	if len(ct) > maxMessage {
		return fmt.Errorf("webrtc frame too large")
	}
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	return l.dc.Send(ct)
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
					return core.Frame{}, fmt.Errorf("webrtc read timeout")
				}
				select {
				case <-l.notify:
				case <-time.After(remain):
					return core.Frame{}, fmt.Errorf("webrtc read timeout")
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
