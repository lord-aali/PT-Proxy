package gre

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/carrier/core"
)

const maxPayload = 60 * 1024

// Raw sockets on loopback deliver a copy of each transmitted GRE packet back
// to the sender. Client sequence numbers are odd and server numbers are even,
// so each side drops its own echo without relying on the bytes matching.
const (
	roleAny    = 0
	roleClient = 1
	roleServer = 2
)

// Link is a core.FrameConn over GRE datagrams. Each datagram is one encrypted frame.
type Link struct {
	pc        net.PacketConn
	remote    net.Addr
	enc       *core.Encryptor
	key       uint32
	seq       atomic.Uint32
	padMax    int
	jitter    time.Duration
	wmu       sync.Mutex
	inbox     chan []byte
	owned     bool
	connected bool
	readWait  time.Duration
	role      int
}

func NewLink(pc net.PacketConn, remote net.Addr, enc *core.Encryptor, key uint32, padMax int, jitter time.Duration, owned, connected bool) *Link {
	return &Link{
		pc: pc, remote: remote, enc: enc, key: key,
		padMax: padMax, jitter: jitter, owned: owned, connected: connected,
	}
}

func (l *Link) Close() error {
	if l.owned && l.pc != nil {
		return l.pc.Close()
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
	if len(ct) > maxPayload {
		return fmt.Errorf("gre frame too large")
	}
	pkt := Encode(l.key, l.nextSeq(), ct)
	if l.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(l.jitter) + 1)))
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if l.connected {
		_, err = l.pc.(interface{ Write([]byte) (int, error) }).Write(pkt)
		return err
	}
	if l.remote == nil {
		return io.ErrClosedPipe
	}
	_, err = l.pc.WriteTo(pkt, l.remote)
	return err
}

func (l *Link) ReadFrame() (core.Frame, error) {
	for {
		var ct []byte
		if l.inbox != nil {
			b, ok := <-l.inbox
			if !ok {
				return core.Frame{}, io.EOF
			}
			ct = b
		} else {
			buf := make([]byte, 65535)
			wait := l.readWait
			if wait <= 0 {
				wait = 5 * time.Minute
			}
			_ = l.pc.SetReadDeadline(time.Now().Add(wait))
			var n int
			var err error
			if l.connected {
				n, err = l.pc.(interface{ Read([]byte) (int, error) }).Read(buf)
			} else {
				var addr net.Addr
				n, addr, err = l.pc.ReadFrom(buf)
				if err == nil && l.remote == nil {
					l.remote = addr
				}
			}
			if err != nil {
				return core.Frame{}, err
			}
			p, err := Decode(Body(buf[:n]))
			if err != nil || !p.HasKey || p.Key != l.key || l.isOwn(p) {
				continue
			}
			ct = p.Payload
		}
		plain, err := l.enc.Decrypt(ct)
		if err != nil {
			if l.inbox != nil {
				return core.Frame{}, err
			}
			continue
		}
		return core.DecodeFrame(plain)
	}
}

func (l *Link) nextSeq() uint32 {
	n := l.seq.Add(1)
	switch l.role {
	case roleClient:
		return n*2 - 1
	case roleServer:
		return n * 2
	default:
		return n
	}
}

func (l *Link) isOwn(p Packet) bool {
	if !p.HasSeq {
		return false
	}
	switch l.role {
	case roleClient:
		return p.Seq%2 == 1
	case roleServer:
		return p.Seq%2 == 0
	default:
		return false
	}
}
