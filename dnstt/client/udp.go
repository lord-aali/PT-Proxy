package client

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lord-aali/PT-Proxy/dnstt/turbotunnel"
)

const (
	// A few long-lived sockets, not one socket per query. dnstt sends on a
	// single UDP socket and reads the reply whenever it arrives. A per-query
	// deadline was throwing those replies away once the server took more
	// than a couple of seconds, which made KCP retransmit into sendq.
	fanoutSockets  = 4
	fanoutReadSize = 4096
)

// fanoutConn sends DNS queries on a small set of connected UDP sockets so the
// source port is not a single value, and keeps those sockets open for the
// whole session. WriteTo returns as soon as the datagram is queued. Replies
// are delivered to ReadFrom with no query timeout.
type fanoutConn struct {
	remote *net.UDPAddr
	conns  []*net.UDPConn
	next   atomic.Uint32

	incoming chan []byte

	closeOnce sync.Once
	closed    chan struct{}
}

func newFanout(addr string) (*fanoutConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	f := &fanoutConn{
		remote:   ua,
		incoming: make(chan []byte, turbotunnel.QueueSize),
		closed:   make(chan struct{}),
	}
	for i := 0; i < fanoutSockets; i++ {
		c, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			f.Close()
			return nil, err
		}
		f.conns = append(f.conns, c)
		go f.readLoop(c)
	}
	return f, nil
}

func (f *fanoutConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(f.conns) == 0 {
		return 0, net.ErrClosed
	}
	c := f.conns[f.next.Add(1)%uint32(len(f.conns))]
	return c.Write(p)
}

func (f *fanoutConn) readLoop(c *net.UDPConn) {
	buf := make([]byte, fanoutReadSize)
	for {
		n, err := c.Read(buf)
		if err != nil {
			select {
			case <-f.closed:
				return
			default:
			}
			if n == 0 {
				continue
			}
		}
		if n == 0 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case <-f.closed:
			return
		case f.incoming <- pkt:
		default:
		}
	}
}

func (f *fanoutConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-f.closed:
		return 0, nil, net.ErrClosed
	case pkt := <-f.incoming:
		n := copy(p, pkt)
		return n, f.remote, nil
	}
}

func (f *fanoutConn) Close() error {
	f.closeOnce.Do(func() {
		close(f.closed)
		for _, c := range f.conns {
			c.Close()
		}
	})
	return nil
}

func (f *fanoutConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (f *fanoutConn) SetDeadline(time.Time) error      { return nil }
func (f *fanoutConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fanoutConn) SetWriteDeadline(time.Time) error { return nil }
