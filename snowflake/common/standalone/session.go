package standalone

import (
	"context"
	"io"
	"log"
	"net"
	"time"

	"github.com/lord-aali/PT-Proxy/snowflake/common/socks5"
	"github.com/lord-aali/PT-Proxy/snowflake/common/turbotunnel"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type dummyAddr struct{}

func (dummyAddr) Network() string { return "dummy" }
func (dummyAddr) String() string  { return "dummy" }

type sessionCloser struct {
	closers []io.Closer
}

func (s *sessionCloser) Close() error {
	var first error
	for _, c := range s.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// NewClientSession builds a KCP/smux client session over turbotunnel WebSockets.
func NewClientSession(dialPacket func(ctx context.Context) (net.PacketConn, error)) (*smux.Session, io.Closer, error) {
	pconn := turbotunnel.NewRedialPacketConn(dummyAddr{}, dummyAddr{}, dialPacket)
	conn, err := kcp.NewConn2(dummyAddr{}, nil, 0, 0, pconn)
	if err != nil {
		pconn.Close()
		return nil, nil, err
	}
	configureKCP(conn)
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = 10 * time.Minute
	sess, err := smux.Client(conn, smuxConfig)
	if err != nil {
		conn.Close()
		pconn.Close()
		return nil, nil, err
	}
	return sess, &sessionCloser{closers: []io.Closer{conn, pconn}}, nil
}

// WrapWebSocketDial returns dialPacket that writes turbotunnel token + clientID.
func WrapWebSocketDial(dialWS func() (net.Conn, error)) func(context.Context) (net.PacketConn, error) {
	clientID := turbotunnel.NewClientID()
	return func(ctx context.Context) (net.PacketConn, error) {
		raw, err := dialWS()
		if err != nil {
			return nil, err
		}
		if _, err := raw.Write(turbotunnel.Token[:]); err != nil {
			raw.Close()
			return nil, err
		}
		if _, err := raw.Write(clientID[:]); err != nil {
			raw.Close()
			return nil, err
		}
		return NewEncapsulationPacketConn(dummyAddr{}, dummyAddr{}, raw), nil
	}
}

func configureKCP(conn *kcp.UDPSession) {
	conn.SetStreamMode(true)
	conn.SetWindowSize(65535, 65535)
	conn.SetNoDelay(0, 0, 0, 1)
}

func handleInboundStream(stream net.Conn, cfg SessionConfig) {
	defer stream.Close()
	streamType, target, err := ReadTarget(stream)
	if err != nil {
		log.Printf("ReadTarget: %v", err)
		return
	}
	switch streamType {
	case StreamCaps:
		mode := byte(0)
		if cfg.ExternalService != "" {
			mode = 1
		}
		_, _ = stream.Write([]byte{mode})
	case StreamClientDial:
		dialAddr := target.Addr()
		dialNet := target.Network
		if cfg.ExternalService != "" {
			dialAddr = cfg.ExternalService
			dialNet = "tcp"
		}
		remote, err := net.Dial(dialNet, dialAddr)
		if err != nil {
			log.Printf("dial %s: %v", dialAddr, err)
			return
		}
		defer remote.Close()
		CopyLoop(stream, remote)
	case StreamServerDial:
		log.Printf("unexpected StreamServerDial on server")
	case StreamForward:
		if cfg.ServerForwardSocks == "" {
			return
		}
		remote, err := net.Dial("tcp", cfg.ServerForwardSocks)
		if err != nil {
			log.Printf("forward to server socks: %v", err)
			return
		}
		defer remote.Close()
		CopyLoop(stream, remote)
	default:
		log.Printf("unknown stream type %d", streamType)
	}
}

// RunStreamAcceptor accepts streams initiated by the peer.
func RunStreamAcceptor(sess *smux.Session, cfg SessionConfig) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			log.Printf("AcceptStream: %v", err)
			return
		}
		go handleInboundStream(stream, cfg)
	}
}

// OpenClientDial requests the server dial target and returns the data stream.
func OpenClientDial(sess *smux.Session, target socks5.Target) (net.Conn, error) {
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := WriteTarget(stream, StreamClientDial, target); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

// OpenForward requests a bridge to the server's SOCKS port.
func OpenForward(sess *smux.Session) (net.Conn, error) {
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if err := WriteTarget(stream, StreamForward, socks5.Target{}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

// ProbeCaps asks the server if it is in external mode. Old servers: standalone.
func ProbeCaps(sess *smux.Session) bool {
	stream, err := sess.OpenStream()
	if err != nil {
		return false
	}
	defer stream.Close()
	if err := WriteTarget(stream, StreamCaps, socks5.Target{}); err != nil {
		return false
	}
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var mode [1]byte
	if _, err := io.ReadFull(stream, mode[:]); err != nil {
		return false
	}
	return mode[0] == 1
}
