package client

import (
	"io"
	"net"
	"sync"

	"github.com/lord-aali/PT-Proxy/common/ptlog"
)

// TunnelConn represents a connection tunneled through the HTTP proxy.
type TunnelConn struct {
	connID    uint32
	transport *Transport
	local     net.Conn
	log       ptlog.PTLog
	closeOnce sync.Once
	closeCh   chan struct{}
}

// NewTunnelConn creates a tunneled connection.
func NewTunnelConn(transport *Transport, connID uint32, local net.Conn, lg ptlog.PTLog) *TunnelConn {
	return &TunnelConn{
		connID:    connID,
		transport: transport,
		local:     local,
		log:       lg,
		closeCh:   make(chan struct{}),
	}
}

// Run starts the bidirectional data pump.
func (tc *TunnelConn) Run() {
	go tc.pumpLocalToServer()
	tc.pumpServerToLocal()
}

func (tc *TunnelConn) pumpLocalToServer() {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-tc.closeCh:
			return
		default:
		}
		n, err := tc.local.Read(buf)
		if n > 0 {
			if err := tc.transport.SendData(tc.connID, buf[:n]); err != nil {
				tc.log.Error("SendData error:", err)
				tc.Close()
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				tc.log.Error("Local read error:", err)
			}
			tc.Close()
			return
		}
	}
}

func (tc *TunnelConn) pumpServerToLocal() {
	defer tc.Close()
	stream, err := tc.transport.DownloadStream(nil, tc.connID)
	if err != nil {
		tc.log.Error("DownloadStream error:", err)
		return
	}
	defer stream.Close()
	io.Copy(tc.local, stream)
}

// Close closes the tunnel connection.
func (tc *TunnelConn) Close() {
	tc.closeOnce.Do(func() {
		close(tc.closeCh)
		tc.transport.CloseConn(tc.connID)
		tc.local.Close()
	})
}
