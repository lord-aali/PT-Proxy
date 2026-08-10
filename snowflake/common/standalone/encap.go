package standalone

import (
	"bufio"
	"errors"
	"io"
	"net"
	"time"

	"github.com/lord-aali/PT-Proxy/snowflake/common/encapsulation"
)

var errNotImplemented = errors.New("not implemented")

// EncapsulationPacketConn implements net.PacketConn over a stream.
type EncapsulationPacketConn struct {
	io.ReadWriteCloser
	localAddr  net.Addr
	remoteAddr net.Addr
	bw         *bufio.Writer
}

func NewEncapsulationPacketConn(localAddr, remoteAddr net.Addr, conn io.ReadWriteCloser) *EncapsulationPacketConn {
	return &EncapsulationPacketConn{
		ReadWriteCloser: conn,
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
		bw:              bufio.NewWriter(conn),
	}
}

func (c *EncapsulationPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data, err := encapsulation.ReadData(c.ReadWriteCloser)
	if err != nil {
		return 0, c.remoteAddr, err
	}
	return copy(p, data), c.remoteAddr, nil
}

func (c *EncapsulationPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	_, err := encapsulation.WriteData(c.bw, p)
	if err == nil {
		err = c.bw.Flush()
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *EncapsulationPacketConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *EncapsulationPacketConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *EncapsulationPacketConn) SetDeadline(t time.Time) error      { return errNotImplemented }
func (c *EncapsulationPacketConn) SetReadDeadline(t time.Time) error  { return errNotImplemented }
func (c *EncapsulationPacketConn) SetWriteDeadline(t time.Time) error { return errNotImplemented }
