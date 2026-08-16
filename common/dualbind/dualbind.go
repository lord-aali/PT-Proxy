package dualbind

import (
	"fmt"
	"net"
)

// Listen opens TCP and UDP on the same host:port. Port 0 is assigned from the
// TCP bind, then UDP uses that port. If UDP bind fails, TCP still works.
func Listen(addr string) (ln net.Listener, udp *net.UDPConn, bound string, err error) {
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, "", err
	}
	bound = ln.Addr().String()
	ua, rerr := net.ResolveUDPAddr("udp", bound)
	if rerr != nil {
		return ln, nil, bound, nil
	}
	udp, err = net.ListenUDP("udp", ua)
	if err != nil {
		return ln, nil, bound, nil
	}
	return ln, udp, bound, nil
}

func MustListen(addr string) (net.Listener, *net.UDPConn, string, error) {
	ln, udp, bound, err := Listen(addr)
	if err != nil {
		return nil, nil, "", err
	}
	if ln == nil {
		return nil, nil, "", fmt.Errorf("listen %s: no tcp", addr)
	}
	return ln, udp, bound, nil
}
