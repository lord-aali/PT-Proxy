package dualbind

import (
	"fmt"
	"log"
	"net"
)

// Listen opens TCP and UDP on the same host:port. Port 0 is assigned from the
// TCP bind, then UDP uses that port. If UDP bind fails, TCP still works and
// the failure is logged.
func Listen(addr string) (ln net.Listener, udp *net.UDPConn, bound string, err error) {
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, "", err
	}
	bound = ln.Addr().String()
	ua, rerr := net.ResolveUDPAddr("udp", bound)
	if rerr != nil {
		log.Printf("dualbind: UDP resolve %s: %v (TCP-only)", bound, rerr)
		return ln, nil, bound, nil
	}
	udp, err = net.ListenUDP("udp", ua)
	if err != nil {
		log.Printf("dualbind: UDP listen %s: %v (TCP-only)", bound, err)
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
