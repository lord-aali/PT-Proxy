package core

import (
	"fmt"
	"net"
	"time"
)

func ResolveDNS(network, upstream string, query []byte) ([]byte, error) {
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	if network == "" {
		network = "udp"
	}
	c, err := net.DialTimeout(network, upstream, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if network == "tcp" {
		var hdr [2]byte
		hdr[0] = byte(len(query) >> 8)
		hdr[1] = byte(len(query))
		if _, err := c.Write(hdr[:]); err != nil {
			return nil, err
		}
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	if network == "tcp" {
		var hdr [2]byte
		if _, err := ioReadFull(c, hdr[:]); err != nil {
			return nil, err
		}
		n := int(hdr[0])<<8 | int(hdr[1])
		if n <= 0 || n > len(buf) {
			return nil, fmt.Errorf("bad dns tcp len")
		}
		out := make([]byte, n)
		if _, err := ioReadFull(c, out); err != nil {
			return nil, err
		}
		return out, nil
	}
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

func ioReadFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := r.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
