package common

import (
	"encoding/binary"
	"fmt"
)

// EncodeConnectRequest encodes a ConnectRequest for transmission.
func EncodeConnectRequest(req *ConnectRequest) []byte {
	netBytes := []byte(req.Network)
	addrBytes := []byte(req.Address)
	// format: networkLen(2) | network | addrLen(2) | addr
	size := 2 + len(netBytes) + 2 + len(addrBytes)
	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(netBytes)))
	off += 2
	copy(buf[off:], netBytes)
	off += len(netBytes)
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(addrBytes)))
	off += 2
	copy(buf[off:], addrBytes)
	return buf
}

// DecodeConnectRequest decodes a ConnectRequest.
func DecodeConnectRequest(data []byte) (*ConnectRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("payload too short")
	}
	netLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < 4+int(netLen) {
		return nil, fmt.Errorf("invalid network length")
	}
	network := string(data[2 : 2+netLen])
	off := int(2 + netLen)
	addrLen := binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	if len(data) < off+int(addrLen) {
		return nil, fmt.Errorf("invalid address length")
	}
	address := string(data[off : off+int(addrLen)])
	return &ConnectRequest{Network: network, Address: address}, nil
}
