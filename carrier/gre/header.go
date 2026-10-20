package gre

import (
	"encoding/binary"
	"fmt"
)

// RFC 2784 / RFC 2890 flags. Key + sequence is the usual keyed-tunnel shape.
const (
	flagChecksum uint16 = 0x8000
	flagRouting  uint16 = 0x4000
	flagKey      uint16 = 0x2000
	flagSeq      uint16 = 0x1000
	verMask      uint16 = 0x0007

	protoIPv4  uint16 = 0x0800 // payload type used by ordinary GRE tunnels
	ipProtoGRE byte   = 47
)

// Packet is one GRE datagram. Payload is the encrypted carrier frame.
type Packet struct {
	Key      uint32
	Seq      uint32
	HasKey   bool
	HasSeq   bool
	Protocol uint16
	Payload  []byte
}

// Encode builds a GRE header with key and sequence, protocol IPv4 (0x0800).
func Encode(key, seq uint32, payload []byte) []byte {
	out := make([]byte, 12+len(payload))
	binary.BigEndian.PutUint16(out[0:2], flagKey|flagSeq)
	binary.BigEndian.PutUint16(out[2:4], protoIPv4)
	binary.BigEndian.PutUint32(out[4:8], key)
	binary.BigEndian.PutUint32(out[8:12], seq)
	copy(out[12:], payload)
	return out
}

// Decode parses a GRE header. Routing (source-route) is rejected.
// Optional checksum is skipped; it is not verified (middleboxes rarely require it).
func Decode(b []byte) (Packet, error) {
	var p Packet
	if len(b) < 4 {
		return p, fmt.Errorf("gre short")
	}
	flags := binary.BigEndian.Uint16(b[0:2])
	if flags&verMask != 0 {
		return p, fmt.Errorf("gre version %d", flags&verMask)
	}
	if flags&flagRouting != 0 {
		return p, fmt.Errorf("gre routing not supported")
	}
	p.Protocol = binary.BigEndian.Uint16(b[2:4])
	off := 4
	if flags&flagChecksum != 0 {
		if len(b) < off+4 {
			return p, fmt.Errorf("gre checksum truncated")
		}
		off += 4
	}
	if flags&flagKey != 0 {
		if len(b) < off+4 {
			return p, fmt.Errorf("gre key truncated")
		}
		p.HasKey = true
		p.Key = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
	}
	if flags&flagSeq != 0 {
		if len(b) < off+4 {
			return p, fmt.Errorf("gre seq truncated")
		}
		p.HasSeq = true
		p.Seq = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
	}
	if off > len(b) {
		return p, fmt.Errorf("gre header overrun")
	}
	p.Payload = b[off:]
	return p, nil
}

// Body returns the GRE datagram inside pkt. Raw IP sockets on some platforms
// deliver the IPv4 header as well; when the first bytes are IPv4 protocol 47,
// that header is stripped.
func Body(pkt []byte) []byte {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return pkt
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl || pkt[9] != ipProtoGRE {
		return pkt
	}
	return pkt[ihl:]
}
