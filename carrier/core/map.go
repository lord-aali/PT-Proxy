package core

import "strings"

// DPI wire message types (dpi/common) mapped to/from core frames.
const (
	DPIMsgConnect     byte = 0x01
	DPIMsgData        byte = 0x02
	DPIMsgClose       byte = 0x03
	DPIMsgUDPAssoc    byte = 0x04
	DPIMsgUDPPacket   byte = 0x05
	DPIMsgReverseBind byte = 0x07
	DPIMsgReverseOpen byte = 0x09
)

// FTP wire types (ftp/common) mapped to/from core frames.
const (
	FTPTypeData        byte = 0x01
	FTPTypeOpen        byte = 0x02
	FTPTypeClose       byte = 0x03
	FTPTypeUDPData     byte = 0x07
	FTPTypeDNSReq      byte = 0x08
	FTPTypeDNSResp     byte = 0x09
	FTPTypeHello       byte = 0x0A
	FTPTypeReverseBind byte = 0x0B
	FTPTypeReverseOpen byte = 0x0C
)

// DPIToCore maps a DPI stream message into a core frame.
// Connect payload is "tcp\x00host:port" or "udp\x00host:port" style via network+address.
func DPIToCore(msgType byte, connID uint32, payload []byte, network string) Frame {
	switch msgType {
	case DPIMsgConnect:
		if strings.EqualFold(network, "udp") {
			return Frame{Type: TypeOpenUDP, ConnID: connID, Data: payload}
		}
		return Frame{Type: TypeOpenTCP, ConnID: connID, Data: payload}
	case DPIMsgData, DPIMsgUDPPacket:
		return Frame{Type: TypeData, ConnID: connID, Data: payload}
	case DPIMsgClose:
		return Frame{Type: TypeClose, ConnID: connID}
	case DPIMsgReverseBind:
		return Frame{Type: TypeReverseBind, ConnID: connID, Data: payload}
	default:
		return Frame{Type: TypePad, ConnID: connID, Data: payload}
	}
}

// CoreToDPI maps a core frame to DPI msg type + payload.
func CoreToDPI(f Frame) (msgType byte, connID uint32, payload []byte) {
	connID = f.ConnID
	payload = f.Data
	switch f.Type {
	case TypeData:
		msgType = DPIMsgData
	case TypeClose:
		msgType = DPIMsgClose
	case TypeReverseOpen:
		msgType = DPIMsgReverseOpen
	case TypeOpenTCP, TypeOpenUDP:
		msgType = DPIMsgConnect
	case TypeReverseBind:
		msgType = DPIMsgReverseBind
	default:
		msgType = DPIMsgData
	}
	return
}

// FTPToCore maps an FTP frame type into a core frame.
// Open data is "tcp\x00addr" or "udp\x00addr".
func FTPToCore(ftpType byte, connID uint32, data []byte) Frame {
	switch ftpType {
	case FTPTypeHello:
		return Frame{Type: TypeHello, ConnID: connID, Data: data}
	case FTPTypeOpen:
		netw, addr := splitNetAddr(data)
		if netw == "udp" {
			return Frame{Type: TypeOpenUDP, ConnID: connID, Data: []byte(addr)}
		}
		return Frame{Type: TypeOpenTCP, ConnID: connID, Data: []byte(addr)}
	case FTPTypeData, FTPTypeUDPData:
		return Frame{Type: TypeData, ConnID: connID, Data: data}
	case FTPTypeClose:
		return Frame{Type: TypeClose, ConnID: connID}
	case FTPTypeDNSReq:
		return Frame{Type: TypeDNSReq, ConnID: connID, Data: data}
	case FTPTypeDNSResp:
		return Frame{Type: TypeDNSResp, ConnID: connID, Data: data}
	case FTPTypeReverseBind:
		return Frame{Type: TypeReverseBind, ConnID: connID, Data: data}
	case FTPTypeReverseOpen:
		return Frame{Type: TypeReverseOpen, ConnID: connID, Data: data}
	default:
		return Frame{Type: TypePad, ConnID: connID, Data: data}
	}
}

// CoreToFTP maps a core frame to FTP type + data.
func CoreToFTP(f Frame) (ftpType byte, connID uint32, data []byte) {
	connID = f.ConnID
	data = f.Data
	switch f.Type {
	case TypeHello:
		ftpType = FTPTypeHello
	case TypeHelloOK:
		ftpType = FTPTypeHello // reply treated as hello-ok at higher layer
	case TypeOpenTCP:
		ftpType = FTPTypeOpen
		data = append([]byte("tcp\x00"), data...)
	case TypeOpenUDP:
		ftpType = FTPTypeOpen
		data = append([]byte("udp\x00"), data...)
	case TypeData:
		ftpType = FTPTypeData
	case TypeClose:
		ftpType = FTPTypeClose
	case TypeDNSReq:
		ftpType = FTPTypeDNSReq
	case TypeDNSResp:
		ftpType = FTPTypeDNSResp
	case TypeReverseBind:
		ftpType = FTPTypeReverseBind
	case TypeReverseOpen:
		ftpType = FTPTypeReverseOpen
	default:
		ftpType = FTPTypeData
	}
	return
}

func splitNetAddr(data []byte) (network, addr string) {
	parts := strings.SplitN(string(data), "\x00", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "tcp", string(data)
}
