package cns

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
)

// XorCrypt performs streaming XOR encryption/decryption.
// CNS uses password-byte XOR with position mixing (data[i] ^= password[pi] | byte(pi)).
func XorCrypt(data []byte, password []byte, passwordSub int) int {
	for i := 0; i < len(data); i++ {
		data[i] ^= password[passwordSub] | byte(passwordSub)
		passwordSub++
		if passwordSub == len(password) {
			passwordSub = 0
}
	}
	return passwordSub
}

// EncryptHost encrypts a host string for the CNS Host header.
// Format: base64(xor(host + "\x00")).
func EncryptHost(host string, password []byte) string {
	plain := []byte(host)
	// Append null terminator
	plain = append(plain, 0)
	enc := make([]byte, len(plain))
	copy(enc, plain)
	XorCrypt(enc, password, 0)
	return base64.StdEncoding.EncodeToString(enc)
}

// Buffer pools for reuse
var (
	udpBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
},
	}
)

// BuildUDPPacket constructs a httpUDP packet.
// Protocol: 2 bytes length (including header) + header + payload.
// IPv4 header: 12 bytes (fields: 0,0,0,1 at offset 2-5, IP at 6-9, port at 10-11).
// IPv6 header: 24 bytes (fields: 0,0,0,3 at offset 2-5, IP at 6-21, port at 22-23).
func BuildUDPPacket(destination M.Socksaddr, data []byte) []byte {
	var headerLen int
	pkt := udpBufferPool.Get().([]byte)

	if destination.IsIPv6() && !destination.IsIPv4() {
		headerLen = 24
	} else {
		headerLen = 12
}

	pktLen := headerLen + len(data)
	pkt[0] = byte(pktLen)
	pkt[1] = byte(pktLen >> 8)

	// Reserved + ATYP
	pkt[2] = 0
	pkt[3] = 0

	addrPort := destination.AddrPort()

	if destination.IsIPv6() && !destination.IsIPv4() {
		// IPv6 code: 0, 3
		pkt[4] = 0
		pkt[5] = 3
		copy(pkt[6:22], addrPort.Addr().AsSlice())
		pkt[22] = byte(addrPort.Port() >> 8)
		pkt[23] = byte(addrPort.Port())
	} else {
		// IPv4 code: 0, 1
		pkt[4] = 0
		pkt[5] = 1
		ip := addrPort.Addr().As4()
		copy(pkt[6:10], ip[:])
		pkt[10] = byte(addrPort.Port() >> 8)
		pkt[11] = byte(addrPort.Port())
	}

	copy(pkt[headerLen:], data)
	return pkt[:pktLen]
}

// ParseUDPResponse parses a httpUDP response packet.
// Returns the destination address and payload.
func ParseUDPResponse(data []byte) (M.Socksaddr, []byte, error) {
	if len(data) < 12 {
		return M.Socksaddr{}, nil, fmt.Errorf("packet too short: %d", len(data))
	}

	pkgLen := binary.LittleEndian.Uint16(data[0:2])
	if int(pkgLen) > len(data) {
		return M.Socksaddr{}, nil, fmt.Errorf("packet length mismatch: declared %d, actual %d", pkgLen, len(data))
}

	var addr netip.Addr
	var port uint16
	var headerLen int

	// Check fields at offset 2-5
	atyp := data[5]
	if atyp == 1 {
		// IPv4
		headerLen = 12
		if len(data) < headerLen {
			return M.Socksaddr{}, nil, fmt.Errorf("IPv4 packet too short")
		}
		addr = netip.AddrFrom4([4]byte{data[6], data[7], data[8], data[9]})
		port = binary.BigEndian.Uint16(data[10:12])
	} else if atyp == 3 {
		// IPv6
		headerLen = 24
		if len(data) < headerLen {
			return M.Socksaddr{}, nil, fmt.Errorf("IPv6 packet too short")
					}
		addr = netip.AddrFrom16([16]byte{
			data[6], data[7], data[8], data[9],
			data[10], data[11], data[12], data[13],
			data[14], data[15], data[16], data[17],
			data[18], data[19], data[20], data[21],
		})
		port = binary.BigEndian.Uint16(data[22:24])
	} else {
		return M.Socksaddr{}, nil, fmt.Errorf("unknown ATYP: %d", atyp)
	}

	return M.SocksaddrFromNetIP(netip.AddrPortFrom(addr, port)), data[headerLen:int(pkgLen)], nil
}
