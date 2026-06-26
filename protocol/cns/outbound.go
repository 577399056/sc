package cns

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
    E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.CNSOutboundOptions](registry, C.TypeCNS, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	dialer          N.Dialer
	tlsDialer       tls.Dialer
	tlsConfig       tls.Config
	serverAddr      M.Socksaddr
	password        string
	xorPassword     []byte
	proxyKey        string
	udpFlag         string
	udpEnabled      bool
	udpTCPBuffer    int
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CNSOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	outbound := &Outbound{
		Adapter:     outbound.NewAdapterWithDialerOptions(C.TypeCNS, tag, options.Network.Build(), options.DialerOptions),
logger:      logger,
		dialer:      outboundDialer,
		serverAddr:  options.ServerOptions.Build(),
		password:    options.Password,
		xorPassword: []byte(options.Password),
		proxyKey:    options.ProxyKey,
		udpFlag:     options.UDPFlag,
		udpEnabled:  common.Contains(options.Network.Build(), N.NetworkUDP),
	}

	// Set defaults
	if outbound.proxyKey == "" {
		outbound.proxyKey = "Host"
	}
	if outbound.udpFlag == "" {
		outbound.udpFlag = "httpUDP"
	}

	// Setup TLS if configured
	if options.TLS != nil && options.TLS.Enabled {
	outbound.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:       ctx,
			Logger:        logger,
			ServerAddress: options.Server,
			Options:       common.PtrValueOrDefault(options.TLS),
		})
		if err != nil {
			return nil, err
		}
		outbound.tlsDialer = tls.NewDialer(outboundDialer, outbound.tlsConfig)
	}

	return outbound, nil
}

func (c *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
metadata.Outbound = c.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		c.logger.InfoContext(ctx, "outbound connection to ", destination)
		return c.dialTCP(ctx, destination)
	case N.NetworkUDP:
		if !c.udpEnabled {
			return nil, os.ErrInvalid
		}
		c.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := c.dialUDP(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
		default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (c *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !c.udpEnabled {
		return nil, os.ErrInvalid
	}
	c.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return c.dialUDP(ctx)
}

func (c *Outbound) InterfaceUpdated() {
	// No persistent state to reset for CNS
}

func (c *Outbound) Close() error {
	return nil
}

// dialTCP establishes a TCP connection to the CNS server and requests a TCP tunnel.
func (c *Outbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	var conn net.Conn
	var err error

	if c.tlsDialer != nil {
		conn, err = c.tlsDialer.DialTLSContext(ctx, c.serverAddr)
	} else {
		conn, err = c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	}
	if err != nil {
		return nil, err
	}

	// Build the CNS CONNECT request
	hostPort := destination.String()
	// Encrypt host if password is set
	var proxyHostValue string
	if len(c.xorPassword) != 0 {
		hostBytes := []byte(hostPort + "\x00")
		cuteBiXorCrypt(hostBytes, c.xorPassword, 0)
		proxyHostValue = base64.StdEncoding.EncodeToString(hostBytes)
	} else {
		proxyHostValue = hostPort
	}

	// CONNECT request with custom proxy_key header
	// Note: CNS getProxyHost parses from proxy_key position, so the value
	// includes the ": " prefix. CNS net.Dial handles this correctly.
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n%s: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n",
		hostPort, c.proxyKey, proxyHostValue)

	_, err = conn.Write([]byte(req))
if err != nil {
		conn.Close()
		return nil, err
	}

	// Read response - CNS returns "HTTP/1.1 200 Connection established\r\n..."
	respBuf := make([]byte, 128)
	n, err := conn.Read(respBuf)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "read CNS response")
	}
	resp := string(respBuf[:n])
	if !strings.Contains(resp, "200") {
		conn.Close()
		return nil, E.New("CNS proxy error: ", resp)
	}

	return newCNSConn(conn, c.xorPassword, 0, 0), nil
}

// dialUDP establishes a connection for UDP transport via CNS httpUDP protocol.
func (c *Outbound) dialUDP(ctx context.Context) (net.PacketConn, error) {
	var conn net.Conn
	var err error

	if c.tlsDialer != nil {
		conn, err = c.tlsDialer.DialTLSContext(ctx, c.serverAddr)
	} else {
		conn, err = c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
	}
	if err != nil {
		return nil, err
	}

	// Build CNS UDP tunnel request with httpUDP flag
	hostPort := "127.0.0.1:0" // Dummy target - CNS recognizes UDP by the header flag
	var proxyHostValue string
	if len(c.xorPassword) != 0 {
hostBytes := []byte(hostPort + "\x00")
		cuteBiXorCrypt(hostBytes, c.xorPassword, 0)
		proxyHostValue = base64.StdEncoding.EncodeToString(hostBytes)
	} else {
		proxyHostValue = hostPort
	}

	req := fmt.Sprintf("GET /%s HTTP/1.1\r\n%s: %s\r\n\r\n",
		c.udpFlag, c.proxyKey, proxyHostValue)

	_, err = conn.Write([]byte(req))
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read response
	respBuf := make([]byte, 128)
	n, err := conn.Read(respBuf)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "read CNS UDP response")
		}
	if !strings.Contains(string(respBuf[:n]), "200") {
		conn.Close()
		return nil, E.New("CNS UDP proxy error: ", string(respBuf[:n]))
	}

	return newCNSUDPConn(conn, c.xorPassword, 0, 0), nil
}

// --- CuteBi XOR Crypt ---

// cuteBiXorCrypt implements the CuteBi XOR encryption with per-byte position mixing.
// The original algorithm: data[i] ^= password[passwordSub] | byte(passwordSub)
// This ensures password "12" ≠ password "1212"
func cuteBiXorCrypt(data []byte, password []byte, passwordSub int) int {
for dataSub := 0; dataSub < len(data); {
		data[dataSub] ^= password[passwordSub] | byte(passwordSub)
		dataSub++
		passwordSub++
		if passwordSub == len(password) {
			passwordSub = 0
		}
	}
	return passwordSub
}

// --- CNS TCP Connection (with XOR support) ---

type cnsConn struct {
	net.Conn
	xorPassword []byte
	readSub     int
	writeSub    int
}

func newCNSConn(conn net.Conn, xorPassword []byte, readSub, writeSub int) *cnsConn {
	return &cnsConn{
		Conn:        conn,
		xorPassword: xorPassword,
		readSub:     readSub,
		writeSub:    writeSub,
	}
}

// xorReadWriter wraps a net.Conn to apply XOR on raw Read/Write calls
// when no buffered reader is being used.

func (c *cnsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	if len(c.xorPassword) != 0 && n > 0 {
		c.readSub = cuteBiXorCrypt(b[:n], c.xorPassword, c.readSub)
	}
	return n, err
}

func (c *cnsConn) Write(b []byte) (int, error) {
	if len(c.xorPassword) != 0 {
		data := make([]byte, len(b))
copy(data, b)
		c.writeSub = cuteBiXorCrypt(data, c.xorPassword, c.writeSub)
		return c.Conn.Write(data)
	}
	return c.Conn.Write(b)
}

// Upstream returns the underlying connection.
func (c *cnsConn) Upstream() any {
	return c.Conn
}

// --- CNS UDP Packet Connection (httpUDP protocol) ---

type cnsUDPConn struct {
	net.Conn
	xorPassword []byte
	readSub     int
	writeSub    int
	mu          sync.Mutex
}

func newCNSUDPConn(conn net.Conn, xorPassword []byte, readSub, writeSub int) *cnsUDPConn {
return &cnsUDPConn{
		Conn:        conn,
		xorPassword: xorPassword,
		readSub:     readSub,
		writeSub:    writeSub,
	}
}

// ReadFrom reads a httpUDP packet from the CNS server.
// Packet format exactly matches CNS udp.go serverToClient:
//
//	byte[0:2]  = total_len (payload bytes + header overhead) 16-bit LE
//	byte[2:4]  = 0x00 0x00 (reserved)
//	byte[4]    = 0x00 (fragment, must be 0)
//	byte[5]    = address type (1=IPv4, 3=IPv6)
//	byte[6:10] = IPv4 address / byte[6:22] = IPv6 address
//	byte[10:12]= port (IPv4) / byte[22:24] = port (IPv6)
//	byte[12:]  = UDP payload (IPv4) / byte[24:] = UDP payload (IPv6)
func (c *cnsUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	// Read 2-byte length prefix
	lenBuf := make([]byte, 2)
	_, err = c.Conn.Read(lenBuf)
	if err != nil {
		return 0, nil, err
	}
	if len(c.xorPassword) != 0 {
		c.readSub = cuteBiXorCrypt(lenBuf, c.xorPassword, c.readSub)
	}
	pktLen := int(lenBuf[0]) | (int(lenBuf[1]) << 8)
	if pktLen < 10 {
		return 0, nil, E.New("invalid httpUDP packet length: ", pktLen)
}

	// Read the rest of the packet (pktLen bytes total, we already read 2)
	bodyLen := pktLen - 2
	readLen := 0
	for readLen < bodyLen {
		nr, readErr := c.Conn.Read(b[readLen:bodyLen])
		if readErr != nil {
			return 0, nil, readErr
		}
		readLen += nr
	}
	if readLen > len(b) {
		// Should not happen given pktLen check above
		readLen = len(b)
	}
	if len(c.xorPassword) != 0 {
		c.readSub = cuteBiXorCrypt(b[:readLen], c.xorPassword, c.readSub)
	}

	// Validate reserved bytes and fragment
	if readLen < 5 {
	return 0, nil, E.New("httpUDP packet too short")
	}
	if b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return 0, nil, E.New("invalid httpUDP reserved/fragment bytes")
	}

	addrType := b[3]
	var payloadStart int
	if addrType == 1 { // IPv4
		payloadStart = 10
	} else if addrType == 3 { // IPv6
		payloadStart = 22
	} else {
		return 0, nil, E.New("unsupported httpUDP address type: ", addrType)
	}

	if readLen < payloadStart {
		return 0, nil, E.New("httpUDP packet truncated")
	}

	payloadLen := readLen - payloadStart
if payloadLen > 0 {
		copy(b, b[payloadStart:readLen])
	}
	n = payloadLen

	// Parse address
	if addrType == 1 {
		ip := net.IPv4(b[4], b[5], b[6], b[7])
		port := int(b[8])<<8 | int(b[9])
		addr = &net.UDPAddr{IP: ip, Port: port}
	} else {
		ip := net.IP(b[4:20])
		port := int(b[20])<<8 | int(b[21])
		addr = &net.UDPAddr{IP: ip, Port: port}
	}

	return n, addr, nil
}

// WriteTo sends a httpUDP packet to the CNS server.
// Packet format exactly matches CNS udp.go writeToServer parsing:
//
//	byte[0:2]  = pktLen (2+reserved+frag+type+addr+port+payload) 16-bit LE
//	byte[2:4]  = 0x00 0x00 (reserved, MUST be 0)
//	byte[4]    = 0x00 (fragment, MUST be 0)
//	byte[5]    = address type (1=IPv4, 3=IPv6)
//	byte[6:10] = IPv4 address / byte[6:22] = IPv6 address
//	byte[10:12]= port (IPv4) / byte[22:24] = port (IPv6)
//	byte[12:]  = UDP payload (IPv4) / byte[24:] = UDP payload (IPv6)
func (c *cnsUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("unsupported address type: ", addr.Network())
	}
c.mu.Lock()
	defer c.mu.Unlock()

	var headerLen int
	if udpAddr.IP.To4() != nil {
		headerLen = 12 // 2(len) + 2(rsvd) + 1(frag) + 1(type) + 4(ip) + 2(port)
	} else {
		headerLen = 24 // 2(len) + 2(rsvd) + 1(frag) + 1(type) + 16(ip) + 2(port)
	}

	totalLen := headerLen + len(b)
	buf := make([]byte, totalLen)

	// Length field = 2 reserved + 1 fragment + 1 type + addr_len + payload_len
	// CNS writeToServer subtracts 2 from pkgLen check: pkgLen > 10
	// So pkgLen covers: [2:rsrv] + [4:frag] + [5:type] + [addr] + [port] + [payload]
pktLen := totalLen - 2 // subtract the 2 reserved bytes
	buf[0] = byte(pktLen)
	buf[1] = byte(pktLen >> 8)

	// Reserved + fragment (MUST be 0, CNS checks them)
	buf[2] = 0
	buf[3] = 0
	buf[4] = 0

	if udpAddr.IP.To4() != nil {
		buf[5] = 1 // IPv4
		copy(buf[6:10], udpAddr.IP.To4())
		buf[10] = byte(udpAddr.Port >> 8)
		buf[11] = byte(udpAddr.Port)
		copy(buf[12:], b)
	} else {
		buf[5] = 3 // IPv6
		copy(buf[6:22], udpAddr.IP.To16())
		buf[22] = byte(udpAddr.Port >> 8)
		buf[23] = byte(udpAddr.Port)
		copy(buf[24:], b)
	}

	if len(c.xorPassword) != 0 {
		// XOR the entire packet including length prefix (matching CNS serverToClient)
		c.writeSub = cuteBiXorCrypt(buf, c.xorPassword, c.writeSub)
	}

	_, err := c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *cnsUDPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *cnsUDPConn) Write(b []byte) (int, error) {
	// UDP bound connections should use WriteTo, but for compatibility
// we just write raw bytes (not recommended)
	return c.Conn.Write(b)
}

func (c *cnsUDPConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *cnsUDPConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *cnsUDPConn) Close() error {
	return c.Conn.Close()
}

// ReadPacket reads a packet into a buf.Buffer (N.PacketReader interface).
func (c *cnsUDPConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := c.ReadFrom(buffer.FreeBytes())
	if err != nil {
			return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr), nil
}

// WritePacket writes a packet from a buf.Buffer (N.PacketWriter interface).
func (c *cnsUDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

// Ensure it implements N.NetPacketConn
var _ N.NetPacketConn = (*cnsUDPConn)(nil)
