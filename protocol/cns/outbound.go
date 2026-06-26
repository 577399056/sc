package cns

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
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
	logger       logger.ContextLogger
	dialer       N.Dialer
	tlsDialer    tls.Dialer
	tlsConfig    tls.Config
	serverAddr   M.Socksaddr
	password     string
	xorPassword  []byte
	proxyKey     string
	udpFlag      string
	udpEnabled   bool
	udpTCPBuffer int
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CNSOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeCNS, tag, options.Network.Build(), options.DialerOptions),
logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
		password:   options.Password,
		xorPassword: []byte(options.Password),
		proxyKey:   options.ProxyKey,
		udpFlag:    options.UDPFlag,
		udpEnabled: common.Contains(options.Network.Build(), N.NetworkUDP),
	}

	if outbound.proxyKey == "" {
		outbound.proxyKey = "Host"
	}
	if outbound.udpFlag == "" {
		outbound.udpFlag = "httpUDP"
	}

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

func (c *Outbound) InterfaceUpdated() {}

func (c *Outbound) Close() error {
	return nil
}

// dialTCP establishes a TCP connection to the CNS server and requests a TCP tunnel.
func (c *Outbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
conn, err := c.dialCNS(ctx)
	if err != nil {
		return nil, err
	}

	hostPort := destination.String()
	var proxyHostValue string
	if len(c.xorPassword) != 0 {
		hostBytes := []byte(hostPort + "\x00")
		cuteBiXorCrypt(hostBytes, c.xorPassword, 0)
		proxyHostValue = base64.StdEncoding.EncodeToString(hostBytes)
	} else {
		proxyHostValue = hostPort
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n%s: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n",
		hostPort, c.proxyKey, proxyHostValue)

	if _, err = conn.Write([]byte(req)); err != nil {
	conn.Close()
		return nil, err
	}

	// Read response — must read exactly up to \r\n\r\n to avoid eating payload
	resp, err := readHTTPHeader(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "read CNS response")
	}
	if !strings.Contains(resp, "200") {
		conn.Close()
		return nil, E.New("CNS proxy error: ", resp)
	}

	return newCNSConn(conn, c.xorPassword, 0, 0), nil
}

// dialUDP establishes a connection for UDP transport via CNS httpUDP protocol.
func (c *Outbound) dialUDP(ctx context.Context) (net.PacketConn, error) {
conn, err := c.dialCNS(ctx)
	if err != nil {
		return nil, err
	}

	hostPort := "127.0.0.1:0"
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

	if _, err = conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response exactly up to \r\n\r\n boundary
	resp, err := readHTTPHeader(conn)
	if err != nil {
		conn.Close()
		return nil, E.Cause(err, "read CNS UDP response")
	}
	if !strings.Contains(resp, "200") {
		conn.Close()
		return nil, E.New("CNS UDP proxy error: ", resp)
	}

	return newCNSUDPConn(conn, c.xorPassword, 0, 0), nil
}

// dialCNS opens a TCP or TLS connection to the CNS server.
func (c *Outbound) dialCNS(ctx context.Context) (net.Conn, error) {
	if c.tlsDialer != nil {
return c.tlsDialer.DialTLSContext(ctx, c.serverAddr)
	}
	return c.dialer.DialContext(ctx, N.NetworkTCP, c.serverAddr)
}

// readHTTPHeader reads bytes from conn until \r\n\r\n is found.
// It reads one byte at a time to avoid consuming data past the header boundary.
func readHTTPHeader(conn net.Conn) (string, error) {
	var buf bytes.Buffer
	prev := [4]byte{}
	for {
		var b [1]byte
		_, err := conn.Read(b[:])
		if err != nil {
			return buf.String(), err
		}
		buf.WriteByte(b[0])
		prev[0], prev[1], prev[2], prev[3] = prev[1], prev[2], prev[3], b[0]
		if prev == [4]byte{'\r', '\n', '\r', '\n'} {
			return buf.String(), nil
		}
	}
}

// --- CuteBi XOR Crypt ---

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

// --- CNS TCP Connection ---

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

func (c *cnsConn) Upstream() any {
	return c.Conn
}

// --- CNS UDP Packet Connection ---

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
// Packet format matching CNS udp.go serverToClient:
//
//	[0:2]  = total_len (LE uint16)
//	[2:4]  = reserved (0x00 0x00)
//	[4]    = fragment (0x00)
//	[5]    = addr type (1=IPv4, 3=IPv6)
//	[6:10] = IPv4 / [6:22] = IPv6
//	[10:12] = port (BE) / [22:24] = port (BE)
//	[12:]  = payload / [24:] = payload
func (c *cnsUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
     lenBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	if len(c.xorPassword) != 0 {
		c.readSub = cuteBiXorCrypt(lenBuf[:], c.xorPassword, c.readSub)
	}
	pktLen := int(lenBuf[0]) | int(lenBuf[1])<<8
	if pktLen < 10 {
		return 0, nil, E.New("invalid httpUDP packet length: ", pktLen)
	}

	bodyLen := pktLen - 2
	// Guard against corrupted data or buffer overflow.
	// cap(b) is the definitive limit: slicing past cap panics.
	if bodyLen > len(b) || bodyLen > cap(b) {
return 0, nil, E.New("httpUDP packet larger than buffer: ", bodyLen, " > ", len(b), "/", cap(b))
	}
	// Read the body portion; slice extends b up to bodyLen.
	body := b[:bodyLen]
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return 0, nil, err
	}
	if len(c.xorPassword) != 0 {
		c.readSub = cuteBiXorCrypt(body, c.xorPassword, c.readSub)
	}

	if bodyLen < 5 {
		return 0, nil, E.New("httpUDP packet too short")
	}
	if body[0] != 0 || body[1] != 0 || body[2] != 0 {
		return 0, nil, E.New("invalid httpUDP reserved/fragment bytes")
}

	addrType := body[3]
	var payloadStart int
	if addrType == 1 {
		payloadStart = 10
	} else if addrType == 3 {
		payloadStart = 22
	} else {
		return 0, nil, E.New("unsupported httpUDP address type: ", addrType)
	}
	if bodyLen < payloadStart {
		return 0, nil, E.New("httpUDP packet truncated")
	}

	payloadLen := bodyLen - payloadStart
	var parsedAddr net.Addr
	if addrType == 1 {
		parsedAddr = &net.UDPAddr{
			IP:   net.IPv4(body[4], body[5], body[6], body[7]),
			Port: int(body[8])<<8 | int(body[9]),
}
	} else {
		parsedAddr = &net.UDPAddr{
			IP:   net.IP(append([]byte{}, body[4:20]...)),
			Port: int(body[20])<<8 | int(body[21]),
		}
	}

	if payloadLen > 0 {
		copy(b, body[payloadStart:])
	}
	return payloadLen, parsedAddr, nil
}

// WriteTo sends a httpUDP packet to the CNS server.
// Packet format matching CNS udp.go writeToServer parsing:
//
//	[0:2]  = pktLen (LE uint16, covers bytes 2..end)
//	[2:4]  = reserved (0x00 0x00)
//	[4]    = fragment (0x00)
//	[5]    = addr type (1=IPv4, 3=IPv6)
//	[6:10] = IPv4 / [6:22] = IPv6
//	[10:12] = port (BE) / [22:24] = port (BE)
//	[12:]  = payload / [24:] = payload
func (c *cnsUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("unsupported address type: ", addr.Network())
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var headerLen int
	if udpAddr.IP.To4() != nil {
		headerLen = 12
	} else {
		headerLen = 24
	}

	totalLen := headerLen + len(b)
	buf := make([]byte, totalLen)
	pktLen := totalLen - 2
	buf[0] = byte(pktLen)
	buf[1] = byte(pktLen >> 8)
	buf[2] = 0
	buf[3] = 0
	buf[4] = 0

	if udpAddr.IP.To4() != nil {
		buf[5] = 1
		copy(buf[6:10], udpAddr.IP.To4())
		buf[10] = byte(udpAddr.Port >> 8)
		buf[11] = byte(udpAddr.Port)
		copy(buf[12:], b)
	} else {
		buf[5] = 3
		copy(buf[6:22], udpAddr.IP.To16())
		buf[22] = byte(udpAddr.Port >> 8)
		buf[23] = byte(udpAddr.Port)
		copy(buf[24:], b)
	}

	if len(c.xorPassword) != 0 {
		c.writeSub = cuteBiXorCrypt(buf, c.xorPassword, c.writeSub)
	}
if _, err := c.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read allows use as io.Reader. Delegates to ReadFrom and discards the address.
func (c *cnsUDPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *cnsUDPConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *cnsUDPConn) LocalAddr() net.Addr  { return c.Conn.LocalAddr() }
func (c *cnsUDPConn) RemoteAddr() net.Addr { return c.Conn.RemoteAddr() }
func (c *cnsUDPConn) Close() error         { return c.Conn.Close() }
// ReadPacket satisfies N.PacketReader.
func (c *cnsUDPConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := c.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr), nil
}

// WritePacket satisfies N.PacketWriter.
func (c *cnsUDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_, err := c.WriteTo(buffer.Bytes(), destination.UDPAddr())
	return err
}

var _ N.NetPacketConn = (*cnsUDPConn)(nil)