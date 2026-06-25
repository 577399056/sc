package cns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.CNSOptions](registry, C.TypeCNS, NewOutbound)
}

// Outbound is the CNS protocol outbound.
type Outbound struct {
	outbound.Adapter
	logger          logger.ContextLogger
	options         option.CNSOptions
	serverAddr      M.Socksaddr
	dialer          N.Dialer
	udpFlag         string
	proxyKey        string
	encryptPassword []byte
	}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.CNSOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	var detour N.Dialer
	detour, err = tls.NewDialerFromOptions(ctx, logger, outboundDialer, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}

	udpFlag := options.UDPFlag
	if udpFlag == "" {
udpFlag = "httpUDP"
	}
	proxyKey := options.ProxyKey
	if proxyKey == "" {
		proxyKey = "Host"
	}

	o := &Outbound{
		Adapter:         outbound.NewAdapterWithDialerOptions(C.TypeCNS, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:          logger,
		options:         options,
		serverAddr:      options.ServerOptions.Build(),
		dialer:          detour,
		udpFlag:         udpFlag,
		proxyKey:        proxyKey,
		encryptPassword: []byte(options.EncryptPassword),
	}
	return o, nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = destination

	switch N.NetworkName(network) {
	case N.NetworkTCP:
		o.logger.InfoContext(ctx, "outbound TCP connection to ", destination)
		return o.dialTCP(ctx, destination)
	case N.NetworkUDP:
		if o.options.UDPOverTCP {
			o.logger.InfoContext(ctx, "outbound UDP-over-TCP connection to ", destination)
return o.dialUDPOverTCP(ctx, destination)
		}
		return nil, E.New("CNS outbound: raw UDP not supported without udp_over_tcp")
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	o.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return o.listenPacket(ctx, destination)
}

// dialTCP establishes a TCP connection through CNS.
func (o *Outbound) dialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
conn, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.serverAddr)
	if err != nil {
		return nil, err
	}

	hostPort := destination.String()

	if len(o.encryptPassword) > 0 {
		encHost := EncryptHost(hostPort, o.encryptPassword)
		request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n%s: %s\r\n\r\n", hostPort, o.proxyKey, encHost)
		_, err = conn.Write([]byte(request))
	} else {
		request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n%s: %s\r\n\r\n", hostPort, o.proxyKey, hostPort)
		_, err = conn.Write([]byte(request))
}
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read response header to confirm 200
	buf := make([]byte, 1024)
	n := 0
	for {
		nn, err := conn.Read(buf[n:])
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "read CNS CONNECT response")
		}
		n += nn
		headerEnd := indexBytes(buf[:n], []byte("\r\n\r\n"))
		if headerEnd >= 0 {
			// Verify 200 response in the header portion
			header := buf[:headerEnd+4]
			if !bytesContains(header, []byte(" 200 ")) {
				conn.Close()
				return nil, E.New("CNS CONNECT failed: ", string(header))
}
			// Return the conn at the data boundary; discard header data
			if len(o.encryptPassword) > 0 {
				return &xorConn{Conn: conn, password: o.encryptPassword}, nil
			}
			return conn, nil
		}
		if n >= len(buf) {
			conn.Close()
			return nil, E.New("CNS response too large")
		}
	}
}

// dialUDPOverTCP creates a UDP-over-TCP tunnel through CNS.
func (o *Outbound) dialUDPOverTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.serverAddr)
	if err != nil {
		return nil, err
	}

	request := fmt.Sprintf("GET / HTTP/1.1\r\n%s: x\r\n%s: 1\r\n\r\n", o.proxyKey, o.udpFlag)
	_, err = conn.Write([]byte(request))
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read response and keep any leftover data after the HTTP header
	buf := make([]byte, 1024)
	n := 0
	for {
		nn, err := conn.Read(buf[n:])
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "read CNS httpUDP response")
		}
		n += nn
		endIdx := indexBytes(buf[:n], []byte("\r\n\r\n"))
if endIdx >= 0 {
			// Found header end; save leftover bytes after header
			headerEnd := endIdx + 4
			var remaining []byte
			if headerEnd < n {
				remaining = make([]byte, n-headerEnd)
				copy(remaining, buf[headerEnd:n])
			}
			return &udpOverTCPConn{
				Conn:      conn,
				password:  o.encryptPassword,
				dst:       destination,
				readBuf:   remaining,
			}, nil
		}
	}
}

// listenPacket implements UDP packet connections through CNS httpUDP.
func (o *Outbound) listenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
conn, err := o.dialer.DialContext(ctx, N.NetworkTCP, o.serverAddr)
	if err != nil {
		return nil, err
	}

	request := fmt.Sprintf("GET / HTTP/1.1\r\n%s: x\r\n%s: 1\r\n\r\n", o.proxyKey, o.udpFlag)
	_, err = conn.Write([]byte(request))
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Read response and keep any leftover data after the HTTP header
	buf := make([]byte, 1024)
	nn := 0
	for {
		n, err := conn.Read(buf[nn:])
		if err != nil {
			conn.Close()
			return nil, E.Cause(err, "read CNS httpUDP response")
}
		nn += n
		endIdx := indexBytes(buf[:nn], []byte("\r\n\r\n"))
		if endIdx >= 0 {
			headerEnd := endIdx + 4
			var remaining []byte
			if headerEnd < nn {
				remaining = make([]byte, nn-headerEnd)
				copy(remaining, buf[headerEnd:nn])
			}
			return newCNSPacketConnWithBuf(conn, o.encryptPassword, remaining), nil
		}
	}
}

// xorConn wraps a net.Conn with XOR stream encryption.
type xorConn struct {
	net.Conn
	password []byte
	passSub  int
	mu       sync.Mutex
}

func (c *xorConn) Read(b []byte) (int, error) {
n, err := c.Conn.Read(b)
	if n > 0 && len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(b[:n], c.password, c.passSub)
		c.mu.Unlock()
	}
	return n, err
}

func (c *xorConn) Write(b []byte) (int, error) {
	if len(c.password) > 0 {
		data := make([]byte, len(b))
		copy(data, b)
		c.mu.Lock()
		c.passSub = XorCrypt(data, c.password, c.passSub)
		c.mu.Unlock()
		return c.Conn.Write(data)
	}
	return c.Conn.Write(b)
}

// udpOverTCPConn implements net.Conn for the CNS httpUDP tunnel.
type udpOverTCPConn struct {
net.Conn
	password []byte
	dst      M.Socksaddr
	passSub  int
	mu       sync.Mutex
	readBuf  []byte
}

func (c *udpOverTCPConn) Read(b []byte) (int, error) {
	// If we have buffered data from handshake, try to extract a complete frame first
	if len(c.readBuf) > 0 {
		n, err := c.readFrameFromBuffer(b)
		if err == nil {
			return n, nil
		}
		// If buffer doesn't have a complete frame, fall through to read from conn
	}

	return c.readFrameFromConn(b)
}

// readFrameFromBuffer tries to extract a complete httpUDP frame from readBuf.
// Returns an error if the buffer doesn't contain a complete frame.
func (c *udpOverTCPConn) readFrameFromBuffer(b []byte) (int, error) {
	if len(c.readBuf) < 2 {
		return 0, fmt.Errorf("readBuf too short: %d", len(c.readBuf))
	}

	pkgLen := binary.LittleEndian.Uint16(c.readBuf[0:2])
	if int(pkgLen) > len(c.readBuf) {
		return 0, fmt.Errorf("readBuf partial frame: declared %d, actual %d", pkgLen, len(c.readBuf))
	}

	// Decrypt the frame in-place
	if len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(c.readBuf[:pkgLen], c.password, c.passSub)
c.mu.Unlock()
	}

	n := copy(b, c.readBuf[:pkgLen])
	c.readBuf = c.readBuf[pkgLen:]
	return n, nil
}

// readFrameFromConn reads a complete httpUDP frame from the connection.
func (c *udpOverTCPConn) readFrameFromConn(b []byte) (int, error) {
	lenBuf := make([]byte, 2)
	_, err := io.ReadFull(c.Conn, lenBuf)
	if err != nil {
		return 0, err
	}

	pkgLen := binary.LittleEndian.Uint16(lenBuf)
	if pkgLen < 12 {
		return 0, fmt.Errorf("invalid httpUDP packet length: %d", pkgLen)
	}

	// Read full frame into a single buffer; we must return the complete frame
	// to UnbindPacketConn, not just the payload.
	pkg := make([]byte, pkgLen)
	copy(pkg[0:2], lenBuf)
	_, err = io.ReadFull(c.Conn, pkg[2:])
	if err != nil {
		return 0, err
	}

	if len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(pkg, c.password, c.passSub)
		c.mu.Unlock()
	}

	// Return complete frame: length(2) + header(10/22) + payload
	return copy(b, pkg), nil
}

func (c *udpOverTCPConn) Write(b []byte) (int, error) {
	pkt := BuildUDPPacket(c.dst, b)
	defer udpBufferPool.Put(pkt[:cap(pkt)])
if len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(pkt, c.password, c.passSub)
		c.mu.Unlock()
	}

	_, err := c.Conn.Write(pkt)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// cnsPacketConn implements net.PacketConn for CNS httpUDP.
type cnsPacketConn struct {
	conn     net.Conn
	password []byte
	passSub  int
	mu       sync.Mutex
	readBuf  []byte
}

func newCNSPacketConnWithBuf(conn net.Conn, password []byte, readBuf []byte) *cnsPacketConn {
	return &cnsPacketConn{
		conn:     conn,
		password: password,
		readBuf:  readBuf,
	}
}

func (c *cnsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Consume buffered leftover from handshake first
	if len(c.readBuf) > 0 {
		return c.readFrameFromBuf(p)
	}

	lenBuf := make([]byte, 2)
	_, err = io.ReadFull(c.conn, lenBuf)
	if err != nil {
		return 0, nil, err
	}

	pkgLen := binary.LittleEndian.Uint16(lenBuf)
	if pkgLen < 12 {
		return 0, nil, fmt.Errorf("invalid httpUDP packet length: %d", pkgLen)
	}

	pkg := make([]byte, pkgLen)
copy(pkg[0:2], lenBuf)
	_, err = io.ReadFull(c.conn, pkg[2:])
	if err != nil {
		return 0, nil, err
	}

	if len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(pkg, c.password, c.passSub)
		c.mu.Unlock()
	}

	dst, payload, err := ParseUDPResponse(pkg)
	if err != nil {
		return 0, nil, err
	}

	n = copy(p, payload)
	return n, dst.UDPAddr(), nil
}

func (c *cnsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, E.New("unsupported address type")
}

	dst := M.SocksaddrFromNetIP(netip.AddrPortFrom(udpAddr.AddrPort().Addr(), uint16(udpAddr.Port)))
	pkt := BuildUDPPacket(dst, p)
	defer udpBufferPool.Put(pkt[:cap(pkt)])

	if len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(pkt, c.password, c.passSub)
		c.mu.Unlock()
	}

	_, err = c.conn.Write(pkt)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *cnsPacketConn) Close() error {
	return c.conn.Close()
}

func (c *cnsPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *cnsPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *cnsPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *cnsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// indexBytes returns the index of sub in b, or -1 if not found.
func indexBytes(b []byte, sub []byte) int {
	for i := 0; i <= len(b)-len(sub); i++ {
		if b[i] == sub[0] {
			match := true
			for j := 1; j < len(sub); j++ {
			if b[i+j] != sub[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
}

// bytesContains is a simple byte-slice contains helper.
func bytesContains(b []byte, sub []byte) bool {
	return indexBytes(b, sub) >= 0
}

// readFrameFromBuf reads a complete httpUDP frame from readBuf.
func (c *cnsPacketConn) readFrameFromBuf(p []byte) (n int, addr net.Addr, err error) {
	if len(c.readBuf) < 2 {
		return 0, nil, fmt.Errorf("cnsPacketConn readBuf too short: %d", len(c.readBuf))
}

	pkgLen := binary.LittleEndian.Uint16(c.readBuf[0:2])
	if int(pkgLen) > len(c.readBuf) {
		return 0, nil, fmt.Errorf("cnsPacketConn readBuf packet length mismatch: declared %d, actual %d", pkgLen, len(c.readBuf))
	}

	pkg := c.readBuf[:pkgLen]
	// Advance readBuf past this frame
	c.readBuf = c.readBuf[pkgLen:]

	if len(c.password) > 0 {
		c.mu.Lock()
		c.passSub = XorCrypt(pkg, c.password, c.passSub)
		c.mu.Unlock()
	}

	dst, payload, err := ParseUDPResponse(pkg)
	if err != nil {
		return 0, nil, err
			}

	n = copy(p, payload)
	return n, dst.UDPAddr(), nil
}
