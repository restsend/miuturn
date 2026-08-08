package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

func main() {
	if err := run(); err != nil {
		log.Fatalf("pion E2E test failed: %v", err)
	}
	log.Println("All pion E2E tests passed!")
}

func run() error {
	udpAddr := os.Getenv("MIUTURN_UDP_ADDR")
	tcpAddr := os.Getenv("MIUTURN_TCP_ADDR")

	if udpAddr == "" {
		pid, udp, tcp, err := startMiuturn()
		if err != nil {
			return fmt.Errorf("start miuturn: %w", err)
		}
		udpAddr = udp
		tcpAddr = tcp
		defer func() {
			proc, _ := os.FindProcess(pid)
			if proc != nil {
				proc.Kill()
			}
		}()
	}

	realm := getEnv("MIUTURN_REALM", "test-realm")
	username := getEnv("MIUTURN_USER", "admin")
	password := getEnv("MIUTURN_PASS", "password")

	log.Printf("miuturn server UDP=%s TCP=%s", udpAddr, tcpAddr)

	tests := []struct {
		name string
		fn   func() error
	}{
		{"UDP TURN", func() error { return testUDPTurn(udpAddr, realm, username, password) }},
	}
	if tcpAddr != "" {
		tests = append(tests, struct {
			name string
			fn   func() error
		}{"TCP TURN", func() error { return testTCPTurn(tcpAddr, realm, username, password) }})
		tests = append(tests, struct {
			name string
			fn   func() error
		}{"TCP Peer→Client", func() error {
			return testTCPPeerToClient(tcpAddr, udpAddr, realm, username, password)
		}})
	}
	tests = append(tests,
		struct {
			name string
			fn   func() error
		}{"SendIndication+ChannelData", func() error {
			return testSendIndicationAndChannelData(udpAddr, realm, username, password)
		}},
		struct {
			name string
			fn   func() error
		}{"DataIntegrity", func() error {
			return testDataIntegrity(udpAddr, realm, username, password)
		}},
		struct {
			name string
			fn   func() error
		}{"Refresh", func() error {
			return testRefresh(udpAddr, realm, username, password)
		}},
		struct {
			name string
			fn   func() error
		}{"ReAllocate", func() error {
			return testReAllocate(udpAddr, realm, username, password)
		}},
		struct {
			name string
			fn   func() error
		}{"ConcurrentSends", func() error {
			return testConcurrentSends(udpAddr, realm, username, password)
		}},
	)

	// Longevity stress test: run only if MIUTURN_STRESS=1
	if os.Getenv("MIUTURN_STRESS") == "1" {
		devices := getEnvInt("MIUTURN_STRESS_DEVICES", 30)
		duration := getEnvInt("MIUTURN_STRESS_DURATION", 60)
		tests = append(tests, struct {
			name string
			fn   func() error
		}{fmt.Sprintf("Longevity(%ddevices,%ds)", devices, duration), func() error {
			return testLongevity(udpAddr, realm, username, password, devices, duration)
		}})
	}

	for _, t := range tests {
		if err := t.fn(); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
		log.Printf("  PASS: %s", t.name)
	}
	return nil
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := fmt.Sscanf(v, "%d", &def)
		if err == nil && n == 1 {
			return def
		}
	}
	return def
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// miuturn subprocess
// ---------------------------------------------------------------------------

func startMiuturn() (pid int, udpAddr, tcpAddr string, err error) {
	binary, err := findBinary()
	if err != nil {
		return 0, "", "", err
	}

	udpPort := pickFreePort()
	tcpPort := pickFreePort()
	udpAddr = fmt.Sprintf("127.0.0.1:%d", udpPort)
	tcpAddr = fmt.Sprintf("127.0.0.1:%d", tcpPort)

	confDir, err := os.MkdirTemp("", "miuturn-e2e-*")
	if err != nil {
		return 0, "", "", fmt.Errorf("mk temp dir: %w", err)
	}

	relayStart := uint16(30000) + uint16((os.Getpid()%200)*20)
	relayEnd := relayStart + uint16(1999)
	config := fmt.Sprintf(`[server]
realm = "test-realm"
external_ip = "127.0.0.1"
relay_bind_ip = "127.0.0.1"
start_port = %d
end_port = %d

[[server.listening]]
protocol = "udp"
address = "%s"

[[server.listening]]
protocol = "tcp"
address = "%s"

[auth]
admin_users = ["admin"]

[[auth.users]]
username = "admin"
password = "password"
user_type = "fixed"
max_allocations = 100

[log]
log_level = "warn"
`, relayStart, relayEnd, udpAddr, tcpAddr)

	confPath := filepath.Join(confDir, "miuturn.toml")
	if err := os.WriteFile(confPath, []byte(config), 0644); err != nil {
		return 0, "", "", fmt.Errorf("write config: %w", err)
	}

	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(), "CONFIG="+confPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, "", "", fmt.Errorf("start miuturn: %w", err)
	}
	pid = cmd.Process.Pid

	if err := waitReady(udpAddr); err != nil {
		cmd.Process.Kill()
		return 0, "", "", fmt.Errorf("wait ready: %w", err)
	}

	go func() { cmd.Wait(); os.RemoveAll(confDir) }()
	return pid, udpAddr, tcpAddr, nil
}

func findBinary() (string, error) {
	if bin := os.Getenv("MIUTURN_BIN"); bin != "" {
		if _, err := os.Stat(bin); err == nil {
			return bin, nil
		}
		return "", fmt.Errorf("MIUTURN_BIN=%s not found", bin)
	}
	wd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(wd, "..", "..", "target/release/miuturn"),
		filepath.Join(wd, "..", "..", "target/debug/miuturn"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("miuturn binary not found (build with 'cargo build --release' or set MIUTURN_BIN)")
}

func waitReady(addr string) error {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := []byte{
		0x00, 0x01, 0x00, 0x00,
		0x21, 0x12, 0xA4, 0x42,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
	}

	for i := 0; i < 50; i++ {
		conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn.Write(req)
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err == nil && n >= 20 && buf[4] == 0x21 && buf[5] == 0x12 &&
			buf[6] == 0xA4 && buf[7] == 0x42 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server at %s not ready", addr)
}

func testTCPPeerToClient(tcpAddr, udpAddr, realm, username, password string) error {
	alloc, err := allocateTCP(tcpAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate TCP: %w", err)
	}
	defer alloc.Close()

	// Peer: binds to loopback so the source IP is 127.0.0.1 (not 0.0.0.0)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission TCP: %w", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Peer sends data directly to the relay address
	relayUDPAddr, err := net.ResolveUDPAddr("udp4", alloc.relay.String())
	if err != nil {
		return fmt.Errorf("resolve relay addr: %w", err)
	}
	payload := []byte("tcp-peer-to-client-data")
	if _, err := peer.WriteTo(payload, relayUDPAddr); err != nil {
		return fmt.Errorf("peer send to relay: %w", err)
	}

	// Read the Data Indication forwarded over TCP
	buf := make([]byte, 4096)
	alloc.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := readTCPFrame(alloc.tcpConn, buf)
	if err != nil {
		return fmt.Errorf("read TCP Data Indication: %w", err)
	}

	// Parse the Data Indication to extract payload
	_, data, err := parseDataIndication(buf[:n])
	if err != nil {
		return fmt.Errorf("parse Data Indication: %w", err)
	}
	if !bytes.Equal(data, payload) {
		return fmt.Errorf("peer→client TCP data mismatch: got %q, want %q", string(data), string(payload))
	}

	// Also test ChannelData over TCP: bind a channel, peer sends again,
	// client reads ChannelData from TCP
	if err := alloc.channelBind(peerAddr, 0x4000); err != nil {
		return fmt.Errorf("channel bind TCP: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	payload2 := []byte("tcp-channeldata-peer-to-client")
	if _, err := peer.WriteTo(payload2, relayUDPAddr); err != nil {
		return fmt.Errorf("peer send ChannelData test: %w", err)
	}

	// Read the ChannelData forwarded over TCP
	alloc.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n2, err := readTCPFrame(alloc.tcpConn, buf)
	if err != nil {
		return fmt.Errorf("read TCP ChannelData: %w", err)
	}
	// ChannelData format: channel(2) + length(2) + payload
	if n2 < 4 {
		return fmt.Errorf("ChannelData too short: %d", n2)
	}
	chPayload := buf[4:n2]
	if !bytes.Equal(chPayload, payload2) {
		return fmt.Errorf("TCP ChannelData data mismatch: got %q, want %q", string(chPayload), string(payload2))
	}

	return nil
}

func pickFreePort() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	if l == nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// ---------------------------------------------------------------------------
// TURN client helpers (raw STUN/TURN over UDP/TCP)
// ---------------------------------------------------------------------------

type turnAlloc struct {
	conn     *net.UDPConn
	server   *net.UDPAddr
	tcpConn  net.Conn
	relay    net.Addr
	username string
	realm    string
	password string
	nonce    []byte
}

func (a *turnAlloc) Close() {
	if a.conn != nil {
		a.conn.Close()
	}
	if a.tcpConn != nil {
		a.tcpConn.Close()
	}
}

func (a *turnAlloc) sendMsg(msg []byte) error {
	if a.tcpConn != nil {
		return writeTCPFrame(a.tcpConn, msg)
	}
	_, err := a.conn.Write(msg)
	return err
}

func (a *turnAlloc) readMsg(buf []byte) (int, error) {
	if a.tcpConn != nil {
		a.tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		return readTCPFrame(a.tcpConn, buf)
	}
	a.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return a.conn.Read(buf)
}

// sendAuthRequest sends an authenticated STUN request and checks for success response.
// It automatically appends USERNAME, REALM, NONCE, and MESSAGE-INTEGRITY.
func (a *turnAlloc) sendAuthRequest(method uint16, attrs [][]byte) error {
	tid := newTID()
	msg := stunHeader(method, 0, tid)
	for _, attr := range attrs {
		msg = appendAttr(msg, binary.BigEndian.Uint16(attr[0:2]), attr[2:])
	}
	msg = appendAttr(msg, 0x0006, []byte(a.username))
	msg = appendAttr(msg, 0x0014, []byte(a.realm))
	msg = appendAttr(msg, 0x0015, a.nonce)

	key := md5Hash([]byte(fmt.Sprintf("%s:%s:%s", a.username, a.realm, a.password)))
	body := msg[20:]
	hmacHdr := stunHeader(method, 0, tid)
	binary.BigEndian.PutUint16(hmacHdr[2:4], uint16(len(body))+24)
	hmacInput := append(hmacHdr, body...)
	integrity := hmacSha1(key, hmacInput)
	msg = appendAttr(msg, 0x0008, integrity)

	if err := a.sendMsg(msg); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, err := a.readMsg(buf)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if n < 20 {
		return fmt.Errorf("response too short")
	}
	// Check for error response
	class := (buf[0]&0x01)<<1 | (buf[1]&0x10)>>4
	if class == 3 { // Error
		errBytes, _ := parseAttr(buf[:n], 0x0009)
		if len(errBytes) >= 4 {
			code := int(binary.BigEndian.Uint32(errBytes) & 0xFFFF)
			return fmt.Errorf("STUN error code=%d", code)
		}
		return fmt.Errorf("STUN error response")
	}
	return nil
}

// allocateUDP creates a TURN allocation over UDP
func allocateUDP(serverAddr, realm, username, password string) (*turnAlloc, error) {
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}

	// Get nonce
	tid := newTID()
	conn.Write(buildAllocateReq(tid))
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := conn.Read(buf)
	nonceRaw, errMsg := parseAttr(buf[:n], 0x0015)
	if errMsg != "" {
		conn.Close()
		return nil, fmt.Errorf("get nonce: %s", errMsg)
	}

	// Authenticated allocate
	tid2 := newTID()
	conn.Write(buildAuthAllocateBytes(tid2, username, realm, nonceRaw, password))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n2, _ := conn.Read(buf)
	relayBytes, errMsg2 := parseAttr(buf[:n2], 0x0016)
	if errMsg2 != "" {
		conn.Close()
		return nil, fmt.Errorf("parse relay addr: %s", errMsg2)
	}
	relayAddr, err := decodeXorAddr(relayBytes)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("decode relay addr: %w", err)
	}

	return &turnAlloc{
		conn:     conn,
		server:   raddr,
		relay:    relayAddr,
		username: username,
		realm:    realm,
		password: password,
		nonce:    nonceRaw,
	}, nil
}

// allocateTCP creates a TURN allocation over TCP
func allocateTCP(serverAddr, realm, username, password string) (*turnAlloc, error) {
	tcpConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Get nonce
	tid := newTID()
	writeTCPFrame(tcpConn, buildAllocateReq(tid))
	buf := make([]byte, 4096)
	n, _ := readTCPFrame(tcpConn, buf)
	nonceRaw, errMsg := parseAttr(buf[:n], 0x0015)
	if errMsg != "" {
		tcpConn.Close()
		return nil, fmt.Errorf("get nonce TCP: %s", errMsg)
	}

	// Authenticated allocate
	tid2 := newTID()
	writeTCPFrame(tcpConn, buildAuthAllocateBytes(tid2, username, realm, nonceRaw, password))
	n2, _ := readTCPFrame(tcpConn, buf)
	relayBytes, errMsg2 := parseAttr(buf[:n2], 0x0016)
	if errMsg2 != "" {
		tcpConn.Close()
		return nil, fmt.Errorf("parse relay addr TCP: %s", errMsg2)
	}
	relayAddr, err := decodeXorAddr(relayBytes)
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	return &turnAlloc{
		tcpConn:  tcpConn,
		relay:    relayAddr,
		username: username,
		realm:    realm,
		password: password,
		nonce:    nonceRaw,
	}, nil
}

// sendSend sends a Send Indication via the allocation (no auth needed for Indications)
func (a *turnAlloc) sendSend(peer net.Addr, data []byte) error {
	tid := newTID()
	msg := buildSendInd(tid, peer, data)
	return a.sendMsg(msg)
}

// writeChannelData sends a ChannelData message (no auth needed)
func (a *turnAlloc) writeChannelData(channel uint16, data []byte) error {
	hdr := []byte{byte(channel >> 8), byte(channel), byte(len(data) >> 8), byte(len(data))}
	msg := append(hdr, data...)
	return a.sendMsg(msg)
}

// createPermission sends an authenticated CreatePermission request
func (a *turnAlloc) createPermission(peer net.Addr) error {
	peerAttr := encodeXorAddr(peer)
	attrBuf := make([]byte, 2+len(peerAttr))
	binary.BigEndian.PutUint16(attrBuf[0:2], 0x0012)
	copy(attrBuf[2:], peerAttr)
	return a.sendAuthRequest(0x0008, [][]byte{attrBuf})
}

// channelBind sends an authenticated ChannelBind request
func (a *turnAlloc) channelBind(peer net.Addr, channel uint16) error {
	peerAttr := encodeXorAddr(peer)
	attrBuf1 := make([]byte, 2+len(peerAttr))
	binary.BigEndian.PutUint16(attrBuf1[0:2], 0x0012)
	copy(attrBuf1[2:], peerAttr)

	chBytes := []byte{byte(channel >> 8), byte(channel)}
	attrBuf2 := make([]byte, 2+len(chBytes))
	binary.BigEndian.PutUint16(attrBuf2[0:2], 0x000C)
	copy(attrBuf2[2:], chBytes)

	return a.sendAuthRequest(0x0009, [][]byte{attrBuf1, attrBuf2})
}

// refresh sends an authenticated Refresh request
func (a *turnAlloc) refresh(lifetime uint32) error {
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, lifetime)
	attrBuf := make([]byte, 2+len(lt))
	binary.BigEndian.PutUint16(attrBuf[0:2], 0x000D)
	copy(attrBuf[2:], lt)
	return a.sendAuthRequest(0x0004, [][]byte{attrBuf})
}

// sendSendInd sends a Send Indication (alternative name)
func sendSendInd(conn *net.UDPConn, server *net.UDPAddr, tid, peerAddr []byte, peerPort int, data []byte) error {
	msg := buildSendInd(tid, &net.UDPAddr{IP: peerAddr, Port: peerPort}, data)
	_, err := conn.Write(msg)
	return err
}

// ---------------------------------------------------------------------------
// STUN message builders
// ---------------------------------------------------------------------------

func newTID() []byte {
	b := make([]byte, 12)
	now := uint64(time.Now().UnixNano())
	for i := 0; i < 12; i++ {
		b[i] = byte(now >> (i * 8))
	}
	return b
}

func stunHeader(method, class uint16, tid []byte) []byte {
	a := method & 0x000F
	b := method & 0x0070
	d := method & 0x0F80
	msgType := a + (b<<1) + (d<<2)
	c0 := (class & 1) << 4
	c1 := (class & 2) << 7
	msgType += c0 + c1

	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], msgType)
	hdr[4] = 0x21
	hdr[5] = 0x12
	hdr[6] = 0xA4
	hdr[7] = 0x42
	copy(hdr[8:20], tid)
	return hdr
}

func setMsgLen(msg []byte, bodyLen int) {
	binary.BigEndian.PutUint16(msg[2:4], uint16(bodyLen))
}

func appendAttr(msg []byte, attrType uint16, value []byte) []byte {
	bodyLen := len(msg) - 20 + 4 + len(value)
	pad := (4 - len(value)%4) % 4
	setMsgLen(msg, bodyLen+pad)

	attr := make([]byte, 4+len(value)+pad)
	binary.BigEndian.PutUint16(attr[0:2], attrType)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(value)))
	copy(attr[4:], value)
	return append(msg, attr...)
}

func encodeXorAddr(addr net.Addr) []byte {
	host := ""
	port := 0
	switch a := addr.(type) {
	case *net.UDPAddr:
		host = a.IP.String()
		port = a.Port
	case *net.TCPAddr:
		host = a.IP.String()
		port = a.Port
	default:
		// Fallback: split host:port and parse IP
		h, p, err := net.SplitHostPort(addr.String())
		if err == nil {
			host = h
			fmt.Sscanf(p, "%d", &port)
		} else {
			host = addr.String()
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		h, _, _ := net.SplitHostPort(addr.String())
		ip = net.ParseIP(h)
	}
	if ip == nil {
		return []byte{0, 1, 0, 0, 0, 0, 0, 0}
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return []byte{0, 2, 0, 0, 0, 0, 0, 0}
	}
	magic := uint32(0x2112A442)
	xport := uint16(port) ^ uint16(magic>>16)
	buf := make([]byte, 8)
	buf[0] = 0
	buf[1] = 1
	binary.BigEndian.PutUint16(buf[2:4], xport)
	buf[4] = ip4[0] ^ byte(magic>>24)
	buf[5] = ip4[1] ^ byte(magic>>16)
	buf[6] = ip4[2] ^ byte(magic>>8)
	buf[7] = ip4[3] ^ byte(magic)
	return buf
}

func decodeXorAddr(data []byte) (*net.UDPAddr, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("addr too short")
	}
	magic := uint32(0x2112A442)
	port := binary.BigEndian.Uint16(data[2:4]) ^ uint16(magic>>16)
	ip := make(net.IP, 4)
	ip[0] = data[4] ^ byte(magic>>24)
	ip[1] = data[5] ^ byte(magic>>16)
	ip[2] = data[6] ^ byte(magic>>8)
	ip[3] = data[7] ^ byte(magic)
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func buildAllocateReq(tid []byte) []byte {
	msg := stunHeader(0x0003, 0, tid)
	msg = appendAttr(msg, 0x0019, []byte{0x11, 0x00, 0x00, 0x00})
	return msg
}

func buildAuthAllocate(tid []byte, username, realm, nonce, password string) []byte {
	msg := stunHeader(0x0003, 0, tid)
	msg = appendAttr(msg, 0x0019, []byte{0x11, 0x00, 0x00, 0x00})
	msg = appendAttr(msg, 0x0006, []byte(username))
	msg = appendAttr(msg, 0x0014, []byte(realm))
	msg = appendAttr(msg, 0x0015, []byte(nonce))
	// RFC 5389 §15.4: MESSAGE-INTEGRITY is HMAC-SHA1 over:
	//   STUN header (with message_length = body_len + 24) + all attributes before MI
	// The +24 accounts for the MI attribute (4-byte header + 20-byte HMAC value).
	key := md5Hash([]byte(fmt.Sprintf("%s:%s:%s", username, realm, password)))
	// Extract the encoded body (everything after the 20-byte header)
	body := msg[20:]
	// Build HMAC input: header with adjusted length + body
	hmacHdr := stunHeader(0x0003, 0, tid)
	binary.BigEndian.PutUint16(hmacHdr[2:4], uint16(len(body))+24)
	hmacInput := append(hmacHdr, body...)
	integrity := hmacSha1(key, hmacInput)
	msg = appendAttr(msg, 0x0008, integrity)
	return msg
}

func buildAuthAllocateBytes(tid []byte, username, realm string, nonce []byte, password string) []byte {
	return buildAuthAllocate(tid, username, realm, string(nonce), password)
}

func buildAuthRefresh(tid []byte, lifetime uint32, username, realm, nonce, password string) []byte {
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, lifetime)
	msg := stunHeader(0x0004, 0, tid)
	msg = appendAttr(msg, 0x000D, lt)
	msg = appendAttr(msg, 0x0006, []byte(username))
	msg = appendAttr(msg, 0x0014, []byte(realm))
	msg = appendAttr(msg, 0x0015, []byte(nonce))
	key := md5Hash([]byte(fmt.Sprintf("%s:%s:%s", username, realm, password)))
	body := msg[20:]
	hmacHdr := stunHeader(0x0004, 0, tid)
	binary.BigEndian.PutUint16(hmacHdr[2:4], uint16(len(body))+24)
	hmacInput := append(hmacHdr, body...)
	integrity := hmacSha1(key, hmacInput)
	msg = appendAttr(msg, 0x0008, integrity)
	return msg
}

func buildSendInd(tid []byte, peer net.Addr, data []byte) []byte {
	msg := stunHeader(0x0006, 1, tid) // Send, Indication
	msg = appendAttr(msg, 0x0012, encodeXorAddr(peer))
	msg = appendAttr(msg, 0x0013, data)
	return msg
}

// ---------------------------------------------------------------------------
// TCP framing (RFC 6062)
// ---------------------------------------------------------------------------

func writeTCPFrame(conn net.Conn, data []byte) error {
	frame := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(data)))
	copy(frame[2:], data)
	_, err := conn.Write(frame)
	return err
}

func readTCPFrame(conn net.Conn, buf []byte) (int, error) {
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return 0, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf))
	if msgLen > len(buf) {
		return 0, fmt.Errorf("message too large: %d > %d", msgLen, len(buf))
	}
	total := 0
	for total < msgLen {
		n, err := conn.Read(buf[total:msgLen])
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// ---------------------------------------------------------------------------
// STUN attribute parser
// ---------------------------------------------------------------------------

func parseAttr(data []byte, attrType uint16) ([]byte, string) {
	if len(data) < 20 {
		return nil, "response too short"
	}
	bodyLen := int(binary.BigEndian.Uint16(data[2:4]))
	end := 20 + bodyLen
	if end > len(data) {
		end = len(data)
	}
	pos := 20
	for pos+4 <= end {
		t := binary.BigEndian.Uint16(data[pos : pos+2])
		l := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if pos+4+l > end {
			break
		}
		if t == attrType {
			val := make([]byte, l)
			copy(val, data[pos+4:pos+4+l])
			return val, ""
		}
		pad := (4 - l%4) % 4
		pos += 4 + l + pad
	}
	return nil, fmt.Sprintf("attribute 0x%04x not found", attrType)
}

// parseDataIndication extracts peer address and payload from a Data Indication
func parseDataIndication(data []byte) (net.Addr, []byte, error) {
	if len(data) < 20 {
		return nil, nil, fmt.Errorf("data too short")
	}
	bodyLen := int(binary.BigEndian.Uint16(data[2:4]))
	end := 20 + bodyLen
	if end > len(data) {
		end = len(data)
	}
	var peerAddr net.Addr
	var payload []byte
	pos := 20
	for pos+4 <= end {
		t := binary.BigEndian.Uint16(data[pos : pos+2])
		l := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if pos+4+l > end {
			break
		}
		switch t {
		case 0x0012:
			peerAddr, _ = decodeXorAddr(data[pos+4 : pos+4+l])
		case 0x0013:
			payload = make([]byte, l)
			copy(payload, data[pos+4:pos+4+l])
		}
		pad := (4 - l%4) % 4
		pos += 4 + l + pad
	}
	if payload == nil {
		return nil, nil, fmt.Errorf("DATA attribute not found")
	}
	return peerAddr, payload, nil
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

func md5Hash(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func hmacSha1(key, msg []byte) []byte {
	// Per RFC 5389: HMAC is over the STUN header (with adjusted message_length
	// to include MESSAGE-INTEGRITY) + all attributes before MESSAGE-INTEGRITY.
	// We approximate this by using the full message.
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	return h.Sum(nil)
}


// listenPeerUDP binds a peer UDP socket on the loopback interface so its
// LocalAddr() is a routable destination. Binding to the wildcard (0.0.0.0)
// makes LocalAddr() return 0.0.0.0:port, which is not a valid send
// destination on macOS (ENOHOST) and would break the relay round-trip.
func listenPeerUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// ---------------------------------------------------------------------------
// Test scenarios
// ---------------------------------------------------------------------------

func testUDPTurn(serverAddr, realm, username, password string) error {
	alloc, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer alloc.Close()

	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	payload := []byte("hello from pion e2e")
	if err := alloc.sendSend(peerAddr, payload); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 4096)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := peer.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("data mismatch: got %q", string(buf[:n]))
	}
	return nil
}

func testTCPTurn(serverAddr, realm, username, password string) error {
	alloc, err := allocateTCP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate TCP: %w", err)
	}
	defer alloc.Close()

	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission TCP: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	payload := []byte("hello over TCP TURN")
	if err := alloc.sendSend(peerAddr, payload); err != nil {
		return fmt.Errorf("send TCP: %w", err)
	}

	buf := make([]byte, 4096)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := peer.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("recv TCP: %w", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("TCP data mismatch: got %q", string(buf[:n]))
	}
	return nil
}

func testSendIndicationAndChannelData(serverAddr, realm, username, password string) error {
	alloc, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer alloc.Close()

	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	// 1. Send Indication
	payload1 := []byte("send-indication-test")
	if err := alloc.sendSend(peerAddr, payload1); err != nil {
		return fmt.Errorf("send indication: %w", err)
	}

	buf := make([]byte, 4096)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := peer.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("recv indication: %w", err)
	}
	if !bytes.Equal(buf[:n], payload1) {
		return fmt.Errorf("indication data mismatch")
	}

	// 2. ChannelData
	ch := uint16(0x4000)
	if err := alloc.channelBind(peerAddr, ch); err != nil {
		return fmt.Errorf("channel bind: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	payload2 := []byte("channel-data-test")
	if err := alloc.writeChannelData(ch, payload2); err != nil {
		return fmt.Errorf("channel data: %w", err)
	}

	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n2, _, err2 := peer.ReadFrom(buf)
	if err2 != nil {
		return fmt.Errorf("recv channel data: %w", err2)
	}
	if !bytes.Equal(buf[:n2], payload2) {
		return fmt.Errorf("channel data mismatch: got %q", string(buf[:n2]))
	}
	return nil
}

func testDataIntegrity(serverAddr, realm, username, password string) error {
	alloc, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer alloc.Close()

	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	const totalPackets = 100
	const packetSize = 512

	for i := 0; i < totalPackets; i++ {
		pkt := make([]byte, packetSize)
		binary.BigEndian.PutUint32(pkt[0:4], uint32(i))
		for j := 4; j < packetSize; j++ {
			pkt[j] = byte(i + j)
		}
		if err := alloc.sendSend(peerAddr, pkt); err != nil {
			return fmt.Errorf("send packet %d: %w", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	received := make(map[uint32]bool)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) && len(received) < totalPackets {
		peer.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			continue
		}
		if n >= 4 {
			seq := binary.BigEndian.Uint32(buf[0:4])
			received[seq] = true
			// Verify payload
			for j := 4; j < n; j++ {
				if buf[j] != byte(int(seq)+j) {
					return fmt.Errorf("corruption at packet %d offset %d", seq, j)
				}
			}
		}
	}

	loss := totalPackets - len(received)
	if loss > 5 {
		return fmt.Errorf("packet loss too high: %d/%d", loss, totalPackets)
	}
	return nil
}

func testRefresh(serverAddr, realm, username, password string) error {
	alloc, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer alloc.Close()

	if err := alloc.refresh(600); err != nil {
		return fmt.Errorf("refresh: %w", err)
	}

	// Verify allocation still works
	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission after refresh: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	payload := []byte("post-refresh-test")
	if err := alloc.sendSend(peerAddr, payload); err != nil {
		return fmt.Errorf("send after refresh: %w", err)
	}

	buf := make([]byte, 4096)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := peer.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("recv after refresh: %w", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("data mismatch after refresh")
	}
	return nil
}

func testReAllocate(serverAddr, realm, username, password string) error {
	// First allocation
	alloc1, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate 1: %w", err)
	}
	relay1 := alloc1.relay.String()
	alloc1.Close()
	time.Sleep(100 * time.Millisecond)

	// Second allocation (should work on different or same port)
	alloc2, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate 2: %w", err)
	}
	defer alloc2.Close()
	relay2 := alloc2.relay.String()

	// Verify new allocation works
	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc2.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	payload := []byte("re-allocate-test")
	if err := alloc2.sendSend(peerAddr, payload); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	buf := make([]byte, 4096)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := peer.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("data mismatch after re-allocate")
	}

	log.Printf("  ReAllocate: relay1=%s relay2=%s", relay1, relay2)
	return nil
}

func testConcurrentSends(serverAddr, realm, username, password string) error {
	alloc, err := allocateUDP(serverAddr, realm, username, password)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer alloc.Close()

	peer, err := listenPeerUDP()
	if err != nil {
		return err
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	if err := alloc.createPermission(peerAddr); err != nil {
		return fmt.Errorf("create permission: %w", err)
	}
	time.Sleep(50 * time.Millisecond)

	const concurrency = 20
	var success atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pkt := []byte(fmt.Sprintf("concurrent-packet-%d", id))
			if err := alloc.sendSend(peerAddr, pkt); err == nil {
				success.Add(1)
			}
		}(i)
	}
	wg.Wait()

	received := make(map[string]bool)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) && len(received) < int(success.Load()) {
		peer.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			continue
		}
		received[string(buf[:n])] = true
	}

	sent := success.Load()
	got := len(received)
	if sent != concurrency {
		return fmt.Errorf("only %d/%d sends succeeded", sent, concurrency)
	}
	if got < concurrency/2 {
		return fmt.Errorf("only received %d/%d packets", got, concurrency)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Longevity stress test
// ---------------------------------------------------------------------------

type deviceStats struct {
	allocOK     atomic.Int64
	allocFail   atomic.Int64
	sendOK      atomic.Int64
	sendFail    atomic.Int64
	recvOK      atomic.Int64
	recvFail    atomic.Int64
	refreshOK   atomic.Int64
	refreshFail atomic.Int64
	permOK      atomic.Int64
	permFail    atomic.Int64
}

func testLongevity(serverAddr, realm, username, password string, numDevices, durationSecs int) error {
	log.Printf("Starting longevity test: %d devices, %d seconds", numDevices, durationSecs)

	var stats deviceStats
	var wg sync.WaitGroup
	stop := make(chan struct{})
	startTime := time.Now()

	for id := range numDevices {
		wg.Add(1)
		go func(deviceID int) {
			defer wg.Done()
			runDevice(deviceID, serverAddr, realm, username, password, stop, &stats)
		}(id)
	}

	// Run for specified duration
	time.Sleep(time.Duration(durationSecs) * time.Second)
	close(stop)
	wg.Wait()

	elapsed := time.Since(startTime)
	ok := stats.allocOK.Load() + stats.sendOK.Load() + stats.recvOK.Load() + stats.refreshOK.Load() + stats.permOK.Load()
	fail := stats.allocFail.Load() + stats.sendFail.Load() + stats.recvFail.Load() + stats.refreshFail.Load() + stats.permFail.Load()
	total := ok + fail

	log.Printf("  Longevity results (%ds, %d devices):", durationSecs, numDevices)
	log.Printf("    Allocate: OK=%d Fail=%d", stats.allocOK.Load(), stats.allocFail.Load())
	log.Printf("    Perm:     OK=%d Fail=%d", stats.permOK.Load(), stats.permFail.Load())
	log.Printf("    Send:     OK=%d Fail=%d", stats.sendOK.Load(), stats.sendFail.Load())
	log.Printf("    Recv:     OK=%d Fail=%d", stats.recvOK.Load(), stats.recvFail.Load())
	log.Printf("    Refresh:  OK=%d Fail=%d", stats.refreshOK.Load(), stats.refreshFail.Load())
	log.Printf("    Total:    OK=%d Fail=%d (rate=%.0f/s)", ok, fail, float64(total)/elapsed.Seconds())

	// At least 80% success rate
	if fail > 0 && float64(fail)/float64(total) > 0.2 {
		return fmt.Errorf("failure rate too high: %d/%d (%.1f%%)", fail, total, float64(fail)/float64(total)*100)
	}
	// Each device must have at least some cycles completed
	if ok == 0 {
		return fmt.Errorf("zero successful operations across all devices")
	}
	return nil
}

func runDevice(id int, serverAddr, realm, username, password string, stop chan struct{}, stats *deviceStats) {
	// Allocate once, reuse across cycles
	alloc, err := quickAllocate(serverAddr, realm, username, password)
	if err != nil {
		stats.allocFail.Add(1)
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(500+rand.Intn(1000)) * time.Millisecond):
		}
	}
	stats.allocOK.Add(1)
	defer alloc.Close()

	// Create a single peer socket for the lifetime of this device
	peer, err := listenPeerUDP()
	if err != nil {
		stats.recvFail.Add(1)
		return
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr()

	// CreatePermission (IP-based, persists for allocation lifetime)
	if err := alloc.createPermission(peerAddr); err != nil {
		stats.permFail.Add(1)
		return
	}
	stats.permOK.Add(1)

	// Channel bind for ChannelData
	if err := alloc.channelBind(peerAddr, 0x4000); err != nil {
		stats.permFail.Add(1)
		return
	}

	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 4096)

	for {
		select {
		case <-stop:
			return
		default:
		}

		sendID := stats.sendOK.Load()

		// Send via Send Indication
		payload := []byte(fmt.Sprintf("si-%d-%d", id, sendID))
		if err := alloc.sendSend(peerAddr, payload); err != nil {
			stats.sendFail.Add(1)
		} else {
			stats.sendOK.Add(1)
		}

		// Verify receipt
		peer.SetReadDeadline(time.Now().Add(1 * time.Second))
		if n, _, err := peer.ReadFrom(buf); err == nil && n == len(payload) && bytes.Equal(buf[:n], payload) {
			stats.recvOK.Add(1)
		} else {
			stats.recvFail.Add(1)
		}

		// Send via ChannelData (uses the channel binding)
		chPayload := []byte(fmt.Sprintf("cd-%d-%d", id, sendID))
		if err := alloc.writeChannelData(0x4000, chPayload); err != nil {
			stats.sendFail.Add(1)
		} else {
			stats.sendOK.Add(1)
		}

		// Verify ChannelData receipt
		peer.SetReadDeadline(time.Now().Add(1 * time.Second))
		if n, _, err := peer.ReadFrom(buf); err == nil && n == len(chPayload) && bytes.Equal(buf[:n], chPayload) {
			stats.recvOK.Add(1)
		} else {
			stats.recvFail.Add(1)
		}

		// Refresh every ~10 cycles
		if sendID > 0 && sendID%10 == 0 {
			if err := alloc.refresh(120); err != nil {
				stats.refreshFail.Add(1)
			} else {
				stats.refreshOK.Add(1)
			}
		}

		select {
		case <-stop:
			return
		case <-time.After(time.Duration(30+rand.Intn(170)) * time.Millisecond):
		}
	}
}

// quickAllocate does a minimal TURN allocate (no extra logging, short timeouts)
func quickAllocate(serverAddr, realm, username, password string) (*turnAlloc, error) {
	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Get nonce
	tid := newTID()
	conn.Write(buildAllocateReq(tid))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	nonceRaw, errMsg := parseAttr(buf[:n], 0x0015)
	if errMsg != "" {
		conn.Close()
		return nil, fmt.Errorf("nonce: %s", errMsg)
	}

	// Authenticated allocate
	tid2 := newTID()
	conn.Write(buildAuthAllocateBytes(tid2, username, realm, nonceRaw, password))
	n2, _ := conn.Read(buf)
	relayBytes, errMsg2 := parseAttr(buf[:n2], 0x0016)
	if errMsg2 != "" {
		conn.Close()
		return nil, fmt.Errorf("relay: %s", errMsg2)
	}
	relayAddr, err := decodeXorAddr(relayBytes)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &turnAlloc{
		conn:     conn,
		server:   raddr,
		relay:    relayAddr,
		username: username,
		realm:    realm,
		password: password,
		nonce:    nonceRaw,
	}, nil
}
