package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/danilobuerger/autocert-s3-cache"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/unix"
)

type TcpInfo struct {
	State        uint8  `json:"state"`
	CaState      uint8  `json:"ca_state"`
	Retransmits  uint8  `json:"retransmits"`
	Probes       uint8  `json:"probes"`
	Backoff      uint8  `json:"backoff"`
	Options      uint8  `json:"options"`
	Rto          uint32 `json:"rto"`
	Ato          uint32 `json:"ato"`
	Rtt          uint32 `json:"rtt"`
	Rttvar       uint32 `json:"rttvar"`
	SndMss       uint32 `json:"snd_mss"`
	RcvMss       uint32 `json:"rcv_mss"`
	Advmss       uint32 `json:"advmss"`
	Unacked      uint32 `json:"unacked"`
	Sacked       uint32 `json:"sacked"`
	Lost         uint32 `json:"lost"`
	Retrans      uint32 `json:"retrans"`
	Fackets      uint32 `json:"fackets"`
	LastDataSent uint32 `json:"last_data_sent"`
	LastAckSent  uint32 `json:"last_ack_sent"`
	LastDataRecv uint32 `json:"last_data_recv"`
	LastAckRecv  uint32 `json:"last_ack_recv"`
	Pmtu         uint32 `json:"pmtu"`
	RcvSsthresh  uint32 `json:"rcv_ssthresh"`
	SndSsthresh  uint32 `json:"snd_ssthresh"`
	SndCwnd      uint32 `json:"snd_cwnd"`
	RcvRtt       uint32 `json:"rcv_rtt"`
	RcvSpace     uint32 `json:"rcv_space"`
	Reordering   uint32 `json:"reordering"`
	TotalRetrans uint32 `json:"total_retrans"`
}

// ClientHints captures Sec-CH-UA-* headers for fraud detection
type ClientHints struct {
	UA                string `json:"ua,omitempty"`
	UAMobile          string `json:"ua_mobile,omitempty"`
	UAPlatform        string `json:"ua_platform,omitempty"`
	UAPlatformVersion string `json:"ua_platform_version,omitempty"`
	UAArch            string `json:"ua_arch,omitempty"`
	UABitness         string `json:"ua_bitness,omitempty"`
	UAModel           string `json:"ua_model,omitempty"`
	UAFullVersionList string `json:"ua_full_version_list,omitempty"`
	UAWOW64           string `json:"ua_wow64,omitempty"`
	UAFormFactor      string `json:"ua_form_factor,omitempty"`
	DeviceMemory      string `json:"device_memory,omitempty"`
	Downlink          string `json:"downlink,omitempty"`
	ECT               string `json:"ect,omitempty"`
	NetworkRTT        string `json:"network_rtt,omitempty"`
	SaveData          string `json:"save_data,omitempty"`
}

// RttFingerprint captures cross-layer RTT measurements for proxy detection
// Based on NDSS 2025 research: "The Discriminative Power of Cross-layer RTTs"
type RttFingerprint struct {
	// Measured times (microseconds)
	TcpRttUs          uint32 `json:"tcp_rtt_us"`          // TCP RTT from kernel (to immediate peer)
	TlsHandshakeUs    int64  `json:"tls_handshake_us"`    // TLS handshake duration
	HttpFirstByteUs   int64  `json:"http_first_byte_us"`  // Time from TLS complete to first HTTP byte
	TotalConnectionUs int64  `json:"total_connection_us"` // Total time from TCP accept to HTTP request

	// TCP characteristics for tunnel detection
	SndMss  uint32 `json:"snd_mss"`  // Send MSS - reduced by VPN tunnel overhead
	RcvMss  uint32 `json:"rcv_mss"`  // Receive MSS
	Pmtu    uint32 `json:"pmtu"`     // Path MTU
	Options uint8  `json:"options"`  // TCP options bitmap

	// Client-reported RTT (from Client Hints, if available)
	ClientReportedRttMs int `json:"client_reported_rtt_ms,omitempty"`

	// Computed ratios for analysis
	TlsToTcpRatio   float64 `json:"tls_to_tcp_ratio"`   // tls_handshake / tcp_rtt
	TotalToTcpRatio float64 `json:"total_to_tcp_ratio"` // total_connection / tcp_rtt

	// Proxy/VPN detection signals
	ProxyScore   float64  `json:"proxy_score"`   // 0.0-1.0 likelihood of proxy/VPN
	VpnScore     float64  `json:"vpn_score"`     // 0.0-1.0 likelihood of VPN tunnel
	ProxySignals []string `json:"proxy_signals"` // Human-readable signals
}

// Http2Fingerprint captures HTTP/2 protocol fingerprint (ACSAC 2022 style)
// Format similar to Akamai's: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS
type Http2Fingerprint struct {
	// Protocol info
	Protocol string `json:"protocol"` // "h2", "http/1.1", etc.

	// SETTINGS frame values (in order received)
	// Format: "id:value" pairs in the order sent by client
	SettingsOrder []string `json:"settings_order,omitempty"`
	// Individual settings for easy access
	HeaderTableSize      uint32 `json:"header_table_size,omitempty"`       // 0x1
	EnablePush           uint32 `json:"enable_push,omitempty"`             // 0x2
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams,omitempty"`  // 0x3
	InitialWindowSize    uint32 `json:"initial_window_size,omitempty"`     // 0x4
	MaxFrameSize         uint32 `json:"max_frame_size,omitempty"`          // 0x5
	MaxHeaderListSize    uint32 `json:"max_header_list_size,omitempty"`    // 0x6

	// WINDOW_UPDATE value (if sent with SETTINGS)
	WindowUpdate uint32 `json:"window_update,omitempty"`

	// Header ordering fingerprint
	// Pseudo-header order: the order of :method, :authority, :scheme, :path
	PseudoHeaderOrder string `json:"pseudo_header_order,omitempty"` // e.g., "m,a,s,p" or "m,s,a,p"
	// Regular header order (first 10 headers)
	HeaderOrder []string `json:"header_order,omitempty"`

	// Computed fingerprint string (Akamai-style)
	// Format: "SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADERS|HEADERS"
	Fingerprint string `json:"fingerprint"`

	// Anomaly signals
	Anomalies []string `json:"anomalies,omitempty"`
}

// HTTP/2 frame types
const (
	frameTypeSettings    = 0x4
	frameTypeWindowUpdate = 0x8
)

// HTTP/2 settings identifiers
const (
	settingHeaderTableSize      = 0x1
	settingEnablePush           = 0x2
	settingMaxConcurrentStreams = 0x3
	settingInitialWindowSize    = 0x4
	settingMaxFrameSize         = 0x5
	settingMaxHeaderListSize    = 0x6
)

// http2Settings stores parsed HTTP/2 SETTINGS
type http2Settings struct {
	settings     map[uint16]uint32
	order        []uint16
	windowUpdate uint32
}

// Global HTTP/2 settings storage - keyed by remote address
var (
	h2SettingsMap = make(map[string]*http2Settings)
	h2SettingsMu  sync.RWMutex
)

// connTiming holds timing data collected during connection lifecycle
type connTiming struct {
	tcpAcceptTime     time.Time
	tlsStartTime      time.Time
	tlsCompleteTime   time.Time
	httpFirstByteTime time.Time
	tcpInfo           *TcpInfo
	tcpInfoPost       *TcpInfo // TCP info after TLS handshake
}

type Response struct {
	TcpInfo          *TcpInfo          `json:"tcp_info"`
	RttFingerprint   *RttFingerprint   `json:"rtt_fingerprint,omitempty"`
	Http2Fingerprint *Http2Fingerprint `json:"http2_fingerprint,omitempty"`
	ClientHints      *ClientHints      `json:"client_hints,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	ClientIP         string            `json:"client_ip"`
	Domain           string            `json:"domain"`
}

type ctxKey struct{}

// Global timing storage - keyed by remote address
var (
	timingMap = make(map[string]*connTiming)
	timingMu  sync.RWMutex
)

func getTcpInfo(conn net.Conn) (*TcpInfo, error) {
	var tcpConn *net.TCPConn

	// Unwrap connection layers to get to TCP
	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case *tls.Conn:
		if netConn := c.NetConn(); netConn != nil {
			if tc, ok := netConn.(*net.TCPConn); ok {
				tcpConn = tc
			}
		}
	case *timedConn:
		return getTcpInfo(c.Conn) // Recurse to unwrap
	}

	if tcpConn == nil {
		return nil, fmt.Errorf("not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var info *unix.TCPInfo
	var sysErr error

	err = rawConn.Control(func(fd uintptr) {
		info, sysErr = unix.GetsockoptTCPInfo(int(fd), syscall.IPPROTO_TCP, syscall.TCP_INFO)
	})

	if err != nil {
		return nil, err
	}
	if sysErr != nil {
		return nil, sysErr
	}

	return &TcpInfo{
		State:        info.State,
		CaState:      info.Ca_state,
		Retransmits:  info.Retransmits,
		Probes:       info.Probes,
		Backoff:      info.Backoff,
		Options:      info.Options,
		Rto:          info.Rto,
		Ato:          info.Ato,
		Rtt:          info.Rtt,
		Rttvar:       info.Rttvar,
		SndMss:       info.Snd_mss,
		RcvMss:       info.Rcv_mss,
		Advmss:       info.Advmss,
		Unacked:      info.Unacked,
		Sacked:       info.Sacked,
		Lost:         info.Lost,
		Retrans:      info.Retrans,
		Fackets:      info.Fackets,
		LastDataSent: info.Last_data_sent,
		LastAckSent:  info.Last_ack_sent,
		LastDataRecv: info.Last_data_recv,
		LastAckRecv:  info.Last_ack_recv,
		Pmtu:         info.Pmtu,
		RcvSsthresh:  info.Rcv_ssthresh,
		SndSsthresh:  info.Snd_ssthresh,
		SndCwnd:      info.Snd_cwnd,
		RcvRtt:       info.Rcv_rtt,
		RcvSpace:     info.Rcv_space,
		Reordering:   info.Reordering,
		TotalRetrans: info.Total_retrans,
	}, nil
}

// timedConn wraps a connection to capture timing at each protocol layer
type timedConn struct {
	net.Conn
	remoteAddr string
	acceptTime time.Time
}

// timedListener wraps a net.Listener to capture TCP accept timing
type timedListener struct {
	net.Listener
}

func (l *timedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	remoteAddr := conn.RemoteAddr().String()

	// Get initial TCP info immediately after accept
	tcpInfo, _ := getTcpInfo(conn)

	// Store timing data
	timingMu.Lock()
	timingMap[remoteAddr] = &connTiming{
		tcpAcceptTime: now,
		tlsStartTime:  now, // TLS starts immediately
		tcpInfo:       tcpInfo,
	}
	timingMu.Unlock()

	return &timedConn{
		Conn:       conn,
		remoteAddr: remoteAddr,
		acceptTime: now,
	}, nil
}

// recordTlsStart is called when TLS handshake begins (via GetConfigForClient)
func recordTlsStart(remoteAddr string) {
	timingMu.Lock()
	defer timingMu.Unlock()
	if t, ok := timingMap[remoteAddr]; ok {
		t.tlsStartTime = time.Now()
	}
}

// recordTlsComplete is called when TLS handshake ends (via VerifyConnection)
func recordTlsComplete(remoteAddr string, conn net.Conn) {
	timingMu.Lock()
	defer timingMu.Unlock()
	if t, ok := timingMap[remoteAddr]; ok {
		t.tlsCompleteTime = time.Now()
		// Get TCP info after handshake - RTT should be more accurate now
		if tcpInfo, err := getTcpInfo(conn); err == nil {
			t.tcpInfoPost = tcpInfo
		}
	}
}

// getAndRecordHttpTime retrieves timing and records HTTP first byte
func getAndRecordHttpTime(remoteAddr string) *connTiming {
	timingMu.Lock()
	defer timingMu.Unlock()
	if t, ok := timingMap[remoteAddr]; ok {
		if t.httpFirstByteTime.IsZero() {
			t.httpFirstByteTime = time.Now()
		}
		return t
	}
	return nil
}

// cleanupTiming removes timing entry
func cleanupTiming(remoteAddr string) {
	timingMu.Lock()
	defer timingMu.Unlock()
	delete(timingMap, remoteAddr)
}

// h2Conn wraps a connection to intercept and parse HTTP/2 preface and SETTINGS
type h2Conn struct {
	net.Conn
	remoteAddr string
	buf        bytes.Buffer
	parsed     bool
}

// HTTP/2 connection preface
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (c *h2Conn) Read(b []byte) (int, error) {
	// If we've already parsed, just pass through
	if c.parsed {
		// First drain any buffered data
		if c.buf.Len() > 0 {
			return c.buf.Read(b)
		}
		return c.Conn.Read(b)
	}

	// Read from underlying connection
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}

	// Store in buffer for parsing
	c.buf.Write(b[:n])

	// Check if we have enough data to parse HTTP/2 preface
	if c.buf.Len() >= len(http2Preface)+9 { // preface + minimum frame header
		c.parseH2Frames()
		c.parsed = true

		// Return the buffered data
		return c.buf.Read(b)
	}

	// Need more data, return what we have
	data := c.buf.Bytes()
	copy(b, data)
	c.buf.Reset()
	return len(data), nil
}

func (c *h2Conn) parseH2Frames() {
	data := c.buf.Bytes()

	// Check for HTTP/2 preface
	if !bytes.HasPrefix(data, http2Preface) {
		// Not HTTP/2
		return
	}

	pos := len(http2Preface)
	settings := &http2Settings{
		settings: make(map[uint16]uint32),
		order:    []uint16{},
	}

	// Parse frames until we can't parse anymore
	for pos+9 <= len(data) {
		// Frame header: 9 bytes
		// Length: 3 bytes, Type: 1 byte, Flags: 1 byte, Stream ID: 4 bytes
		length := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
		frameType := data[pos+3]
		flags := data[pos+4]
		// streamID := binary.BigEndian.Uint32(data[pos+5:pos+9]) & 0x7FFFFFFF

		pos += 9 // Move past header

		// Check if we have the full frame
		if pos+length > len(data) {
			break
		}

		payload := data[pos : pos+length]
		pos += length

		switch frameType {
		case frameTypeSettings:
			// Skip if ACK flag is set (flags & 0x1)
			if flags&0x1 != 0 {
				continue
			}
			// Parse settings: each setting is 6 bytes (2 byte ID + 4 byte value)
			for i := 0; i+6 <= len(payload); i += 6 {
				id := binary.BigEndian.Uint16(payload[i : i+2])
				value := binary.BigEndian.Uint32(payload[i+2 : i+6])
				settings.settings[id] = value
				settings.order = append(settings.order, id)
			}

		case frameTypeWindowUpdate:
			// Window update: 4 bytes value
			if len(payload) >= 4 {
				settings.windowUpdate = binary.BigEndian.Uint32(payload) & 0x7FFFFFFF
			}
		}
	}

	// Store the settings
	if len(settings.order) > 0 {
		h2SettingsMu.Lock()
		h2SettingsMap[c.remoteAddr] = settings
		h2SettingsMu.Unlock()
	}
}

// h2Listener wraps a listener to wrap connections with h2Conn
type h2Listener struct {
	net.Listener
}

func (l *h2Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &h2Conn{
		Conn:       conn,
		remoteAddr: conn.RemoteAddr().String(),
	}, nil
}

// getH2Settings retrieves stored HTTP/2 settings for a connection
func getH2Settings(remoteAddr string) *http2Settings {
	h2SettingsMu.RLock()
	defer h2SettingsMu.RUnlock()
	return h2SettingsMap[remoteAddr]
}

// cleanupH2Settings removes HTTP/2 settings entry
func cleanupH2Settings(remoteAddr string) {
	h2SettingsMu.Lock()
	defer h2SettingsMu.Unlock()
	delete(h2SettingsMap, remoteAddr)
}

// settingName returns human-readable name for HTTP/2 setting
func settingName(id uint16) string {
	switch id {
	case settingHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case settingEnablePush:
		return "ENABLE_PUSH"
	case settingMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case settingInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case settingMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case settingMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	default:
		return fmt.Sprintf("UNKNOWN_%d", id)
	}
}

// buildHttp2Fingerprint creates fingerprint from request and stored settings
func buildHttp2Fingerprint(r *http.Request) *Http2Fingerprint {
	fp := &Http2Fingerprint{
		Protocol:  r.Proto,
		Anomalies: []string{},
	}

	// Get stored SETTINGS
	settings := getH2Settings(r.RemoteAddr)
	if settings != nil {
		// Build settings order string
		var settingsOrder []string
		for _, id := range settings.order {
			value := settings.settings[id]
			settingsOrder = append(settingsOrder, fmt.Sprintf("%d:%d", id, value))

			// Store individual settings
			switch id {
			case settingHeaderTableSize:
				fp.HeaderTableSize = value
			case settingEnablePush:
				fp.EnablePush = value
			case settingMaxConcurrentStreams:
				fp.MaxConcurrentStreams = value
			case settingInitialWindowSize:
				fp.InitialWindowSize = value
			case settingMaxFrameSize:
				fp.MaxFrameSize = value
			case settingMaxHeaderListSize:
				fp.MaxHeaderListSize = value
			}
		}
		fp.SettingsOrder = settingsOrder
		fp.WindowUpdate = settings.windowUpdate
	}

	// Extract header order from request
	// Go's http.Request.Header is a map, but we can get original order from the raw request
	// For now, we'll capture what we can see
	if r.Proto == "HTTP/2.0" {
		// Pseudo-headers are synthesized by Go from the h2 frame
		// We can infer them from the request
		// Standard pseudo-header order for most clients: m,a,s,p (method, authority, scheme, path)
		// Some clients (curl) use: m,s,a,p
		// This helps identify the HTTP/2 stack

		// Header order - sorted alphabetically by Go, so we note which headers are present
		var headerNames []string
		for name := range r.Header {
			// Skip pseudo-headers (already captured)
			if !strings.HasPrefix(name, ":") {
				headerNames = append(headerNames, strings.ToLower(name))
			}
		}
		sort.Strings(headerNames) // Go sorts these, but we note which ones exist
		if len(headerNames) > 10 {
			headerNames = headerNames[:10]
		}
		fp.HeaderOrder = headerNames
	}

	// Build fingerprint string
	// Format: "SETTINGS|WINDOW_UPDATE|PSEUDO_ORDER|HEADER_HASH"
	var parts []string

	// Settings part
	if len(fp.SettingsOrder) > 0 {
		parts = append(parts, strings.Join(fp.SettingsOrder, ","))
	} else {
		parts = append(parts, "-")
	}

	// Window update part
	if fp.WindowUpdate > 0 {
		parts = append(parts, fmt.Sprintf("%d", fp.WindowUpdate))
	} else {
		parts = append(parts, "-")
	}

	// Header order hash (simplified)
	if len(fp.HeaderOrder) > 0 {
		parts = append(parts, strings.Join(fp.HeaderOrder, ","))
	} else {
		parts = append(parts, "-")
	}

	fp.Fingerprint = strings.Join(parts, "|")

	// Detect anomalies
	if r.Proto == "HTTP/2.0" {
		// Check for unusual settings
		if fp.InitialWindowSize > 0 && fp.InitialWindowSize < 65535 {
			fp.Anomalies = append(fp.Anomalies, "low_initial_window")
		}
		if fp.InitialWindowSize > 16777215 { // > 16MB
			fp.Anomalies = append(fp.Anomalies, "very_high_initial_window")
		}
		if fp.MaxConcurrentStreams > 0 && fp.MaxConcurrentStreams < 100 {
			fp.Anomalies = append(fp.Anomalies, "low_max_streams")
		}
		if fp.EnablePush == 1 {
			fp.Anomalies = append(fp.Anomalies, "server_push_enabled") // Unusual for modern clients
		}
		if fp.HeaderTableSize == 0 {
			fp.Anomalies = append(fp.Anomalies, "zero_header_table") // HPACK disabled
		}
	}

	// Clean up settings after building fingerprint
	cleanupH2Settings(r.RemoteAddr)

	return fp
}

// analyzeRttFingerprint computes proxy detection signals from timing data
func analyzeRttFingerprint(timing *connTiming, clientReportedRtt int) *RttFingerprint {
	if timing == nil {
		return nil
	}

	// Use post-handshake TCP info if available (more accurate RTT)
	tcpInfo := timing.tcpInfoPost
	if tcpInfo == nil {
		tcpInfo = timing.tcpInfo
	}
	if tcpInfo == nil {
		return nil
	}

	fp := &RttFingerprint{
		TcpRttUs:            tcpInfo.Rtt,
		SndMss:              tcpInfo.SndMss,
		RcvMss:              tcpInfo.RcvMss,
		Pmtu:                tcpInfo.Pmtu,
		Options:             tcpInfo.Options,
		ClientReportedRttMs: clientReportedRtt,
		ProxySignals:        []string{},
	}

	// Calculate durations
	if !timing.tlsCompleteTime.IsZero() && !timing.tlsStartTime.IsZero() {
		fp.TlsHandshakeUs = timing.tlsCompleteTime.Sub(timing.tlsStartTime).Microseconds()
	}

	if !timing.httpFirstByteTime.IsZero() && !timing.tlsCompleteTime.IsZero() {
		fp.HttpFirstByteUs = timing.httpFirstByteTime.Sub(timing.tlsCompleteTime).Microseconds()
	}

	if !timing.httpFirstByteTime.IsZero() && !timing.tcpAcceptTime.IsZero() {
		fp.TotalConnectionUs = timing.httpFirstByteTime.Sub(timing.tcpAcceptTime).Microseconds()
	}

	// Calculate ratios
	tcpRttUs := float64(fp.TcpRttUs)
	if tcpRttUs > 0 {
		fp.TlsToTcpRatio = float64(fp.TlsHandshakeUs) / tcpRttUs
		fp.TotalToTcpRatio = float64(fp.TotalConnectionUs) / tcpRttUs
	}

	var proxyScore float64
	var vpnScore float64

	// =========================================================================
	// VPN DETECTION (tunnel-based)
	// =========================================================================

	// VPN Signal 1: Low MSS indicates tunnel encapsulation overhead
	// Standard ethernet: MSS ~1460 (MTU 1500 - 40 byte IP/TCP headers)
	// WireGuard: ~1380 (80 byte overhead)
	// OpenVPN: ~1350-1400
	// IPsec: ~1400
	// Heavy tunnels: <1300
	if fp.SndMss > 0 {
		if fp.SndMss < 1300 {
			vpnScore += 0.6
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("very_low_mss:%d", fp.SndMss))
		} else if fp.SndMss < 1400 {
			vpnScore += 0.4
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("low_mss:%d", fp.SndMss))
		} else if fp.SndMss < 1440 {
			vpnScore += 0.2
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("reduced_mss:%d", fp.SndMss))
		}
	}

	// VPN Signal 2: Non-standard PMTU can indicate tunnel
	// AWS VPC uses jumbo frames (9001), standard internet is 1500
	// VPN tunnels often have PMTU < 1500
	if fp.Pmtu > 0 && fp.Pmtu < 1500 && fp.Pmtu != 1280 { // 1280 is IPv6 minimum
		vpnScore += 0.2
		fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("low_pmtu:%d", fp.Pmtu))
	}

	// VPN Signal 3: TLS/TCP ratio > 1.5 suggests tunnel latency
	// VPN adds latency to TLS but not to TCP (TCP terminates at tunnel endpoint)
	if fp.TlsToTcpRatio > 2.5 {
		vpnScore += 0.2
		// Don't duplicate signal if already added for proxy
	} else if fp.TlsToTcpRatio > 1.8 {
		vpnScore += 0.1
	}

	// =========================================================================
	// PROXY DETECTION (application-layer)
	// =========================================================================

	// Proxy Signal 1: TLS/TCP ratio anomaly (for residential/datacenter proxies)
	// Direct connection: ~1.0-1.5 (TLS 1.3 = 2 RTTs, but measured from different points)
	// VPN: ~1.5-2.5 (tunnel adds some latency)
	// Residential proxy: ~3.0+ (application-layer forwarding adds significant latency)
	// Heavy proxy: ~5.0+ (multiple hops or distant proxy)
	if fp.TlsToTcpRatio > 5.0 {
		proxyScore += 0.5
		fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("high_tls_ratio:%.1f", fp.TlsToTcpRatio))
	} else if fp.TlsToTcpRatio > 3.0 {
		proxyScore += 0.35
		fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("elevated_tls_ratio:%.1f", fp.TlsToTcpRatio))
	} else if fp.TlsToTcpRatio > 2.0 {
		proxyScore += 0.15
		fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("moderate_tls_ratio:%.1f", fp.TlsToTcpRatio))
	}

	// Proxy Signal 2: Very low TCP RTT with high total time
	// Suggests nearby proxy but distant actual client
	if tcpRttUs > 0 && tcpRttUs < 10000 { // < 10ms TCP RTT
		if fp.TotalConnectionUs > 150000 { // > 150ms total
			proxyScore += 0.35
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("low_tcp_high_total:%.1fms/%.1fms",
				tcpRttUs/1000, float64(fp.TotalConnectionUs)/1000))
		} else if fp.TotalConnectionUs > 80000 { // > 80ms total
			proxyScore += 0.2
			fp.ProxySignals = append(fp.ProxySignals, "moderate_tcp_total_gap")
		}
	}

	// Proxy Signal 3: Client-reported RTT mismatch
	if clientReportedRtt > 0 && tcpRttUs > 0 {
		clientRttUs := float64(clientReportedRtt) * 1000
		rttRatio := clientRttUs / tcpRttUs

		if rttRatio > 3.0 {
			proxyScore += 0.4
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("client_rtt_mismatch:%.1fx", rttRatio))
		} else if rttRatio > 2.0 {
			proxyScore += 0.2
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("client_rtt_elevated:%.1fx", rttRatio))
		}
	}

	// Proxy Signal 4: High RTT variance
	if tcpInfo.Rttvar > 0 && tcpRttUs > 0 {
		varianceRatio := float64(tcpInfo.Rttvar) / tcpRttUs
		if varianceRatio > 0.5 {
			proxyScore += 0.15
			fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("high_rtt_variance:%.0f%%", varianceRatio*100))
		}
	}

	// Proxy Signal 5: Fast TCP but retransmits
	if tcpRttUs < 20000 && tcpInfo.TotalRetrans > 0 {
		proxyScore += 0.1
		fp.ProxySignals = append(fp.ProxySignals, fmt.Sprintf("fast_tcp_retrans:%d", tcpInfo.TotalRetrans))
	}

	fp.ProxyScore = math.Min(proxyScore, 1.0)
	fp.VpnScore = math.Min(vpnScore, 1.0)

	if len(fp.ProxySignals) == 0 {
		fp.ProxySignals = append(fp.ProxySignals, "none")
	}

	return fp
}

func parseClientRtt(r *http.Request) int {
	rttStr := r.Header.Get("RTT")
	if rttStr == "" {
		return 0
	}
	rttStr = strings.TrimSpace(rttStr)
	if rtt, err := strconv.ParseFloat(rttStr, 64); err == nil {
		return int(rtt)
	}
	return 0
}

func extractClientHints(r *http.Request) *ClientHints {
	ch := &ClientHints{
		UA:                r.Header.Get("Sec-CH-UA"),
		UAMobile:          r.Header.Get("Sec-CH-UA-Mobile"),
		UAPlatform:        r.Header.Get("Sec-CH-UA-Platform"),
		UAPlatformVersion: r.Header.Get("Sec-CH-UA-Platform-Version"),
		UAArch:            r.Header.Get("Sec-CH-UA-Arch"),
		UABitness:         r.Header.Get("Sec-CH-UA-Bitness"),
		UAModel:           r.Header.Get("Sec-CH-UA-Model"),
		UAFullVersionList: r.Header.Get("Sec-CH-UA-Full-Version-List"),
		UAWOW64:           r.Header.Get("Sec-CH-UA-WoW64"),
		UAFormFactor:      r.Header.Get("Sec-CH-UA-Form-Factor"),
		DeviceMemory:      r.Header.Get("Device-Memory"),
		Downlink:          r.Header.Get("Downlink"),
		ECT:               r.Header.Get("ECT"),
		NetworkRTT:        r.Header.Get("RTT"),
		SaveData:          r.Header.Get("Save-Data"),
	}
	if ch.UA == "" && ch.UAMobile == "" && ch.UAPlatform == "" {
		return nil
	}
	return ch
}

func setClientHintHeaders(w http.ResponseWriter) {
	w.Header().Set("Accept-CH",
		"Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, "+
			"Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, "+
			"Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64, "+
			"Sec-CH-UA-Form-Factor, Device-Memory, Downlink, ECT, RTT, Save-Data")
	w.Header().Set("Critical-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch")
}

func main() {
	domain := os.Getenv("DOMAIN")
	bucket := os.Getenv("CERT_BUCKET")
	region := os.Getenv("AWS_REGION")

	if domain == "" {
		log.Fatal("DOMAIN environment variable required")
	}

	log.Printf("Starting TCP probe server for domain: %s (with RTT + HTTP/2 fingerprinting)", domain)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setClientHintHeaders(w)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Expose-Headers", "Accept-CH, Critical-CH")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		response := Response{
			ClientHints: extractClientHints(r),
			UserAgent:   r.UserAgent(),
			ClientIP:    clientIP,
			Domain:      domain,
		}

		// Get timing and record HTTP first byte time
		timing := getAndRecordHttpTime(r.RemoteAddr)
		if timing != nil {
			// Use post-handshake TCP info if available
			if timing.tcpInfoPost != nil {
				response.TcpInfo = timing.tcpInfoPost
			} else {
				response.TcpInfo = timing.tcpInfo
			}
			clientRtt := parseClientRtt(r)
			response.RttFingerprint = analyzeRttFingerprint(timing, clientRtt)
			defer cleanupTiming(r.RemoteAddr)
		}

		// Build HTTP/2 fingerprint
		response.Http2Fingerprint = buildHttp2Fingerprint(r)

		json.NewEncoder(w).Encode(response)
	})

	// Health check server
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","feature":"rtt_fingerprint_v2_h2fp"}`))
		})
		log.Printf("Starting health check server on :8080")
		if err := http.ListenAndServe(":8080", healthMux); err != nil {
			log.Printf("Health server error: %v", err)
		}
	}()

	// Stale timing cleanup goroutine
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			timingMu.Lock()
			now := time.Now()
			for addr, t := range timingMap {
				if now.Sub(t.tcpAcceptTime) > 5*time.Minute {
					delete(timingMap, addr)
				}
			}
			timingMu.Unlock()
		}
	}()

	// Certificate cache
	var cache autocert.Cache
	if bucket != "" {
		log.Printf("Using S3 bucket %s for certificate storage", bucket)
		s3Cache, err := s3cache.New(region, bucket)
		if err != nil {
			log.Fatalf("Failed to initialize S3 cache: %v", err)
		}
		cache = s3Cache
	} else {
		log.Printf("Using local disk for certificate storage (Ephemeral!)")
		cache = autocert.DirCache("/var/lib/tcpprobe-certs")
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	// Build TLS config with timing hooks
	baseTlsConfig := certManager.TLSConfig()
	tlsConfig := baseTlsConfig.Clone()

	// Hook: Called when TLS handshake begins (we receive ClientHello)
	origGetConfigForClient := tlsConfig.GetConfigForClient
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// Record TLS start time
		if hello.Conn != nil {
			recordTlsStart(hello.Conn.RemoteAddr().String())
		}
		if origGetConfigForClient != nil {
			return origGetConfigForClient(hello)
		}
		return nil, nil
	}

	// Hook: Called when TLS handshake completes successfully
	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		// We need the connection to record timing, but VerifyConnection
		// doesn't give us direct access. We'll record in ConnState instead.
		return nil
	}

	// Create TCP listener
	tcpListener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on :443: %v", err)
	}

	// Wrap with timing capture
	timedLn := &timedListener{Listener: tcpListener}

	// Create TLS listener
	tlsLn := tls.NewListener(timedLn, tlsConfig)

	// Wrap TLS listener for HTTP/2 frame capture
	// HTTP/2 preface and SETTINGS are sent after TLS handshake on decrypted stream
	h2Ln := &h2Listener{Listener: tlsLn}

	server := &http.Server{
		Handler: mux,
		ConnState: func(conn net.Conn, state http.ConnState) {
			// ConnState is called when connection state changes
			// StateActive means TLS handshake just completed
			if state == http.StateActive {
				recordTlsComplete(conn.RemoteAddr().String(), conn)
			}
		},
	}

	// ACME HTTP-01 challenge server
	go func() {
		log.Printf("Starting HTTP server on :80 for ACME challenges")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	log.Printf("Starting HTTPS server on :443 with RTT + HTTP/2 fingerprinting")
	if err := server.Serve(h2Ln); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}
