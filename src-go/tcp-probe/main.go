package main

import (
	"crypto/tls"
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

// connTiming holds timing data collected during connection lifecycle
type connTiming struct {
	tcpAcceptTime     time.Time
	tlsStartTime      time.Time
	tlsCompleteTime   time.Time
	httpFirstByteTime time.Time
	tcpInfo           *TcpInfo
	tcpInfoPost       *TcpInfo // TCP info after TLS handshake
	conn              net.Conn // Store connection for fresh tcp_info on subsequent requests
	tlsRecorded       bool     // Track if TLS complete was already recorded
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

// recordTlsComplete is called when TLS handshake ends (via ConnState StateActive)
// For HTTP/2, StateActive fires on 0->1 active requests, so we only record once
func recordTlsComplete(remoteAddr string, conn net.Conn) {
	timingMu.Lock()
	defer timingMu.Unlock()
	if t, ok := timingMap[remoteAddr]; ok {
		// Only record TLS complete once per connection
		if t.tlsRecorded {
			return
		}
		t.tlsRecorded = true
		t.tlsCompleteTime = time.Now()
		t.conn = conn // Store connection for fresh tcp_info on subsequent requests
		// Get TCP info after handshake - RTT should be more accurate now
		if tcpInfo, err := getTcpInfo(conn); err == nil {
			t.tcpInfoPost = tcpInfo
		}
	}
}

// getAndRecordHttpTime retrieves timing and records HTTP first byte
// For HTTP/2, this may be called multiple times on the same connection
// We refresh tcp_info on each request to get current RTT/congestion data
func getAndRecordHttpTime(remoteAddr string) *connTiming {
	timingMu.Lock()
	defer timingMu.Unlock()
	if t, ok := timingMap[remoteAddr]; ok {
		if t.httpFirstByteTime.IsZero() {
			t.httpFirstByteTime = time.Now()
		}
		// Refresh tcp_info on each request for current metrics
		// (RTT, congestion window, etc. change over connection lifetime)
		if t.conn != nil {
			if freshInfo, err := getTcpInfo(t.conn); err == nil {
				t.tcpInfoPost = freshInfo
			}
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

// buildHttp2Fingerprint creates fingerprint from request
// Note: SETTINGS frame capture was removed as it breaks HTTP/2 protocol.
// We capture protocol version and header information available at HTTP level.
func buildHttp2Fingerprint(r *http.Request) *Http2Fingerprint {
	fp := &Http2Fingerprint{
		Protocol:  r.Proto,
		Anomalies: []string{},
	}

	// Extract header order from request
	// Go's http.Request.Header is a map, but iteration order can vary
	var headerNames []string
	for name := range r.Header {
		headerNames = append(headerNames, strings.ToLower(name))
	}
	sort.Strings(headerNames)
	if len(headerNames) > 15 {
		headerNames = headerNames[:15]
	}
	fp.HeaderOrder = headerNames

	// Build fingerprint string based on available info
	// Format: "PROTOCOL|HEADERS"
	var parts []string
	parts = append(parts, r.Proto)
	if len(fp.HeaderOrder) > 0 {
		parts = append(parts, strings.Join(fp.HeaderOrder, ","))
	} else {
		parts = append(parts, "-")
	}
	fp.Fingerprint = strings.Join(parts, "|")

	// Detect anomalies based on headers
	if r.Proto == "HTTP/2.0" {
		// Check for missing common headers
		hasAccept := r.Header.Get("Accept") != ""
		hasUA := r.Header.Get("User-Agent") != ""
		if !hasAccept && !hasUA {
			fp.Anomalies = append(fp.Anomalies, "missing_common_headers")
		}
	}

	// HTTP/1.1 when HTTP/2 is expected can be a signal
	if r.Proto == "HTTP/1.1" {
		// Check if this looks like it should be HTTP/2
		if r.TLS != nil && r.TLS.NegotiatedProtocol == "" {
			fp.Anomalies = append(fp.Anomalies, "no_alpn_negotiated")
		}
	}

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

		// Echo Origin header for CORS with credentials
		// Cannot use "*" when credentials mode is "include"
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
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
		// Note: For HTTP/2, multiple requests share one connection
		// We do NOT cleanup here - cleanup happens when connection closes
		timing := getAndRecordHttpTime(r.RemoteAddr)
		if timing != nil {
			// Use post-handshake TCP info if available (refreshed on each request)
			if timing.tcpInfoPost != nil {
				response.TcpInfo = timing.tcpInfoPost
			} else {
				response.TcpInfo = timing.tcpInfo
			}
			clientRtt := parseClientRtt(r)
			response.RttFingerprint = analyzeRttFingerprint(timing, clientRtt)
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

	server := &http.Server{
		Handler: mux,
		ConnState: func(conn net.Conn, state http.ConnState) {
			remoteAddr := conn.RemoteAddr().String()
			switch state {
			case http.StateActive:
				// StateActive fires when connection reads request bytes
				// For HTTP/2, this fires on 0->1 active requests
				// recordTlsComplete only records once per connection
				recordTlsComplete(remoteAddr, conn)
			case http.StateClosed, http.StateHijacked:
				// Connection is done - clean up timing data
				// This is the proper place to cleanup, not per-request
				cleanupTiming(remoteAddr)
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
	if err := server.Serve(tlsLn); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}
