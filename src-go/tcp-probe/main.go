package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	s3cache "github.com/danilobuerger/autocert-s3-cache"
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
	TcpRttRawUs       uint32 `json:"tcp_rtt_raw_us"`      // Raw kernel RTT before correction
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
	TlsToTcpRatio    float64 `json:"tls_to_tcp_ratio"`              // tls_handshake / tcp_rtt
	TotalToTcpRatio  float64 `json:"total_to_tcp_ratio"`            // total_connection / tcp_rtt
	RttCorrected     bool    `json:"rtt_corrected"`                 // True if kernel RTT was unreliable and corrected
	TlsTcpRatioNote  string  `json:"tls_tcp_ratio_note,omitempty"` // direct/normal/possible_relay/likely_relay

	// Peer IP-layer signals (observed at the TCP accept)
	PeerTTL     uint8 `json:"peer_ttl,omitempty"`      // Incoming IP TTL from the connecting host
	PeerTTLHops uint8 `json:"peer_ttl_hops,omitempty"` // Estimated hops (inferred starting TTL - peer TTL)

	// Proxy/VPN detection signals
	ProxyScore   float64  `json:"proxy_score"`   // 0.0-1.0 likelihood of proxy/VPN
	VpnScore     float64  `json:"vpn_score"`     // 0.0-1.0 likelihood of VPN tunnel
	ProxySignals []string `json:"proxy_signals"` // Human-readable signals
}

// connTiming holds timing data collected during connection lifecycle
type connTiming struct {
	tcpAcceptTime     time.Time
	tlsStartTime      time.Time
	tlsCompleteTime   time.Time
	httpFirstByteTime time.Time
	tcpInfo           *TcpInfo
	tcpInfoPost       *TcpInfo // TCP info after TLS handshake (used for ratio calculations)
	tlsRecorded       bool     // Track if TLS complete was already recorded
	ja4               string   // JA4 TLS fingerprint computed from ClientHello
	hasGREASE         bool     // Whether GREASE values were present (Chromium indicator)
	cipherCount       int      // Non-GREASE cipher suite count
	peerTTL           uint8    // Incoming IP TTL from the client's packets
}

// TLSSignals captures TLS-layer fingerprint signals and UA consistency checks.
type TLSSignals struct {
	HasGREASE   bool     `json:"has_grease"`             // GREASE present → Chromium-based client
	CipherCount int      `json:"cipher_count"`           // Non-GREASE cipher suite count
	UAMismatch  bool     `json:"ua_mismatch"`            // JA4 signals inconsistent with User-Agent
	UAHints     []string `json:"ua_hints,omitempty"`     // Human-readable mismatch reasons
}

type Response struct {
	TcpInfo        *TcpInfo        `json:"tcp_info"`
	RttFingerprint *RttFingerprint `json:"rtt_fingerprint,omitempty"`
	TLSSignals     *TLSSignals     `json:"tls_signals,omitempty"`
	ClientHints    *ClientHints    `json:"client_hints,omitempty"`
	UserAgent      string          `json:"user_agent,omitempty"`
	ClientIP       string          `json:"client_ip"`
	Domain         string          `json:"domain"`
	JA4            string          `json:"ja4,omitempty"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type probeTokenItem struct {
	Token       string `dynamodbav:"token"`
	Fingerprint string `dynamodbav:"fingerprint"` // JSON-encoded Response
	ClientIP    string `dynamodbav:"client_ip"`
	TTL         int64  `dynamodbav:"ttl"` // Unix seconds — DynamoDB TTL attribute
}

type ctxKey struct{}

var (
	signingKey       []byte
	dynamoClient     *dynamodb.DynamoDB
	probeTokensTable string
)

func initSigningKey() {
	keyHex := os.Getenv("SIGINT_AES_KEY")
	if keyHex == "" {
		log.Fatal("SIGINT_AES_KEY not set — required for token signing")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		log.Fatalf("SIGINT_AES_KEY must be 64 hex chars (32 bytes): %v", err)
	}
	signingKey = key
	log.Println("Token signing key initialized")
}

func initDynamo() {
	probeTokensTable = os.Getenv("PROBE_TOKENS_TABLE")
	if probeTokensTable == "" {
		log.Fatal("PROBE_TOKENS_TABLE not set")
	}
	sess := session.Must(session.NewSession())
	dynamoClient = dynamodb.New(sess)
	log.Printf("DynamoDB client initialized, table: %s", probeTokensTable)
}

// generateToken creates a signed token embedding the expiry and client IP.
// Format: {nonce_hex}.{expiry_ms}.{hmac_hex}
func generateToken(clientIP string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	expiry := fmt.Sprintf("%d", time.Now().Add(90*time.Second).UnixMilli())

	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(nonceHex + "." + expiry + "." + clientIP))
	sig := hex.EncodeToString(mac.Sum(nil))

	return nonceHex + "." + expiry + "." + sig, nil
}

// storeFingerprint writes the TCP/TLS fingerprint to DynamoDB keyed by token.
func storeFingerprint(token string, data any, clientIP string) error {
	fpJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal fingerprint: %w", err)
	}
	item, err := dynamodbattribute.MarshalMap(probeTokenItem{
		Token:       token,
		Fingerprint: string(fpJSON),
		ClientIP:    clientIP,
		TTL:         time.Now().Add(90 * time.Second).Unix(),
	})
	if err != nil {
		return fmt.Errorf("marshal dynamo item: %w", err)
	}
	_, err = dynamoClient.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String(probeTokensTable),
		Item:      item,
	})
	return err
}

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
		// NetConn() may return *peekConn, *timedConn, or *net.TCPConn - recurse to handle all
		if netConn := c.NetConn(); netConn != nil {
			return getTcpInfo(netConn)
		}
	case *peekConn:
		return getTcpInfo(c.Conn) // Unwrap to underlying TCP conn
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

// estimateStartingTTL returns the likely initial TTL based on common OS defaults.
// Linux: 64, Windows: 128, some routers/older macOS: 255.
func estimateStartingTTL(ttl uint8) uint8 {
	if ttl > 128 {
		return 255
	}
	if ttl > 64 {
		return 128
	}
	return 64
}

// getPeerTTL reads the incoming IP TTL from the first received bytes of the
// connection via MSG_PEEK + IP_RECVTTL ancillary data. Returns 0 on failure.
// Requires the listening socket to have had IP_RECVTTL set before accept.
func getPeerTTL(tcpConn *net.TCPConn) uint8 {
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0
	}
	var ttl uint8
	rawConn.Read(func(fd uintptr) bool {
		peek := make([]byte, 1)
		oob := make([]byte, 64)
		_, oobn, _, _, err := syscall.Recvmsg(int(fd), peek, oob, syscall.MSG_PEEK)
		if err != nil || oobn == 0 {
			return true
		}
		msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return true
		}
		for _, m := range msgs {
			if m.Header.Level == syscall.IPPROTO_IP && int(m.Header.Type) == unix.IP_TTL {
				if len(m.Data) >= 1 {
					ttl = m.Data[0]
				}
			}
		}
		return true
	})
	return ttl
}

// timedConn wraps a connection to capture timing at each protocol layer
type timedConn struct {
	net.Conn
	remoteAddr string
	acceptTime time.Time
}

// peekConn wraps a net.Conn and replays buffered bytes before delegating to the
// underlying connection. Used to capture the raw ClientHello before handing the
// connection to crypto/tls, which needs to re-read those same bytes.
type peekConn struct {
	net.Conn
	buf []byte
	pos int
}

func (c *peekConn) Read(b []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(b, c.buf[c.pos:])
		c.pos += n
		if c.pos >= len(c.buf) {
			c.buf = nil // free once drained
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// captureClientHello reads the first TLS record from conn, returning a peekConn
// that will replay those bytes to the TLS stack, and the raw handshake payload
// (without the 5-byte record header) for JA4 parsing.
// Returns (peekConn, nil, nil) when the record is not a ClientHello.
func captureClientHello(conn net.Conn) (*peekConn, []byte) {
	// Short deadline so a slow/malicious client can't block Accept
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// TLS record header: content_type(1) + legacy_version(2) + length(2)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return &peekConn{Conn: conn}, nil
	}

	if hdr[0] != 0x16 { // Not a handshake record
		return &peekConn{Conn: conn, buf: append([]byte(nil), hdr...)}, nil
	}

	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen > 16384 { // Max TLS plaintext record length
		return &peekConn{Conn: conn, buf: append([]byte(nil), hdr...)}, nil
	}

	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return &peekConn{Conn: conn, buf: append(hdr, body...)}, nil
	}

	all := append(hdr, body...)
	if len(body) < 4 || body[0] != 0x01 { // Not a ClientHello
		return &peekConn{Conn: conn, buf: all}, nil
	}

	return &peekConn{Conn: conn, buf: all}, body
}

// timedTlsListener wraps a TCP listener and performs TLS handshake with accurate timing.
// Unlike tls.NewListener which does lazy handshake, this explicitly calls Handshake()
// during Accept() so we can measure the actual TLS handshake duration.
type timedTlsListener struct {
	tcpListener net.Listener
	tlsConfig   *tls.Config
}

func (l *timedTlsListener) Accept() (net.Conn, error) {
	// Accept TCP connection
	tcpConn, err := l.tcpListener.Accept()
	if err != nil {
		return nil, err
	}

	tcpAcceptTime := time.Now()
	remoteAddr := tcpConn.RemoteAddr().String()

	// Get initial TCP info immediately after accept
	initialTcpInfo, _ := getTcpInfo(tcpConn)

	// Read peer TTL via MSG_PEEK before any data is consumed.
	// Requires IP_RECVTTL on the listener socket (set in main via ListenConfig).
	var peerTTL uint8
	if rawTCP, ok := tcpConn.(*net.TCPConn); ok {
		peerTTL = getPeerTTL(rawTCP)
	}

	// Capture the ClientHello before TLS processes it so we can compute JA4.
	// peekConn replays the captured bytes transparently to the TLS stack.
	peeked, helloBody := captureClientHello(tcpConn)
	var ja4 string
	var hasGREASE bool
	var cipherCount int
	if helloBody != nil {
		if fields, err := parseClientHello(helloBody); err == nil {
			ja4 = computeJA4(fields)
			hasGREASE = fields.HasGREASE
			for _, c := range fields.CipherSuites {
				if !isGREASE(c) {
					cipherCount++
				}
			}
		} else {
			log.Printf("JA4 parse error from %s: %v", remoteAddr, err)
		}
	}

	// Create TLS connection wrapping the peek buffer so TLS re-reads the hello
	tlsConn := tls.Server(peeked, l.tlsConfig)

	// Record TLS start time and perform handshake with timing
	tlsStartTime := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	tlsCompleteTime := time.Now()

	// Get TCP info after handshake - this RTT is used for ratio calculations
	// The kernel now has accurate RTT from the TLS handshake packets
	postTcpInfo, _ := getTcpInfo(tlsConn)

	// Store all timing data atomically
	timingMu.Lock()
	timingMap[remoteAddr] = &connTiming{
		tcpAcceptTime:   tcpAcceptTime,
		tlsStartTime:    tlsStartTime,
		tlsCompleteTime: tlsCompleteTime,
		tcpInfo:         initialTcpInfo,
		tcpInfoPost:     postTcpInfo,
		tlsRecorded:     true, // Already recorded
		ja4:             ja4,
		hasGREASE:       hasGREASE,
		cipherCount:     cipherCount,
		peerTTL:         peerTTL,
	}
	timingMu.Unlock()

	return tlsConn, nil
}

func (l *timedTlsListener) Close() error {
	return l.tcpListener.Close()
}

func (l *timedTlsListener) Addr() net.Addr {
	return l.tcpListener.Addr()
}

// recordTlsComplete is now only used as a fallback for edge cases.
// Primary TLS timing is captured in timedTlsListener.Accept().
func recordTlsComplete(remoteAddr string, conn net.Conn) {
	timingMu.Lock()
	defer timingMu.Unlock()
	if t, ok := timingMap[remoteAddr]; ok {
		// Skip if already recorded (normal case - recorded in Accept)
		if t.tlsRecorded {
			return
		}
		t.tlsRecorded = true
		t.tlsCompleteTime = time.Now()
		if tcpInfo, err := getTcpInfo(conn); err == nil {
			t.tcpInfoPost = tcpInfo
		}
	}
}

// getAndRecordHttpTime retrieves timing and records HTTP first byte
// For HTTP/2, this may be called multiple times on the same connection
// Note: We do NOT refresh tcpInfoPost here - it must stay at the value captured
// at TLS handshake time for accurate TLS/TCP ratio calculations.
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

// analyzeRttFingerprint computes proxy detection signals from timing data
func analyzeRttFingerprint(timing *connTiming, clientReportedRtt int) *RttFingerprint {
	if timing == nil {
		return nil
	}

	// Use post-handshake TCP info if available (more accurate RTT)
	// Use tcpInfoPost (captured at TLS complete) for accurate ratio calculations.
	// Do NOT fall back to tcpInfo (captured at TCP accept) as its RTT is stale
	// and would produce invalid ratios (e.g., TLS time < TCP RTT).
	tcpInfo := timing.tcpInfoPost
	if tcpInfo == nil {
		// tcpInfoPost not available - can still return basic info from tcpInfo
		tcpInfo = timing.tcpInfo
		if tcpInfo == nil {
			return nil
		}
	}

	// Track if we have post-handshake TCP info for accurate ratios
	hasPostHandshakeInfo := timing.tcpInfoPost != nil

	fp := &RttFingerprint{
		TcpRttUs:            tcpInfo.Rtt,
		TcpRttRawUs:         tcpInfo.Rtt,
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

	// Calculate ratios with sanity checks
	// The kernel's SRTT can be wrong in several cases:
	// 1. Includes server processing delays (inflated)
	// 2. Only has 1-2 samples from initial handshake (noisy)
	// 3. Delayed ACKs can inflate it by up to 200ms
	tcpRttUs := float64(fp.TcpRttUs)
	tlsUs := float64(fp.TlsHandshakeUs)

	if tcpRttUs > 0 && tlsUs > 0 && hasPostHandshakeInfo {
		// Sanity check: TLS handshake must be >= ~0.8x TCP RTT for a direct connection
		// (TLS 1.3 requires at least 1 RTT, minus some overlap from pipelining)
		// If TLS < 0.8x TCP RTT, the kernel's RTT is inflated (includes processing)
		if tlsUs < tcpRttUs*0.8 {
			// Kernel RTT is clearly wrong - estimate from TLS handshake
			// TLS 1.3 handshake ≈ 1 RTT + ~5ms crypto overhead
			// Use TLS/1.05 as estimated RTT (conservative)
			estimatedRtt := tlsUs / 1.05
			fp.TcpRttUs = uint32(estimatedRtt)
			fp.RttCorrected = true
			tcpRttUs = estimatedRtt
		}

		// Also check for impossibly high RTT (> 2 seconds suggests measurement error)
		if tcpRttUs > 2000000 {
			fp.RttCorrected = true
			// Don't calculate ratio for clearly broken data
			tcpRttUs = 0
		}

		if tcpRttUs > 0 {
			fp.TlsToTcpRatio = tlsUs / tcpRttUs
			fp.TotalToTcpRatio = float64(fp.TotalConnectionUs) / tcpRttUs

			// Label the ratio for easy interpretation without feeding into scores.
			// A direct connection should be ~1-3x (1 TLS RTT + server crypto overhead).
			// A relay chain inflates TLS time while TCP RTT reflects only the last hop.
			switch {
			case fp.TlsToTcpRatio >= 12.0:
				fp.TlsTcpRatioNote = "likely_relay"
			case fp.TlsToTcpRatio >= 6.0 && tcpRttUs < 40000:
				fp.TlsTcpRatioNote = "possible_relay"
			case fp.TlsToTcpRatio >= 3.0:
				fp.TlsTcpRatioNote = "normal"
			default:
				fp.TlsTcpRatioNote = "direct"
			}
		}
	}

	// Peer TTL — observed incoming IP TTL and estimated hop count.
	// Does not feed into scores; exposed for cross-layer OS fingerprinting.
	if timing.peerTTL > 0 {
		fp.PeerTTL = timing.peerTTL
		fp.PeerTTLHops = estimateStartingTTL(timing.peerTTL) - timing.peerTTL
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

	// =========================================================================
	// PROXY DETECTION (application-layer)
	// =========================================================================

	// Proxy Signal 1: Very low TCP RTT with high total time
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

// buildTLSSignals computes TLS-layer signals and UA consistency for a connection.
func buildTLSSignals(hasGREASE bool, cipherCount int, ua string) *TLSSignals {
	s := &TLSSignals{
		HasGREASE:   hasGREASE,
		CipherCount: cipherCount,
	}

	uaL := strings.ToLower(ua)

	// Classify the claimed client from the User-Agent string.
	// Chrome/Chromium UA always contains "Chrome/" but NOT "Edg/" for Edge.
	// Edge contains both "Chrome/" and "Edg/". Brave also contains "Chrome/".
	// Safari (non-Chrome) contains "Safari/" and "Version/" but not "Chrome/".
	isChromiumUA := strings.Contains(uaL, "chrome/") || strings.Contains(uaL, "chromium/")
	isFirefoxUA := strings.Contains(uaL, "firefox/")
	isSafariUA := strings.Contains(uaL, "safari/") && strings.Contains(uaL, "version/") && !isChromiumUA
	isBotUA := strings.Contains(uaL, "curl/") || strings.Contains(uaL, "python-requests") ||
		strings.HasPrefix(uaL, "python/") || strings.HasPrefix(uaL, "go-http-client") ||
		strings.Contains(uaL, "java/") || strings.Contains(uaL, "okhttp/") ||
		strings.Contains(uaL, "libwww") || strings.Contains(uaL, "wget/")

	// GREASE is sent exclusively by Chromium-based TLS stacks.
	if hasGREASE && !isChromiumUA {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, "grease_without_chromium_ua")
	}
	if !hasGREASE && isChromiumUA {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, "chromium_ua_without_grease")
	}

	// Cipher count sanity checks per browser family.
	// Chrome: 29–35 non-GREASE suites. Firefox: ~17. Safari: ~20. Bots: <15.
	if isFirefoxUA && cipherCount > 25 {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, fmt.Sprintf("firefox_ua_high_ciphers:%d", cipherCount))
	}
	if isChromiumUA && cipherCount < 20 {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, fmt.Sprintf("chromium_ua_low_ciphers:%d", cipherCount))
	}
	if isSafariUA && cipherCount > 30 {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, fmt.Sprintf("safari_ua_high_ciphers:%d", cipherCount))
	}

	// Known bot/automation UA claiming to be a browser.
	if isBotUA && (isChromiumUA || isFirefoxUA || isSafariUA) {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, "conflicting_ua_identifiers")
	}

	return s
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

	initSigningKey()
	initDynamo()

	log.Printf("Starting TCP probe server for domain: %s (RTT fingerprinting)", domain)

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
			response.JA4 = timing.ja4
			response.TLSSignals = buildTLSSignals(timing.hasGREASE, timing.cipherCount, r.UserAgent())
		}

		token, err := generateToken(clientIP)
		if err != nil {
			log.Printf("Error generating token for %s: %v", clientIP, err)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		if err := storeFingerprint(token, response, clientIP); err != nil {
			log.Printf("Error storing fingerprint for %s: %v", clientIP, err)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		out, err := json.Marshal(TokenResponse{Token: token})
		if err != nil {
			log.Printf("Error marshaling token response: %v", err)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		w.Write(out)
	})

	// Health check server
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","service":"tcp-probe"}`))
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

	// Create TCP listener with IP_RECVTTL so the kernel delivers the incoming
	// IP TTL as ancillary data on each received segment (used by getPeerTTL).
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, unix.IP_RECVTTL, 1)
			})
		},
	}
	tcpListener, err := lc.Listen(context.Background(), "tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on :443: %v", err)
	}

	// Create our custom TLS listener that explicitly times the handshake.
	// This gives us accurate TLS handshake duration measurement, unlike
	// the standard tls.NewListener which does lazy handshake.
	tlsLn := &timedTlsListener{
		tcpListener: tcpListener,
		tlsConfig:   tlsConfig,
	}

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

	log.Printf("Starting HTTPS server on :443 with RTT fingerprinting")
	if err := server.Serve(tlsLn); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}
