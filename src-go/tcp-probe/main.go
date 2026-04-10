package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	TlsToTcpRatio   float64 `json:"tls_to_tcp_ratio"`  // tls_handshake / tcp_rtt
	TotalToTcpRatio float64 `json:"total_to_tcp_ratio"` // total_connection / tcp_rtt
	RttCorrected    bool    `json:"rtt_corrected"`      // True if kernel RTT was unreliable and corrected

	// Refreshed at HTTP request time (kernel has seen more packets than at TLS time)
	RcvRttRefreshed uint32 `json:"rcv_rtt_refreshed"` // kernel rcv_rtt at request time
	RttRefreshed    uint32 `json:"rtt_refreshed"`     // kernel smoothed rtt at request time

	// Application-layer round trip: time from response sent to next request received.
	// More reliable than rcv_rtt for proxy detection because it measures the full
	// client path regardless of proxy TCP buffering behavior.
	AppRttUs int64 `json:"app_rtt_us,omitempty"` // 0 on first request (no prior response)
}

// connTiming holds timing data collected during connection lifecycle
type connTiming struct {
	tcpAcceptTime     time.Time
	tlsStartTime      time.Time
	tlsCompleteTime   time.Time
	httpFirstByteTime time.Time
	tcpInfo           *TcpInfo
	tcpInfoPost       *TcpInfo // TCP info after TLS handshake (used for ratio calculations)
	conn              net.Conn  // stored for per-request tcp_info refresh
	lastResponseTime  time.Time // when the last response was sent (for app-layer RTT)
	tlsRecorded       bool      // Track if TLS complete was already recorded
	ja4               string   // JA4 TLS fingerprint computed from ClientHello
	hasGREASE         bool     // Whether GREASE values were present (Chromium indicator)
	cipherCount       int      // Non-GREASE cipher suite count
}

// TLSSignals captures TLS-layer fingerprint signals.
type TLSSignals struct {
	HasGREASE   bool `json:"has_grease"`   // GREASE present in ClientHello
	CipherCount int  `json:"cipher_count"` // Non-GREASE cipher suite count
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
		conn:            tlsConn,
		tlsRecorded:     true, // Already recorded
		ja4:             ja4,
		hasGREASE:       hasGREASE,
		cipherCount:     cipherCount,
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

// analyzeRttFingerprint computes proxy detection signals from timing data.
// freshTcpInfo is an optional re-read of tcp_info at HTTP request time.
func analyzeRttFingerprint(timing *connTiming, clientReportedRtt int, freshTcpInfo *TcpInfo) *RttFingerprint {
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
		}
	}

	// Populate refreshed tcp_info fields if available
	if freshTcpInfo != nil {
		fp.RcvRttRefreshed = freshTcpInfo.RcvRtt
		fp.RttRefreshed = freshTcpInfo.Rtt
	}

	return fp
}

// buildTLSSignals returns raw TLS fingerprint signals.
func buildTLSSignals(hasGREASE bool, cipherCount int) *TLSSignals {
	return &TLSSignals{
		HasGREASE:   hasGREASE,
		CipherCount: cipherCount,
	}
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
		requestArrived := time.Now()
		timing := getAndRecordHttpTime(r.RemoteAddr)
		if timing != nil {
			// Use post-handshake TCP info for ratios (captured at TLS time)
			if timing.tcpInfoPost != nil {
				response.TcpInfo = timing.tcpInfoPost
			} else {
				response.TcpInfo = timing.tcpInfo
			}
			// Refresh tcp_info now — the kernel has seen more packets since
			// TLS handshake (HTTP request headers at minimum). This gives a
			// better rcv_rtt estimate for proxy detection.
			var freshTcpInfo *TcpInfo
			if timing.conn != nil {
				freshTcpInfo, _ = getTcpInfo(timing.conn)
			}
			// Application-layer RTT: time from last response sent to this
			// request arriving. Measures the full client round trip through
			// any proxy, unlike kernel rtt which only sees the immediate peer.
			var appRttUs int64
			if !timing.lastResponseTime.IsZero() {
				appRttUs = requestArrived.Sub(timing.lastResponseTime).Microseconds()
			}
			clientRtt := parseClientRtt(r)
			response.RttFingerprint = analyzeRttFingerprint(timing, clientRtt, freshTcpInfo)
			if response.RttFingerprint != nil {
				response.RttFingerprint.AppRttUs = appRttUs
			}
			response.JA4 = timing.ja4
			response.TLSSignals = buildTLSSignals(timing.hasGREASE, timing.cipherCount)
		}

		// Warm-up request: keep connection alive, record timing, but don't
		// store in DynamoDB. Only ?use=1 generates a token and stores.
		if r.URL.Query().Get("use") != "1" {
			// Record response time for app-layer RTT on next request
			if timing != nil {
				timingMu.Lock()
				timing.lastResponseTime = time.Now()
				timingMu.Unlock()
			}
			w.WriteHeader(http.StatusNoContent)
			return
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

		// Record when response was sent for app-layer RTT on next request
		if timing != nil {
			timingMu.Lock()
			timing.lastResponseTime = time.Now()
			timingMu.Unlock()
		}
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

	tcpListener, err := net.Listen("tcp", ":443")
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
