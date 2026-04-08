package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	s3cache "github.com/danilobuerger/autocert-s3-cache"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TLSSignals captures TLS-layer fingerprint signals and UA consistency checks.
type TLSSignals struct {
	HasGREASE   bool     `json:"has_grease"`
	CipherCount int      `json:"cipher_count"`
	UAMismatch  bool     `json:"ua_mismatch"`
	UAHints     []string `json:"ua_hints,omitempty"`
}

// peekConn replays buffered bytes before delegating reads to the underlying conn.
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
			c.buf = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// captureClientHello reads the first TLS record and returns a peekConn that
// replays those bytes to the TLS stack, plus the raw ClientHello payload for
// JA4 parsing.
func captureClientHello(conn net.Conn) (*peekConn, []byte) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return &peekConn{Conn: conn}, nil
	}
	if hdr[0] != 0x16 {
		return &peekConn{Conn: conn, buf: append([]byte(nil), hdr...)}, nil
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen > 16384 {
		return &peekConn{Conn: conn, buf: append([]byte(nil), hdr...)}, nil
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return &peekConn{Conn: conn, buf: append(hdr, body...)}, nil
	}
	all := append(hdr, body...)
	if len(body) < 4 || body[0] != 0x01 {
		return &peekConn{Conn: conn, buf: all}, nil
	}
	return &peekConn{Conn: conn, buf: all}, body
}

// buildTLSSignals computes UA consistency signals from TLS-layer data.
func buildTLSSignals(hasGREASE bool, cipherCount int, ua string) *TLSSignals {
	s := &TLSSignals{HasGREASE: hasGREASE, CipherCount: cipherCount}
	uaL := strings.ToLower(ua)

	isChromiumUA := strings.Contains(uaL, "chrome/") || strings.Contains(uaL, "chromium/")
	isFirefoxUA := strings.Contains(uaL, "firefox/")
	isSafariUA := strings.Contains(uaL, "safari/") && strings.Contains(uaL, "version/") && !isChromiumUA
	isBotUA := strings.Contains(uaL, "curl/") || strings.Contains(uaL, "python-requests") ||
		strings.HasPrefix(uaL, "python/") || strings.HasPrefix(uaL, "go-http-client") ||
		strings.Contains(uaL, "java/") || strings.Contains(uaL, "okhttp/") ||
		strings.Contains(uaL, "libwww") || strings.Contains(uaL, "wget/")

	if hasGREASE && !isChromiumUA {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, "grease_without_chromium_ua")
	}
	if !hasGREASE && isChromiumUA {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, "chromium_ua_without_grease")
	}
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
	if isBotUA && (isChromiumUA || isFirefoxUA || isSafariUA) {
		s.UAMismatch = true
		s.UAHints = append(s.UAHints, "conflicting_ua_identifiers")
	}
	return s
}

// Http2Fingerprint captures the real HTTP/2 protocol fingerprint
type Http2Fingerprint struct {
	// SETTINGS frame values in order received (canonical format: "ID:value")
	SettingsOrder []string `json:"settings_order"`

	// Individual settings for easy access
	HeaderTableSize      uint32 `json:"header_table_size,omitempty"`
	EnablePush           uint32 `json:"enable_push,omitempty"`
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams,omitempty"`
	InitialWindowSize    uint32 `json:"initial_window_size,omitempty"`
	MaxFrameSize         uint32 `json:"max_frame_size,omitempty"`
	MaxHeaderListSize    uint32 `json:"max_header_list_size,omitempty"`

	// WINDOW_UPDATE value (connection-level, stream 0)
	WindowUpdate uint32 `json:"window_update,omitempty"`

	// Priority frames info
	PriorityFrames []PriorityFrame `json:"priority_frames,omitempty"`

	// Pseudo-header order (e.g., "m,p,a,s" for :method,:path,:authority,:scheme)
	PseudoHeaderOrder string `json:"pseudo_header_order,omitempty"`

	// Regular header order (first 8 headers, excluding pseudo-headers)
	HeaderOrder []string `json:"header_order,omitempty"`

	// Computed fingerprint string (Akamai-style)
	// Format: "SETTINGS|WINDOW_UPDATE|PRIORITIES|PSEUDO_HEADERS"
	Fingerprint string `json:"fingerprint"`

	// Raw protocol info
	Protocol string `json:"protocol"`

	// TLS layer — populated from ClientHello captured before the TLS handshake
	JA4        string      `json:"ja4,omitempty"`
	TLSSignals *TLSSignals `json:"tls_signals,omitempty"`
	UserAgent  string      `json:"user_agent,omitempty"`

}

// PriorityFrame captures HTTP/2 PRIORITY frame data
type PriorityFrame struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}

// TokenResponse is the JSON response returned to the client
type TokenResponse struct {
	Token           string `json:"token"`
	XApiVersionHash string `json:"x-api-version-hash,omitempty"`
	Error           string `json:"error,omitempty"`
}

// probeTokenItem is the DynamoDB item written for each fingerprinted connection
type probeTokenItem struct {
	Token       string `dynamodbav:"token"`
	Fingerprint string `dynamodbav:"fingerprint"` // JSON-encoded Http2Fingerprint
	ClientIP    string `dynamodbav:"client_ip"`
	TTL         int64  `dynamodbav:"ttl"` // Unix seconds — DynamoDB TTL attribute
}

var (
	signingKey       []byte
	dynamoClient     *dynamodb.DynamoDB
	probeTokensTable string
	apiEcdhRawPubkey string
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

// initEcdhPubkey loads the API's raw ECDH public key from the environment.
// Empty = feature disabled; probe returns token only (backward compat).
func initEcdhPubkey() {
	apiEcdhRawPubkey = os.Getenv("API_ECDH_RAW_PUBKEY")
	if apiEcdhRawPubkey != "" {
		log.Printf("ECDH public key loaded (%d chars) — will embed in responses", len(apiEcdhRawPubkey))
	} else {
		log.Println("API_ECDH_RAW_PUBKEY not set — x-api-version-hash field will be omitted")
	}
}

// buildVersionHash encodes the server's ECDH public key as a JWT-shaped string.
// The payload carries the key in a "vh" (version hash) claim alongside an "iat"
// truncated to the current UTC hour — so the value rotates hourly, looking like
// a normal signed build-info token rather than a static key.
func buildVersionHash(pubkey string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	iat := time.Now().UTC().Truncate(time.Hour).Unix()
	payloadJSON := fmt.Sprintf(`{"vh":%q,"iat":%d}`, pubkey, iat)
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))

	unsigned := header + "." + payload
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + sig
}

// generateToken creates a signed token embedding the expiry and client IP.
// Format: {nonce_hex}.{expiry_ms}.{hmac_hex}
// The API verifies expiry (no key needed), then HMAC (proves IP + authenticity).
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

// storeFingerprint writes the H2 fingerprint to DynamoDB keyed by token.
func storeFingerprint(token string, fp *Http2Fingerprint, clientIP string) error {
	fpJSON, err := json.Marshal(fp)
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

// Pseudo-header short names for fingerprint
var pseudoHeaderShort = map[string]string{
	":method":    "m",
	":path":      "p",
	":authority": "a",
	":scheme":    "s",
}

var domain string

func buildFingerprintString(fp *Http2Fingerprint) string {
	var parts []string

	// Part 1: SETTINGS in canonical Akamai format (ID:value;ID:value)
	if len(fp.SettingsOrder) > 0 {
		parts = append(parts, strings.Join(fp.SettingsOrder, ";"))
	} else {
		parts = append(parts, "0")
	}

	// Part 2: WINDOW_UPDATE
	parts = append(parts, fmt.Sprintf("%d", fp.WindowUpdate))

	// Part 3: PRIORITY frames (streamID:exclusive:dependsOn:weight)
	if len(fp.PriorityFrames) > 0 {
		var prioPattern []string
		for _, p := range fp.PriorityFrames {
			exc := "0"
			if p.Exclusive {
				exc = "1"
			}
			prioPattern = append(prioPattern, fmt.Sprintf("%d:%s:%d:%d", p.StreamID, exc, p.DependsOn, p.Weight))
		}
		parts = append(parts, strings.Join(prioPattern, ","))
	} else {
		parts = append(parts, "0")
	}

	// Part 4: Pseudo-header order (m,p,a,s format)
	if fp.PseudoHeaderOrder != "" {
		parts = append(parts, fp.PseudoHeaderOrder)
	} else {
		parts = append(parts, "0")
	}

	return strings.Join(parts, "|")
}

// handleHTTP1Fallback generates a token with TLS-only signals for HTTP/1.1 clients.
// These clients are behind intercepting proxies (e.g. Cisco Umbrella) that downgrade H2.
// We still generate a valid token + store a fingerprint with TLS data, just without H2 signals.
// The token + x-api-version-hash match the same shape as the H2 success response.
func handleHTTP1Fallback(conn net.Conn, ja4Str string, hasGREASE bool, cipherCount int) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	clientIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	log.Printf("HTTP/1.1 fallback from %s — generating token with TLS-only signals", clientIP)

	// Drain the HTTP/1.1 request
	buf := make([]byte, 4096)
	conn.Read(buf)

	// Extract User-Agent from the raw HTTP/1.1 request
	userAgent := ""
	lines := strings.Split(string(buf), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			userAgent = strings.TrimSpace(line[len("user-agent:"):])
			break
		}
	}

	// Build a minimal fingerprint with TLS-only data
	fp := &Http2Fingerprint{
		Protocol:   "h1",
		JA4:        ja4Str,
		TLSSignals: buildTLSSignals(hasGREASE, cipherCount, userAgent),
		UserAgent:  userAgent,
	}

	// Generate token and store
	token, err := generateToken(clientIP)
	if err != nil {
		log.Printf("Error generating token for HTTP/1.1 client %s: %v", clientIP, err)
		writeHTTP11Response(conn, `{"error":"token_generation_failed"}`)
		return
	}
	if err := storeFingerprint(token, fp, clientIP); err != nil {
		log.Printf("Error storing H1 fingerprint for %s: %v", clientIP, err)
		// Still return the token — fingerprint storage is best-effort
	}

	resp := TokenResponse{Token: token}
	if apiEcdhRawPubkey != "" {
		resp.XApiVersionHash = buildVersionHash(apiEcdhRawPubkey)
	}
	responseBytes, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error marshaling H1 token response: %v", err)
		writeHTTP11Response(conn, `{"error":"internal"}`)
		return
	}

	writeHTTP11Response(conn, string(responseBytes))
}

// writeHTTP11Response sends a minimal HTTP/1.1 200 JSON response.
func writeHTTP11Response(conn net.Conn, body string) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + fmt.Sprintf("%d", len(body)) + "\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"Access-Control-Allow-Headers: *\r\n" +
		"Access-Control-Allow-Methods: GET, OPTIONS\r\n" +
		"Cache-Control: no-store\r\n" +
		"Connection: close\r\n\r\n" +
		body
	conn.Write([]byte(resp))
}

// handleH2Connection manually handles an HTTP/2 connection.
// ja4Str, hasGREASE, cipherCount come from the ClientHello captured before TLS.
func handleH2Connection(conn net.Conn, ja4Str string, hasGREASE bool, cipherCount int) {
	defer conn.Close()

	clientIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	// Set deadline for the entire exchange
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Create framer — do NOT call SetReuseFrames() because we store a
	// reference to the HEADERS frame and access it after further writes.
	framer := http2.NewFramer(conn, conn)

	// Read client preface (24 bytes: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	// Use io.ReadFull to guarantee all 24 bytes are read; a plain Read()
	// may return fewer bytes if TLS record boundaries split the data.
	preface := make([]byte, 24)
	if _, err := io.ReadFull(conn, preface); err != nil {
		log.Printf("Error reading preface from %s: %v", clientIP, err)
		return
	}

	expectedPreface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if string(preface) != expectedPreface {
		// Proxy negotiated h2 ALPN but sent non-H2 bytes (e.g. Cisco Umbrella SSL inspection
		// mode that agrees to h2 but then proxies as HTTP/1.1). Generate a TLS-only token.
		log.Printf("Invalid HTTP/2 preface from %s (proxy intercept) — issuing TLS-only token", clientIP)

		fp := &Http2Fingerprint{
			Protocol:   "h1-proxy",
			JA4:        ja4Str,
			TLSSignals: buildTLSSignals(hasGREASE, cipherCount, ""),
		}
		token, err := generateToken(clientIP)
		if err == nil {
			storeFingerprint(token, fp, clientIP) // best-effort
			resp := TokenResponse{Token: token}
			if apiEcdhRawPubkey != "" {
				resp.XApiVersionHash = buildVersionHash(apiEcdhRawPubkey)
			}
			if respBytes, err := json.Marshal(resp); err == nil {
				writeHTTP11Response(conn, string(respBytes))
				return
			}
		}
		writeHTTP11Response(conn, `{"error":"token_generation_failed"}`)
		return
	}

	// Collect fingerprint data
	fp := &Http2Fingerprint{
		Protocol:       "h2",
		SettingsOrder:  []string{},
		PriorityFrames: []PriorityFrame{},
		JA4:            ja4Str,
	}

	// Send our SETTINGS frame first (empty settings)
	if err := framer.WriteSettings(); err != nil {
		log.Printf("Error writing settings to %s: %v", clientIP, err)
		return
	}

	// Read frames until we get a HEADERS frame.
	// Save the stream ID and header block fragment separately so we don't
	// depend on the frame pointer remaining valid.
	var streamID uint32
	var headerBlock []byte
	hpackDecoder := hpack.NewDecoder(4096, nil)

	for i := 0; i < 20; i++ { // Max 20 frames to prevent infinite loop
		frame, err := framer.ReadFrame()
		if err != nil {
			log.Printf("Error reading frame from %s: %v", clientIP, err)
			return
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				// Capture settings in order using numeric IDs (canonical Akamai format)
				f.ForeachSetting(func(s http2.Setting) error {
					fp.SettingsOrder = append(fp.SettingsOrder, fmt.Sprintf("%d:%d", s.ID, s.Val))

					switch s.ID {
					case http2.SettingHeaderTableSize:
						fp.HeaderTableSize = s.Val
					case http2.SettingEnablePush:
						fp.EnablePush = s.Val
					case http2.SettingMaxConcurrentStreams:
						fp.MaxConcurrentStreams = s.Val
					case http2.SettingInitialWindowSize:
						fp.InitialWindowSize = s.Val
					case http2.SettingMaxFrameSize:
						fp.MaxFrameSize = s.Val
					case http2.SettingMaxHeaderListSize:
						fp.MaxHeaderListSize = s.Val
					}
					return nil
				})

				// ACK the client's settings
				if err := framer.WriteSettingsAck(); err != nil {
					log.Printf("Error writing settings ack to %s: %v", clientIP, err)
					return
				}
			}

		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				fp.WindowUpdate = f.Increment
			}

		case *http2.PriorityFrame:
			fp.PriorityFrames = append(fp.PriorityFrames, PriorityFrame{
				StreamID:  f.StreamID,
				Exclusive: f.PriorityParam.Exclusive,
				DependsOn: f.PriorityParam.StreamDep,
				Weight:    f.PriorityParam.Weight,
			})

		case *http2.HeadersFrame:
			// Copy the data we need before any further framer operations
			streamID = f.StreamID
			frag := f.HeaderBlockFragment()
			headerBlock = make([]byte, len(frag))
			copy(headerBlock, frag)
			goto sendResponse
		}
	}

sendResponse:
	if streamID == 0 {
		log.Printf("No HEADERS frame received from %s", clientIP)
		return
	}

	// Decode headers to extract pseudo-header order, regular header order, and UA
	headers, err := hpackDecoder.DecodeFull(headerBlock)
	if err == nil {
		var pseudoOrder []string
		var regularHeaders []string

		for _, hf := range headers {
			if short, isPseudo := pseudoHeaderShort[hf.Name]; isPseudo {
				pseudoOrder = append(pseudoOrder, short)
			} else {
				if hf.Name == "user-agent" {
					fp.UserAgent = hf.Value
				}
				if len(regularHeaders) < 8 {
					regularHeaders = append(regularHeaders, hf.Name)
				}
			}
		}

		if len(pseudoOrder) > 0 {
			fp.PseudoHeaderOrder = strings.Join(pseudoOrder, ",")
		}
		fp.HeaderOrder = regularHeaders
	}

	// Build TLS signals (GREASE + UA mismatch)
	fp.TLSSignals = buildTLSSignals(hasGREASE, cipherCount, fp.UserAgent)

	// Build fingerprint string
	fp.Fingerprint = buildFingerprintString(fp)

	log.Printf("H2 fingerprint from %s: %s", clientIP, fp.Fingerprint)

	// Generate token and store fingerprint server-side — client only receives the token
	token, err := generateToken(clientIP)
	if err != nil {
		log.Printf("Error generating token for %s: %v", clientIP, err)
		return
	}
	if err := storeFingerprint(token, fp, clientIP); err != nil {
		log.Printf("Error storing fingerprint for %s: %v", clientIP, err)
		return
	}

	resp := TokenResponse{Token: token}
	if apiEcdhRawPubkey != "" {
		resp.XApiVersionHash = buildVersionHash(apiEcdhRawPubkey)
	}
	responseBytes, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error marshaling token response: %v", err)
		return
	}

	// Encode response headers via HPACK
	var respHdrBuf []byte
	hpackEncoder := hpack.NewEncoder(&hpackBuf{buf: &respHdrBuf})
	hpackEncoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "access-control-allow-origin", Value: "*"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "cache-control", Value: "no-store"})

	// Send response HEADERS frame
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: respHdrBuf,
		EndHeaders:    true,
	}); err != nil {
		log.Printf("Error writing response headers: %v", err)
		return
	}

	// Send response DATA frame (endStream=true)
	if err := framer.WriteData(streamID, true, responseBytes); err != nil {
		log.Printf("Error writing response data: %v", err)
		return
	}

	// Send GOAWAY for graceful shutdown — tells the browser the connection
	// is closing cleanly rather than being abruptly reset.
	framer.WriteGoAway(streamID, http2.ErrCodeNo, nil)

	// Brief pause so the GOAWAY and response frames are flushed to the
	// network before the deferred conn.Close() fires.
	time.Sleep(50 * time.Millisecond)
}

// hpackBuf implements io.Writer for HPACK encoding
type hpackBuf struct {
	buf *[]byte
}

func (h *hpackBuf) Write(p []byte) (n int, err error) {
	*h.buf = append(*h.buf, p...)
	return len(p), nil
}

func main() {
	domain = os.Getenv("DOMAIN")
	bucket := os.Getenv("CERT_BUCKET")
	region := os.Getenv("AWS_REGION")

	if domain == "" {
		log.Fatal("DOMAIN environment variable required")
	}

	initSigningKey()
	initDynamo()
	initEcdhPubkey()

	log.Printf("Starting H2 fingerprint probe for domain: %s", domain)

	// Health check server (HTTP on 8080)
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok","service":"h2-probe"}`))
		})
		log.Printf("Starting health check server on :8080")
		if err := http.ListenAndServe(":8080", healthMux); err != nil {
			log.Printf("Health server error: %v", err)
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
		log.Printf("Using local disk for certificate storage")
		cache = autocert.DirCache("/var/lib/h2probe-certs")
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	// TLS config - prefer HTTP/2, fall back to HTTP/1.1 for proxies that don't support h2
	tlsConfig := certManager.TLSConfig()
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	tcpListener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on :443: %v", err)
	}

	// ACME HTTP-01 challenge server
	go func() {
		log.Printf("Starting HTTP server on :80 for ACME challenges")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	log.Printf("Starting HTTPS server on :443 with HTTP/2 fingerprinting")

	// Accept connections and handle manually.
	// We accept raw TCP, capture ClientHello for JA4, then perform TLS ourselves
	// so the TLS stack sees a complete record via peekConn.
	for {
		rawConn, err := tcpListener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			// Capture ClientHello before TLS consumes it
			peeked, helloBody := captureClientHello(c)
			var ja4Str string
			var hasGREASE bool
			var cipherCount int
			if helloBody != nil {
				if fields, err := parseClientHello(helloBody); err == nil {
					ja4Str = computeJA4(fields)
					hasGREASE = fields.HasGREASE
					for _, cs := range fields.CipherSuites {
						if !isGREASE(cs) {
							cipherCount++
						}
					}
				} else {
					log.Printf("JA4 parse error from %s: %v", c.RemoteAddr(), err)
				}
			}

			// Perform TLS handshake explicitly
			tlsConn := tls.Server(peeked, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake error from %s: %v", c.RemoteAddr(), err)
				tlsConn.Close()
				return
			}

			// If the proxy only negotiated HTTP/1.1 (e.g. Cisco Umbrella intelligent proxy),
			// return a proper JSON response so the proxy doesn't 502.
			if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				handleHTTP1Fallback(tlsConn, ja4Str, hasGREASE, cipherCount)
				return
			}

			handleH2Connection(tlsConn, ja4Str, hasGREASE, cipherCount)
		}(rawConn)
	}
}
