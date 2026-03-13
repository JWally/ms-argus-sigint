package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

	s3cache "github.com/danilobuerger/autocert-s3-cache"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

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
}

// PriorityFrame captures HTTP/2 PRIORITY frame data
type PriorityFrame struct {
	StreamID  uint32 `json:"stream_id"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
	Weight    uint8  `json:"weight"`
}

// Response is the JSON response from the h2-probe endpoint
type Response struct {
	Fingerprint *Http2Fingerprint `json:"h2_fingerprint"`
	ClientIP    string            `json:"client_ip"`
	Domain      string            `json:"domain"`
	Error       string            `json:"error,omitempty"`
}

type EncryptedResponse struct {
	Version int    `json:"v"`
	Data    string `json:"data"`
}

// AES-256-GCM key for response encryption (nil = plaintext mode)
var aesGCM cipher.AEAD

func initEncryption() {
	keyHex := os.Getenv("SIGINT_AES_KEY")
	if keyHex == "" {
		log.Println("SIGINT_AES_KEY not set — responses will be plaintext")
		return
	}
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil || len(keyBytes) != 32 {
		log.Fatalf("SIGINT_AES_KEY must be 64 hex chars (32 bytes): %v", err)
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Fatalf("AES cipher init failed: %v", err)
	}
	aesGCM, err = cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("GCM init failed: %v", err)
	}
	log.Println("AES-256-GCM response encryption enabled")
}

func encryptResponse(data any) ([]byte, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if aesGCM == nil {
		return plaintext, nil
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	wrapped := EncryptedResponse{
		Version: 1,
		Data:    base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.Marshal(wrapped)
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

// handleH2Connection manually handles an HTTP/2 connection
func handleH2Connection(conn net.Conn) {
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
		log.Printf("Invalid HTTP/2 preface from %s", clientIP)
		return
	}

	// Collect fingerprint data
	fp := &Http2Fingerprint{
		Protocol:       "h2",
		SettingsOrder:  []string{},
		PriorityFrames: []PriorityFrame{},
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

	// Decode headers to extract pseudo-header order and regular header order
	headers, err := hpackDecoder.DecodeFull(headerBlock)
	if err == nil {
		var pseudoOrder []string
		var regularHeaders []string

		for _, hf := range headers {
			if short, isPseudo := pseudoHeaderShort[hf.Name]; isPseudo {
				pseudoOrder = append(pseudoOrder, short)
			} else if len(regularHeaders) < 8 {
				regularHeaders = append(regularHeaders, hf.Name)
			}
		}

		if len(pseudoOrder) > 0 {
			fp.PseudoHeaderOrder = strings.Join(pseudoOrder, ",")
		}
		fp.HeaderOrder = regularHeaders
	}

	// Build fingerprint string
	fp.Fingerprint = buildFingerprintString(fp)

	log.Printf("H2 fingerprint from %s: %s", clientIP, fp.Fingerprint)

	// Build response
	response := Response{
		Fingerprint: fp,
		ClientIP:    clientIP,
		Domain:      domain,
	}

	responseBytes, err := encryptResponse(response)
	if err != nil {
		log.Printf("Error marshaling/encrypting response: %v", err)
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

	initEncryption()

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

	// TLS config - HTTP/2 only
	tlsConfig := certManager.TLSConfig()
	tlsConfig.NextProtos = []string{"h2"}

	// Create TCP listener
	tcpListener, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen on :443: %v", err)
	}

	// Create TLS listener
	tlsLn := tls.NewListener(tcpListener, tlsConfig)

	// ACME HTTP-01 challenge server
	go func() {
		log.Printf("Starting HTTP server on :80 for ACME challenges")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	log.Printf("Starting HTTPS server on :443 with HTTP/2 fingerprinting")

	// Accept connections and handle manually
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleH2Connection(conn)
	}
}
