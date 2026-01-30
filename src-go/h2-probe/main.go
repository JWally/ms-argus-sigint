package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
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
	// SETTINGS frame values in order received
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

	// Computed fingerprint string (Akamai-style)
	// Format: "SETTINGS|WINDOW_UPDATE|PRIORITIES"
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

// Setting name lookup
var settingNames = map[http2.SettingID]string{
	http2.SettingHeaderTableSize:      "HEADER_TABLE_SIZE",
	http2.SettingEnablePush:           "ENABLE_PUSH",
	http2.SettingMaxConcurrentStreams: "MAX_CONCURRENT_STREAMS",
	http2.SettingInitialWindowSize:    "INITIAL_WINDOW_SIZE",
	http2.SettingMaxFrameSize:         "MAX_FRAME_SIZE",
	http2.SettingMaxHeaderListSize:    "MAX_HEADER_LIST_SIZE",
}

var domain string

func buildFingerprintString(fp *Http2Fingerprint) string {
	var parts []string

	// Part 1: SETTINGS in order (just values, comma-separated)
	var settingsValues []string
	for _, s := range fp.SettingsOrder {
		if idx := strings.Index(s, ":"); idx >= 0 {
			settingsValues = append(settingsValues, s[idx+1:])
		}
	}
	if len(settingsValues) > 0 {
		parts = append(parts, strings.Join(settingsValues, ","))
	} else {
		parts = append(parts, "0")
	}

	// Part 2: WINDOW_UPDATE
	parts = append(parts, fmt.Sprintf("%d", fp.WindowUpdate))

	// Part 3: PRIORITY frames count and pattern
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

	return strings.Join(parts, "|")
}

// handleH2Connection manually handles an HTTP/2 connection
func handleH2Connection(conn net.Conn) {
	defer conn.Close()

	clientIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	// Set read deadline
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Create framer
	framer := http2.NewFramer(conn, conn)
	framer.SetReuseFrames()

	// Read client preface (24 bytes: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	preface := make([]byte, 24)
	if _, err := conn.Read(preface); err != nil {
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

	// Read frames until we get a HEADERS frame
	var headersFrame *http2.HeadersFrame
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
				// Capture settings in order
				f.ForeachSetting(func(s http2.Setting) error {
					name := settingNames[s.ID]
					if name == "" {
						name = fmt.Sprintf("UNKNOWN_%d", s.ID)
					}
					fp.SettingsOrder = append(fp.SettingsOrder, fmt.Sprintf("%s:%d", name, s.Val))

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

				// ACK the settings
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
			headersFrame = f
			// Stop reading frames once we get HEADERS
			goto sendResponse
		}
	}

sendResponse:
	if headersFrame == nil {
		log.Printf("No HEADERS frame received from %s", clientIP)
		return
	}

	// Decode headers (we don't really need them, but must decode for protocol)
	_, _ = hpackDecoder.DecodeFull(headersFrame.HeaderBlockFragment())

	// Build fingerprint string
	fp.Fingerprint = buildFingerprintString(fp)

	log.Printf("H2 fingerprint from %s: %s", clientIP, fp.Fingerprint)

	// Build response
	response := Response{
		Fingerprint: fp,
		ClientIP:    clientIP,
		Domain:      domain,
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		return
	}

	// Send response headers
	var respHdrBuf []byte
	hpackEncoder := hpack.NewEncoder(&hpackBuf{buf: &respHdrBuf})
	hpackEncoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "access-control-allow-origin", Value: "*"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "access-control-allow-credentials", Value: "true"})
	hpackEncoder.WriteField(hpack.HeaderField{Name: "cache-control", Value: "no-store"})

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      headersFrame.StreamID,
		BlockFragment: respHdrBuf,
		EndHeaders:    true,
	}); err != nil {
		log.Printf("Error writing response headers: %v", err)
		return
	}

	// Send response body
	if err := framer.WriteData(headersFrame.StreamID, true, responseBytes); err != nil {
		log.Printf("Error writing response data: %v", err)
		return
	}
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
