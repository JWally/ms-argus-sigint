package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pion/stun"

	"stun-server/cipher"
)

// Response returned by the HTTP endpoint for debugging/verification
type Response struct {
	ReflexiveIP   string `json:"reflexive_ip"`
	ReflexivePort int    `json:"reflexive_port"`
	LocalIP       string `json:"local_ip,omitempty"`
	Domain        string `json:"domain"`
	Protocol      string `json:"protocol"`
}

// v6Payload builds authenticated, encrypted attestation blobs that the STUN
// server returns as the 128-bit IPv6 address of XOR-MAPPED-ADDRESS even when
// the client connected over IPv4. RFC 8489 §6.3.4 explicitly permits
// clients to accept a family-mismatched XOR-MAPPED-ADDRESS; libwebrtc
// (Chromium/Firefox/Safari) surfaces the attribute to JavaScript as an srflx
// candidate without filtering. This gives us 128 bits of signed, nonce'd
// payload in a single response instead of the 48 we'd get in v4 form.
var v6Payload *cipher.V6Payload

// reportedPortOnAuth is the TCP/UDP port echoed back in XOR-MAPPED-ADDRESS
// when v6Payload is active. The value is cosmetic — clients won't open a
// connection to it — so we pick a plausible HTTPS port.
const reportedPortOnAuth = 443

// ipCipher encrypts client IPv4 addresses before returning them in the v4
// form of XOR-MAPPED-ADDRESS. Retained for fallback; unused while v6Payload
// is active.
var ipCipher *cipher.Feistel32

// portTagger derives a 16-bit HMAC tag bound to (clientIP, timeBucket) for
// the port field of v4-form XOR-MAPPED-ADDRESS. Retained for fallback;
// unused while v6Payload is active.
var portTagger *cipher.PortTagger

// portTagBucketSeconds is the v4-form port-tag bucket width (unused while
// v6Payload is active).
const portTagBucketSeconds = 300

func main() {
	domain := os.Getenv("DOMAIN")
	stunPort := os.Getenv("STUN_PORT")
	if stunPort == "" {
		stunPort = "3478"
	}

	if domain == "" {
		log.Fatal("DOMAIN environment variable required")
	}

	initCrypto()

	log.Printf("Starting STUN server for domain: %s", domain)

	// Start UDP STUN server
	go func() {
		if err := startUDPServer(stunPort); err != nil {
			log.Fatalf("UDP STUN server failed: %v", err)
		}
	}()

	// Start TCP STUN server
	go func() {
		if err := startTCPServer(stunPort); err != nil {
			log.Fatalf("TCP STUN server failed: %v", err)
		}
	}()

	// Health check + HTTP info endpoint
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Info endpoint - returns server info (not STUN, just metadata)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Cache-Control", "no-store")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		clientIP := r.RemoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		response := map[string]interface{}{
			"domain":    domain,
			"stun_port": stunPort,
			"stun_uri":  fmt.Sprintf("stun:%s:%s", domain, stunPort),
			"client_ip": clientIP,
			"protocols": []string{"udp", "tcp"},
		}
		json.NewEncoder(w).Encode(response)
	})

	log.Printf("Starting health/info server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func initCrypto() {
	keyHex := os.Getenv("SIGINT_AES_KEY")
	if keyHex == "" {
		log.Println("SIGINT_AES_KEY not set — returning plaintext client IPs and source ports in STUN responses")
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		log.Fatalf("SIGINT_AES_KEY must be 64 hex chars (32 bytes): %v", err)
	}
	ic, err := cipher.NewFeistel32(key, nil, "argus-sigint-ipv4-v1")
	if err != nil {
		log.Fatalf("Feistel32 init failed: %v", err)
	}
	pt, err := cipher.NewPortTagger(key, nil, "argus-sigint-port-tag-v1")
	if err != nil {
		log.Fatalf("PortTagger init failed: %v", err)
	}
	vp, err := cipher.NewV6Payload(key, nil, "argus-sigint-v6-payload-v1")
	if err != nil {
		log.Fatalf("V6Payload init failed: %v", err)
	}
	ipCipher = ic
	portTagger = pt
	v6Payload = vp
	log.Printf("v6 attestation payload initialized — key_fp=%s info=argus-sigint-v6-payload-v1", vp.DebugFingerprint())
}

// reportedAddress returns the IP/port to place into XOR-MAPPED-ADDRESS for a
// client observed at src. When v6Payload is active, the returned "IP" is
// actually a 16-byte encrypted attestation blob (IP ‖ epoch ‖ nonce ‖ MAC),
// emitted as the IPv6 form of XOR-MAPPED-ADDRESS even for v4 clients.
// If no secret is configured the source address passes through unchanged.
func reportedAddress(src net.IP, port int) (net.IP, int) {
	if v6Payload == nil {
		return src, port
	}
	ip4 := src.To4()
	if ip4 == nil {
		return src, port
	}
	now := time.Now()
	blob, err := v6Payload.Encode(ip4, now)
	if err != nil {
		log.Printf("v6Payload.Encode failed for %s: %v", src, err)
		return src, port
	}
	// Also decode with the same payload to prove end-to-end consistency on
	// the server; any mismatch between what we Encode and what Decode gets
	// back would indicate a bug.
	if dec, err := v6Payload.Decode(blob, now); err == nil {
		log.Printf("encode: src_ip=%s ip4=%x epoch=%d blob=%x self_decode_ip=%s self_mac=%v",
			src, []byte(ip4), now.Unix(), blob, dec.IP, dec.ValidMAC)
	}
	return net.IP(blob), reportedPortOnAuth
}

// isReservedIPv4 reports whether an IPv4 address (as a 32-bit word) falls in
// a range that WebRTC implementations commonly filter from srflx candidates.
// Cycle-walking over these keeps the output bijective while avoiding drops.
func isReservedIPv4(ip uint32) bool {
	a := byte(ip >> 24)
	b := byte(ip >> 16)
	switch {
	case a == 0: // 0.0.0.0/8
		return true
	case a == 127: // loopback
		return true
	case a == 169 && b == 254: // link-local
		return true
	case a >= 224: // multicast + reserved + broadcast
		return true
	}
	return false
}

func startUDPServer(port string) error {
	addr, err := net.ResolveUDPAddr("udp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}
	defer conn.Close()

	log.Printf("UDP STUN server listening on :%s", port)

	buf := make([]byte, 1500)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			continue
		}

		go handleUDPRequest(conn, remoteAddr, buf[:n])
	}
}

func handleUDPRequest(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	msg := &stun.Message{Raw: data}
	if err := msg.Decode(); err != nil {
		log.Printf("Failed to decode STUN message from %s: %v", remoteAddr, err)
		return
	}

	if msg.Type != stun.BindingRequest {
		log.Printf("Ignoring non-binding request from %s: %s", remoteAddr, msg.Type)
		return
	}

	reportedIP, reportedPort := reportedAddress(remoteAddr.IP, remoteAddr.Port)

	// Use the request's transaction ID for the response so that the XOR
	// applied by XORMappedAddress.AddTo — which is keyed on
	// magicCookie || transactionID — inverts correctly on the client.
	response, err := stun.Build(
		stun.NewTransactionIDSetter(msg.TransactionID),
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: reportedIP, Port: reportedPort},
		stun.Fingerprint,
	)
	if err != nil {
		log.Printf("Failed to build STUN response: %v", err)
		return
	}

	response.Encode()

	if _, err := conn.WriteToUDP(response.Raw, remoteAddr); err != nil {
		log.Printf("Failed to send UDP response to %s: %v", remoteAddr, err)
	}
}

func startTCPServer(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("failed to listen TCP: %w", err)
	}
	defer listener.Close()

	log.Printf("TCP STUN server listening on :%s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP accept error: %v", err)
			continue
		}

		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	// TCP STUN has a 2-byte length prefix before each message
	header := make([]byte, 2)
	for {
		// Read length prefix
		if _, err := conn.Read(header); err != nil {
			return // Connection closed
		}

		length := int(header[0])<<8 | int(header[1])
		if length > 1500 || length < 20 {
			log.Printf("Invalid STUN message length from %s: %d", remoteAddr, length)
			return
		}

		// Read message body
		data := make([]byte, length)
		if _, err := conn.Read(data); err != nil {
			log.Printf("TCP read error from %s: %v", remoteAddr, err)
			return
		}

		msg := &stun.Message{Raw: data}
		if err := msg.Decode(); err != nil {
			log.Printf("Failed to decode TCP STUN from %s: %v", remoteAddr, err)
			continue
		}

		if msg.Type != stun.BindingRequest {
			continue
		}

		reportedIP, reportedPort := reportedAddress(remoteAddr.IP, remoteAddr.Port)

		response, err := stun.Build(
			stun.NewTransactionIDSetter(msg.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: reportedIP, Port: reportedPort},
			stun.Fingerprint,
		)
		if err != nil {
			log.Printf("Failed to build TCP STUN response: %v", err)
			continue
		}

		response.Encode()

		// Write with length prefix
		respLen := len(response.Raw)
		prefixed := make([]byte, 2+respLen)
		prefixed[0] = byte(respLen >> 8)
		prefixed[1] = byte(respLen)
		copy(prefixed[2:], response.Raw)

		if _, err := conn.Write(prefixed); err != nil {
			log.Printf("Failed to send TCP response to %s: %v", remoteAddr, err)
		}
	}
}
