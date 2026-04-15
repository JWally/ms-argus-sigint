package main

import (
	"encoding/binary"
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

// ipCipher encrypts client IPv4 addresses before returning them in
// XOR-MAPPED-ADDRESS. nil means pass-through (unset key).
var ipCipher *cipher.Feistel32

// portTagger derives a 16-bit HMAC tag bound to (clientIP, timeBucket) which
// the STUN server places into the XOR-MAPPED-ADDRESS port field in lieu of
// the source port. nil means pass through the source port unchanged.
var portTagger *cipher.PortTagger

// portTagBucketSeconds is the granularity of the time bucket bound into each
// port tag. Backends must accept tags for the current and previous bucket to
// tolerate clock skew and responses that straddle a boundary.
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
	ipCipher = ic
	portTagger = pt
	log.Println("IPv4 cipher and port tagger initialized")
}

// reportedAddress returns the IP/port to place into XOR-MAPPED-ADDRESS for a
// client observed at src. Non-v4 addresses and unset ciphers pass through
// unchanged; v4 addresses are Feistel-encrypted with cycle-walking past
// ranges that browsers are known to drop from srflx candidates, and the
// source port is replaced with a 16-bit HMAC tag bound to the plaintext IP
// and the current 5-minute time bucket.
func reportedAddress(src net.IP, port int) (net.IP, int) {
	if ipCipher == nil {
		return src, port
	}
	ip4 := src.To4()
	if ip4 == nil {
		return src, port
	}
	ct := ipCipher.Encrypt(binary.BigEndian.Uint32(ip4))
	for isReservedIPv4(ct) {
		ct = ipCipher.Encrypt(ct)
	}
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, ct)

	bucket := time.Now().Unix() / portTagBucketSeconds
	tag := portTagger.Tag(ip4, bucket)
	return out, cipher.PortFromTag(tag)
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

	response, err := stun.Build(
		stun.TransactionID,
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: reportedIP, Port: reportedPort},
		stun.Fingerprint,
	)
	if err != nil {
		log.Printf("Failed to build STUN response: %v", err)
		return
	}

	copy(response.TransactionID[:], msg.TransactionID[:])
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
			stun.TransactionID,
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: reportedIP, Port: reportedPort},
			stun.Fingerprint,
		)
		if err != nil {
			log.Printf("Failed to build TCP STUN response: %v", err)
			continue
		}

		copy(response.TransactionID[:], msg.TransactionID[:])
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
