package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/pion/stun"
)

// Response returned by the HTTP endpoint for debugging/verification
type Response struct {
	ReflexiveIP   string `json:"reflexive_ip"`
	ReflexivePort int    `json:"reflexive_port"`
	LocalIP       string `json:"local_ip,omitempty"`
	Domain        string `json:"domain"`
	Protocol      string `json:"protocol"`
}

func main() {
	domain := os.Getenv("DOMAIN")
	stunPort := os.Getenv("STUN_PORT")
	if stunPort == "" {
		stunPort = "3478"
	}

	if domain == "" {
		log.Fatal("DOMAIN environment variable required")
	}

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

	log.Printf("UDP Binding request from %s", remoteAddr)

	// Build response with XOR-MAPPED-ADDRESS
	response, err := stun.Build(
		stun.TransactionID,
		stun.BindingSuccess,
		&stun.XORMappedAddress{
			IP:   remoteAddr.IP,
			Port: remoteAddr.Port,
		},
		stun.Fingerprint,
	)
	if err != nil {
		log.Printf("Failed to build STUN response: %v", err)
		return
	}

	// Copy transaction ID from request
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

		log.Printf("TCP Binding request from %s", remoteAddr)

		// Build response
		response, err := stun.Build(
			stun.TransactionID,
			stun.BindingSuccess,
			&stun.XORMappedAddress{
				IP:   remoteAddr.IP,
				Port: remoteAddr.Port,
			},
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
