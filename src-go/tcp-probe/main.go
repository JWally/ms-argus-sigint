package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"

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
	// Low-entropy (sent by default on first request)
	UA         string `json:"ua,omitempty"`          // Sec-CH-UA
	UAMobile   string `json:"ua_mobile,omitempty"`   // Sec-CH-UA-Mobile
	UAPlatform string `json:"ua_platform,omitempty"` // Sec-CH-UA-Platform

	// High-entropy (requires Accept-CH response header, sent on subsequent requests)
	UAPlatformVersion string `json:"ua_platform_version,omitempty"` // Sec-CH-UA-Platform-Version
	UAArch            string `json:"ua_arch,omitempty"`             // Sec-CH-UA-Arch
	UABitness         string `json:"ua_bitness,omitempty"`          // Sec-CH-UA-Bitness
	UAModel           string `json:"ua_model,omitempty"`            // Sec-CH-UA-Model
	UAFullVersionList string `json:"ua_full_version_list,omitempty"` // Sec-CH-UA-Full-Version-List
	UAWOW64           string `json:"ua_wow64,omitempty"`            // Sec-CH-UA-WoW64 (Windows 32-bit on 64-bit)
	UAFormFactor      string `json:"ua_form_factor,omitempty"`      // Sec-CH-UA-Form-Factor

	// Device hints
	DeviceMemory string `json:"device_memory,omitempty"` // Device-Memory (GB of RAM)

	// Network hints
	Downlink   string `json:"downlink,omitempty"`    // Downlink (Mbps estimate)
	ECT        string `json:"ect,omitempty"`         // ECT (effective connection type: 4g, 3g, 2g, slow-2g)
	NetworkRTT string `json:"network_rtt,omitempty"` // RTT (network round-trip estimate in ms)
	SaveData   string `json:"save_data,omitempty"`   // Save-Data (data saver mode)
}

type Response struct {
	TcpInfo     *TcpInfo     `json:"tcp_info"`
	ClientHints *ClientHints `json:"client_hints,omitempty"`
	UserAgent   string       `json:"user_agent,omitempty"`
	ClientIP    string       `json:"client_ip"`
	Domain      string       `json:"domain"`
}

type ctxKey struct{}

func getTcpInfo(conn net.Conn) (*TcpInfo, error) {
	var tcpConn *net.TCPConn
	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case *tls.Conn:
		if netConn := c.NetConn(); netConn != nil {
			if tc, ok := netConn.(*net.TCPConn); ok {
				tcpConn = tc
			}
		}
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

// extractClientHints pulls all Client Hints headers from the request
func extractClientHints(r *http.Request) *ClientHints {
	ch := &ClientHints{
		// Low-entropy (default)
		UA:         r.Header.Get("Sec-CH-UA"),
		UAMobile:   r.Header.Get("Sec-CH-UA-Mobile"),
		UAPlatform: r.Header.Get("Sec-CH-UA-Platform"),

		// High-entropy (after Accept-CH)
		UAPlatformVersion: r.Header.Get("Sec-CH-UA-Platform-Version"),
		UAArch:            r.Header.Get("Sec-CH-UA-Arch"),
		UABitness:         r.Header.Get("Sec-CH-UA-Bitness"),
		UAModel:           r.Header.Get("Sec-CH-UA-Model"),
		UAFullVersionList: r.Header.Get("Sec-CH-UA-Full-Version-List"),
		UAWOW64:           r.Header.Get("Sec-CH-UA-WoW64"),
		UAFormFactor:      r.Header.Get("Sec-CH-UA-Form-Factor"),

		// Device hints
		DeviceMemory: r.Header.Get("Device-Memory"),

		// Network hints
		Downlink:   r.Header.Get("Downlink"),
		ECT:        r.Header.Get("ECT"),
		NetworkRTT: r.Header.Get("RTT"),
		SaveData:   r.Header.Get("Save-Data"),
	}

	// Return nil if no hints present at all
	if ch.UA == "" && ch.UAMobile == "" && ch.UAPlatform == "" {
		return nil
	}

	return ch
}

// setClientHintHeaders tells browser to send high-entropy hints on next request
func setClientHintHeaders(w http.ResponseWriter) {
	// Request all available client hints
	w.Header().Set("Accept-CH",
		"Sec-CH-UA, "+
			"Sec-CH-UA-Mobile, "+
			"Sec-CH-UA-Platform, "+
			"Sec-CH-UA-Platform-Version, "+
			"Sec-CH-UA-Arch, "+
			"Sec-CH-UA-Bitness, "+
			"Sec-CH-UA-Model, "+
			"Sec-CH-UA-Full-Version-List, "+
			"Sec-CH-UA-WoW64, "+
			"Sec-CH-UA-Form-Factor, "+
			"Device-Memory, "+
			"Downlink, "+
			"ECT, "+
			"RTT, "+
			"Save-Data")

	// Critical-CH forces a retry if hints are missing (Chromium 96+)
	// Use sparingly - adds latency on first request
	w.Header().Set("Critical-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch")
}

func main() {
	domain := os.Getenv("DOMAIN")
	bucket := os.Getenv("CERT_BUCKET")
	region := os.Getenv("AWS_REGION")

	if domain == "" {
		log.Fatal("DOMAIN environment variable required")
	}

	log.Printf("Starting TCP probe server for domain: %s", domain)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Request client hints for subsequent requests
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

		if info, ok := r.Context().Value(ctxKey{}).(*TcpInfo); ok {
			response.TcpInfo = info
		}

		json.NewEncoder(w).Encode(response)
	})

	// Health check server
	go func() {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
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
		log.Printf("Using local disk for certificate storage (Ephemeral!)")
		cache = autocert.DirCache("/var/lib/tcpprobe-certs")
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      cache,
	}

	server := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: certManager.TLSConfig(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			info, err := getTcpInfo(c)
			if err != nil {
				log.Printf("Failed to get TCP info: %v", err)
				return ctx
			}
			return context.WithValue(ctx, ctxKey{}, info)
		},
	}

	// ACME HTTP-01 challenge server
	go func() {
		log.Printf("Starting HTTP server on :80 for ACME challenges")
		if err := http.ListenAndServe(":80", certManager.HTTPHandler(nil)); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	log.Printf("Starting HTTPS server on :443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}