package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"stun-server/cipher"
)

// Usage: checkport <plaintextIP> <observedPort>
func main() {
	key, _ := hex.DecodeString(os.Getenv("SIGINT_AES_KEY"))
	pt, _ := cipher.NewPortTagger(key, nil, "argus-sigint-port-tag-v1")
	ip := net.ParseIP(os.Args[1]).To4()
	observed, _ := fmt.Sscanf(os.Args[2], "%d", new(int))
	_ = observed
	var obs int
	fmt.Sscanf(os.Args[2], "%d", &obs)
	now := time.Now().Unix() / 300
	for _, off := range []int64{0, -1} {
		b := now + off
		p := cipher.PortFromTag(pt.Tag(ip, b))
		match := ""
		if p == obs {
			match = "  <-- MATCH"
		}
		fmt.Printf("bucket=%d expected_port=%d%s\n", b, p, match)
	}
}
