package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"stun-server/cipher"
)

// Usage: decryptv6 <hex16bytes>...
func main() {
	key, _ := hex.DecodeString(os.Getenv("SIGINT_AES_KEY"))
	v, _ := cipher.NewV6Payload(key, nil, "argus-sigint-v6-payload-v1")
	now := time.Now()
	for _, h := range os.Args[1:] {
		raw, err := hex.DecodeString(h)
		if err != nil {
			fmt.Printf("%s: bad hex: %v\n", h, err)
			continue
		}
		dec, err := v.Decode(raw, now)
		if err != nil {
			fmt.Printf("%s: decode error: %v\n", h, err)
			continue
		}
		fmt.Printf("ct=%s\n  ip=%s epoch=%d age=%ds nonce=%08x mac_valid=%v\n",
			h, dec.IP, dec.Epoch, dec.AgeSec, dec.Nonce, dec.ValidMAC)
	}
}
