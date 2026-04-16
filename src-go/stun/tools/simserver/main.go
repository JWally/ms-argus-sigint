package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"stun-server/cipher"
)

func main() {
	key, _ := hex.DecodeString(os.Getenv("SIGINT_AES_KEY"))
	v, _ := cipher.NewV6Payload(key, nil, "argus-sigint-v6-payload-v1")
	fmt.Println("key_fp:", v.DebugFingerprint())
	ip := net.ParseIP("107.210.133.127").To4()
	now := time.Now()
	ct, _ := v.Encode(ip, now)
	fmt.Printf("encode(107.210.133.127, now) ct=%x\n", ct)
	dec, _ := v.Decode(ct, now)
	fmt.Printf("decode -> ip=%s epoch=%d nonce=%08x mac_valid=%v\n",
		dec.IP, dec.Epoch, dec.Nonce, dec.ValidMAC)
}
