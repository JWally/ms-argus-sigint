package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pion/stun"

	"stun-server/cipher"
)

func main() {
	conn, err := net.Dial("udp", "dev-jw-stun.argus.pw:3478")
	if err != nil { panic(err) }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil { panic(err) }
	if _, err := conn.Write(msg.Raw); err != nil { panic(err) }

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil { panic(err) }

	resp := &stun.Message{Raw: buf[:n]}
	if err := resp.Decode(); err != nil { panic(err) }

	var xm stun.XORMappedAddress
	if err := xm.GetFrom(resp); err != nil { panic(err) }
	fmt.Printf("pion-parsed: IP=%s (len=%d) Port=%d\n", xm.IP, len(xm.IP), xm.Port)
	fmt.Printf("IP hex: %s\n", hex.EncodeToString(xm.IP))

	// Try decrypting with local key
	key, _ := hex.DecodeString(os.Getenv("SIGINT_AES_KEY"))
	v, _ := cipher.NewV6Payload(key, nil, "argus-sigint-v6-payload-v1")
	dec, err := v.Decode(xm.IP, time.Now())
	if err != nil { fmt.Println("decode err:", err); return }
	fmt.Printf("decoded: ip=%s epoch=%d age=%d nonce=%08x mac_valid=%v\n",
		dec.IP, dec.Epoch, dec.AgeSec, dec.Nonce, dec.ValidMAC)
}
