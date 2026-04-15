package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"stun-server/cipher"
)

func main() {
	keyHex := os.Getenv("SIGINT_AES_KEY")
	key, _ := hex.DecodeString(keyHex)
	f, _ := cipher.NewFeistel32(key, nil, "argus-sigint-ipv4-v1")
	ct := net.ParseIP(os.Args[1]).To4()
	dec := f.Decrypt(binary.BigEndian.Uint32(ct))
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, dec)
	fmt.Printf("ciphertext=%s  plaintext=%s\n", os.Args[1], out)
}
