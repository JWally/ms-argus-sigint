package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"stun-server/cipher"
)

func main() {
	key, _ := hex.DecodeString(os.Getenv("SIGINT_AES_KEY"))
	v, _ := cipher.NewV6Payload(key, nil, "argus-sigint-v6-payload-v1")
	fmt.Println("local key_fp:", v.DebugFingerprint())
}
