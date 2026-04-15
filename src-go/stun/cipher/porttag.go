package cipher

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"
)

// PortTagger produces a 16-bit HMAC-SHA256 tag over (clientIP || timeBucket)
// that fits into the STUN XOR-MAPPED-ADDRESS port field. Backends verify the
// tag to prove the response came from a server holding the same root secret,
// binds to the plaintext IP recovered from the Feistel-encrypted IP field,
// and is recent (within the allowed bucket window).
type PortTagger struct {
	key []byte
}

// NewPortTagger derives an HMAC key from secret via HKDF-SHA256. Use a
// distinct info string from the IP cipher for domain separation.
func NewPortTagger(secret, salt []byte, info string) (*PortTagger, error) {
	kdf := hkdf.New(sha256.New, secret, salt, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return &PortTagger{key: key}, nil
}

// Tag returns the raw 16-bit HMAC tag for (ip, bucket). Callers should
// convert this to a port value via PortFromTag.
func (p *PortTagger) Tag(ip net.IP, bucket int64) uint16 {
	mac := hmac.New(sha256.New, p.key)
	if v4 := ip.To4(); v4 != nil {
		mac.Write(v4)
	} else {
		mac.Write(ip.To16())
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	mac.Write(b[:])
	return binary.BigEndian.Uint16(mac.Sum(nil)[:2])
}

// PortFromTag maps a raw 16-bit tag to an unprivileged UDP port in
// [1024, 65535]. Deterministic; backend verifiers compute PortFromTag(Tag(...))
// and constant-time compare to the received port.
func PortFromTag(tag uint16) int {
	return 1024 + int(tag)%(65536-1024)
}
