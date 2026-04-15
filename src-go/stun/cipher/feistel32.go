// Package cipher implements a 32-bit block cipher used to encrypt IPv4
// addresses so they can be returned in STUN XOR-MAPPED-ADDRESS without
// revealing the client's true reflexive IP to the client itself.
package cipher

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Feistel32 is a 4-round Feistel network over 32-bit blocks using
// HMAC-SHA256 as the round function. By Luby-Rackoff this yields a
// pseudorandom permutation suitable for format-preserving encryption
// of 32-bit values (e.g., IPv4 addresses).
type Feistel32 struct {
	roundKeys [4][]byte
}

// NewFeistel32 derives four round keys from secret via HKDF-SHA256.
// info is used for domain separation — use distinct info strings per
// purpose (e.g. "argus-sigint-ipv4-v1") so the same secret can't be
// confused across contexts.
func NewFeistel32(secret, salt []byte, info string) (*Feistel32, error) {
	kdf := hkdf.New(sha256.New, secret, salt, []byte(info))
	var f Feistel32
	for i := range f.roundKeys {
		key := make([]byte, 32)
		if _, err := io.ReadFull(kdf, key); err != nil {
			return nil, err
		}
		f.roundKeys[i] = key
	}
	return &f, nil
}

func (f *Feistel32) round(r uint16, key []byte) uint16 {
	mac := hmac.New(sha256.New, key)
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], r)
	mac.Write(b[:])
	sum := mac.Sum(nil)
	return binary.BigEndian.Uint16(sum[:2])
}

// Encrypt transforms a 32-bit plaintext into a 32-bit ciphertext.
func (f *Feistel32) Encrypt(x uint32) uint32 {
	L := uint16(x >> 16)
	R := uint16(x)
	for i := 0; i < 4; i++ {
		L, R = R, L^f.round(R, f.roundKeys[i])
	}
	return uint32(L)<<16 | uint32(R)
}

// Decrypt inverts Encrypt.
func (f *Feistel32) Decrypt(y uint32) uint32 {
	L := uint16(y >> 16)
	R := uint16(y)
	for i := 3; i >= 0; i-- {
		L, R = R^f.round(L, f.roundKeys[i]), L
	}
	return uint32(L)<<16 | uint32(R)
}
