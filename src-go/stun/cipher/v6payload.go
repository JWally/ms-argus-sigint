package cipher

import (
	"crypto/aes"
	cryptorand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

// V6PayloadSize is the size of a serialized attestation payload (128 bits,
// the full IPv6 XOR-MAPPED-ADDRESS field).
const V6PayloadSize = 16

// V6Payload encodes an authenticated attestation of a client's observed
// IPv4 reflexive address into a 128-bit block suitable for packing into the
// IPv6-family XOR-MAPPED-ADDRESS attribute of a STUN Binding Response.
//
// Wire layout (before encryption):
//
//	byte  0..3  : clientIPv4          (big-endian uint32)
//	byte  4..7  : epoch seconds        (big-endian uint32)
//	byte  8..11 : random nonce         (crypto/rand)
//	byte 12..15 : HMAC-SHA256 tag      (truncated to 4 bytes, over bytes 0..11)
//
// The whole 16-byte block is then encrypted as a single AES-128 block using
// the encryption key derived from the shared secret. AES is a PRP over a
// 128-bit block, so ECB on a single block is equivalent to CBC with IV=0;
// mode selection is moot at exactly one block. The per-response random
// nonce ensures identical clients produce distinct ciphertexts.
type V6Payload struct {
	encBlock func(dst, src []byte) // aes.Block.Encrypt
	decBlock func(dst, src []byte) // aes.Block.Decrypt
	macKey   []byte
}

// NewV6Payload derives independent encryption and MAC keys from the shared
// secret via HKDF-SHA256 and returns a Payload encoder/decoder.
func NewV6Payload(secret, salt []byte, info string) (*V6Payload, error) {
	kdf := hkdf.New(sha256.New, secret, salt, []byte(info))
	encKey := make([]byte, 16)
	if _, err := io.ReadFull(kdf, encKey); err != nil {
		return nil, fmt.Errorf("derive enc key: %w", err)
	}
	macKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, macKey); err != nil {
		return nil, fmt.Errorf("derive mac key: %w", err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes new: %w", err)
	}
	return &V6Payload{
		encBlock: block.Encrypt,
		decBlock: block.Decrypt,
		macKey:   macKey,
	}, nil
}

// Encode builds a 16-byte authenticated, encrypted attestation of clientIP at
// the current wall clock. The returned byte slice is intended to be placed
// into the IPv6 address field of XOR-MAPPED-ADDRESS.
func (v *V6Payload) Encode(clientIP net.IP, now time.Time) ([]byte, error) {
	ip4 := clientIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("v6 payload requires IPv4 client; got %s", clientIP)
	}
	plain := make([]byte, V6PayloadSize)
	copy(plain[0:4], ip4)
	binary.BigEndian.PutUint32(plain[4:8], uint32(now.Unix()))
	if _, err := io.ReadFull(cryptorand.Reader, plain[8:12]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	tag := v.computeTag(plain[0:12])
	copy(plain[12:16], tag)

	ct := make([]byte, V6PayloadSize)
	v.encBlock(ct, plain)
	return ct, nil
}

// Decoded is the output of Decode.
type Decoded struct {
	IP        net.IP
	Epoch     uint32
	Nonce     uint32
	NonceRaw  [4]byte
	AgeSec    int64 // now - epoch, signed (positive = past)
	ValidMAC  bool
}

// Decode reverses Encode. It decrypts and verifies the MAC, returning the
// extracted fields and a flag indicating MAC validity. Callers must still
// enforce freshness (|AgeSec| < window) and one-shot replay (via the nonce
// or full raw block) at the verification layer.
func (v *V6Payload) Decode(ciphertext []byte, now time.Time) (*Decoded, error) {
	if len(ciphertext) != V6PayloadSize {
		return nil, fmt.Errorf("expected %d bytes, got %d", V6PayloadSize, len(ciphertext))
	}
	plain := make([]byte, V6PayloadSize)
	v.decBlock(plain, ciphertext)

	expected := v.computeTag(plain[0:12])
	valid := hmac.Equal(expected, plain[12:16])

	ip := net.IPv4(plain[0], plain[1], plain[2], plain[3]).To4()
	epoch := binary.BigEndian.Uint32(plain[4:8])
	nonce := binary.BigEndian.Uint32(plain[8:12])
	var nonceRaw [4]byte
	copy(nonceRaw[:], plain[8:12])

	age := now.Unix() - int64(epoch)
	return &Decoded{
		IP:       ip,
		Epoch:    epoch,
		Nonce:    nonce,
		NonceRaw: nonceRaw,
		AgeSec:   age,
		ValidMAC: valid,
	}, nil
}

func (v *V6Payload) computeTag(b []byte) []byte {
	mac := hmac.New(sha256.New, v.macKey)
	mac.Write(b)
	return mac.Sum(nil)[:4]
}

// DebugFingerprint returns the first 4 bytes of a test-encryption of the
// all-zeros plaintext. This provides a safe, non-secret identity for the
// derived key material so server logs and offline tools can confirm they
// agree on the same keys without exposing them.
func (v *V6Payload) DebugFingerprint() string {
	probe := make([]byte, 16)
	out := make([]byte, 16)
	v.encBlock(out, probe)
	return fmt.Sprintf("%x", out[:4])
}
