package cipher

import (
	"net"
	"testing"
	"time"
)

func newV6Payload(t *testing.T) *V6Payload {
	t.Helper()
	v, err := NewV6Payload([]byte("test-secret-do-not-use-in-prod"), nil, "v6-payload-test")
	if err != nil {
		t.Fatalf("NewV6Payload: %v", err)
	}
	return v
}

func TestV6Roundtrip(t *testing.T) {
	v := newV6Payload(t)
	ip := net.ParseIP("107.210.133.127")
	now := time.Unix(1_800_000_000, 0)
	ct, err := v.Encode(ip, now)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(ct) != V6PayloadSize {
		t.Fatalf("ciphertext len %d != %d", len(ct), V6PayloadSize)
	}
	dec, err := v.Decode(ct, now)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !dec.ValidMAC {
		t.Fatal("valid response failed MAC check")
	}
	if !dec.IP.Equal(ip) {
		t.Errorf("IP mismatch: got %s want %s", dec.IP, ip)
	}
	if dec.Epoch != uint32(now.Unix()) {
		t.Errorf("epoch mismatch")
	}
	if dec.AgeSec != 0 {
		t.Errorf("age should be 0, got %d", dec.AgeSec)
	}
}

func TestV6NonceUniqueness(t *testing.T) {
	v := newV6Payload(t)
	ip := net.ParseIP("1.2.3.4")
	now := time.Now()
	seen := make(map[[4]byte]bool)
	for i := 0; i < 1000; i++ {
		ct, _ := v.Encode(ip, now)
		dec, _ := v.Decode(ct, now)
		if seen[dec.NonceRaw] {
			t.Fatalf("nonce collision on iter %d: %x", i, dec.NonceRaw)
		}
		seen[dec.NonceRaw] = true
	}
}

func TestV6CiphertextNonDeterministic(t *testing.T) {
	// Same input at same time must still produce different ciphertexts —
	// the nonce is internal and random.
	v := newV6Payload(t)
	ip := net.ParseIP("1.2.3.4")
	now := time.Unix(1_800_000_000, 0)
	ct1, _ := v.Encode(ip, now)
	ct2, _ := v.Encode(ip, now)
	same := true
	for i := range ct1 {
		if ct1[i] != ct2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("successive encodings of the same input produced identical ciphertexts — nonce not applied")
	}
}

func TestV6MACDetectsTamper(t *testing.T) {
	v := newV6Payload(t)
	ip := net.ParseIP("1.2.3.4")
	now := time.Now()
	ct, _ := v.Encode(ip, now)

	// Flip every bit in turn; each must break the MAC.
	for i := 0; i < V6PayloadSize*8; i++ {
		tampered := make([]byte, V6PayloadSize)
		copy(tampered, ct)
		tampered[i/8] ^= 1 << uint(i%8)
		dec, err := v.Decode(tampered, now)
		if err != nil {
			t.Fatalf("unexpected decode error: %v", err)
		}
		if dec.ValidMAC {
			t.Errorf("bit %d flip did not break MAC", i)
		}
	}
}

func TestV6WrongKeyFailsMAC(t *testing.T) {
	a, _ := NewV6Payload([]byte("secret-a"), nil, "info")
	b, _ := NewV6Payload([]byte("secret-b"), nil, "info")
	ct, _ := a.Encode(net.ParseIP("1.2.3.4"), time.Now())
	dec, _ := b.Decode(ct, time.Now())
	if dec.ValidMAC {
		t.Fatal("decode with different key should fail MAC")
	}
}

func TestV6DomainSeparation(t *testing.T) {
	a, _ := NewV6Payload([]byte("secret"), nil, "info-a")
	b, _ := NewV6Payload([]byte("secret"), nil, "info-b")
	ct, _ := a.Encode(net.ParseIP("1.2.3.4"), time.Now())
	dec, _ := b.Decode(ct, time.Now())
	if dec.ValidMAC {
		t.Fatal("decode with different info string should fail MAC")
	}
}

func TestV6RequiresIPv4(t *testing.T) {
	v := newV6Payload(t)
	_, err := v.Encode(net.ParseIP("2001:db8::1"), time.Now())
	if err == nil {
		t.Fatal("Encode should refuse v6 client addresses")
	}
}

func TestV6AgeComputation(t *testing.T) {
	v := newV6Payload(t)
	t0 := time.Unix(1_800_000_000, 0)
	ct, _ := v.Encode(net.ParseIP("1.2.3.4"), t0)
	dec, _ := v.Decode(ct, t0.Add(90*time.Second))
	if dec.AgeSec != 90 {
		t.Errorf("age expected 90, got %d", dec.AgeSec)
	}
}
