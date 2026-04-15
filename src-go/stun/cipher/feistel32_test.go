package cipher

import (
	"encoding/binary"
	"math/bits"
	"net"
	"testing"
)

func mustNew(t *testing.T, info string) *Feistel32 {
	t.Helper()
	f, err := NewFeistel32([]byte("test-secret-do-not-use-in-prod"), nil, info)
	if err != nil {
		t.Fatalf("NewFeistel32: %v", err)
	}
	return f
}

func TestRoundtripSamples(t *testing.T) {
	f := mustNew(t, "argus-sigint-ipv4-v1")
	samples := []uint32{
		0x00000000, 0x00000001, 0xffffffff, 0xdeadbeef,
		0x01010101, 0x08080808,
		0xc0a80101, // 192.168.1.1
		0x7f000001, // 127.0.0.1
		0x0a000001, // 10.0.0.1
		0x08080808, // 8.8.8.8
	}
	for _, p := range samples {
		c := f.Encrypt(p)
		if d := f.Decrypt(c); d != p {
			t.Errorf("roundtrip failed: p=%08x c=%08x d=%08x", p, c, d)
		}
	}
}

func TestRoundtripScan(t *testing.T) {
	f := mustNew(t, "scan")
	// Step through the 32-bit space sampling ~1M points.
	for p := uint32(0); ; p += 1 << 12 {
		if f.Decrypt(f.Encrypt(p)) != p {
			t.Fatalf("roundtrip failed at p=%08x", p)
		}
		if p > 0xffffe000 {
			break
		}
	}
}

func TestNoCollisionsOver16Bits(t *testing.T) {
	f := mustNew(t, "collision")
	seen := make(map[uint32]uint32, 1<<16)
	for p := uint32(0); p < 1<<16; p++ {
		c := f.Encrypt(p)
		if prev, ok := seen[c]; ok {
			t.Fatalf("collision: %08x and %08x both map to %08x", prev, p, c)
		}
		seen[c] = p
	}
}

func TestDiffusion(t *testing.T) {
	f := mustNew(t, "diffusion")
	// Every single plaintext-bit flip should flip a non-trivial number of
	// output bits. For a sound PRP we'd expect ~16; we assert >= 8 to
	// leave headroom for statistical variance.
	base := uint32(0xc0a80101)
	baseC := f.Encrypt(base)
	for bit := 0; bit < 32; bit++ {
		flipped := base ^ (1 << bit)
		diff := bits.OnesCount32(baseC ^ f.Encrypt(flipped))
		if diff < 8 {
			t.Errorf("bit %d: only %d output bits differ (expected >= 8)", bit, diff)
		}
	}
}

func TestDeterministic(t *testing.T) {
	f1, _ := NewFeistel32([]byte("secret"), nil, "info")
	f2, _ := NewFeistel32([]byte("secret"), nil, "info")
	if f1.Encrypt(0xdeadbeef) != f2.Encrypt(0xdeadbeef) {
		t.Fatal("same inputs must produce same ciphertext")
	}
}

func TestDomainSeparation(t *testing.T) {
	f1, _ := NewFeistel32([]byte("secret"), nil, "info-a")
	f2, _ := NewFeistel32([]byte("secret"), nil, "info-b")
	if f1.Encrypt(0xdeadbeef) == f2.Encrypt(0xdeadbeef) {
		t.Fatal("different info strings must yield different ciphertexts")
	}
}

func TestKeySeparation(t *testing.T) {
	f1, _ := NewFeistel32([]byte("secret-a"), nil, "info")
	f2, _ := NewFeistel32([]byte("secret-b"), nil, "info")
	if f1.Encrypt(0xdeadbeef) == f2.Encrypt(0xdeadbeef) {
		t.Fatal("different secrets must yield different ciphertexts")
	}
}

func TestIPv4Roundtrip(t *testing.T) {
	f := mustNew(t, "ipv4")
	ips := []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "192.168.1.1", "8.8.8.8", "255.255.255.255"}
	for _, s := range ips {
		ip := net.ParseIP(s).To4()
		p := binary.BigEndian.Uint32(ip)
		c := f.Encrypt(p)
		ctIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(ctIP, c)
		back := f.Decrypt(binary.BigEndian.Uint32(ctIP))
		if back != p {
			t.Errorf("ip %s: roundtrip failed (ct=%s)", s, ctIP)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	f, _ := NewFeistel32([]byte("bench-secret"), nil, "bench")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = f.Encrypt(uint32(i))
	}
}
