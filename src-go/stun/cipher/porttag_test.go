package cipher

import (
	"net"
	"testing"
)

func newTagger(t *testing.T, info string) *PortTagger {
	t.Helper()
	p, err := NewPortTagger([]byte("test-secret-do-not-use-in-prod"), nil, info)
	if err != nil {
		t.Fatalf("NewPortTagger: %v", err)
	}
	return p
}

func TestTagDeterministic(t *testing.T) {
	p := newTagger(t, "det")
	ip := net.ParseIP("107.210.133.127")
	if p.Tag(ip, 12345) != p.Tag(ip, 12345) {
		t.Fatal("same inputs must produce same tag")
	}
}

func TestTagIPBinding(t *testing.T) {
	p := newTagger(t, "ip")
	a := p.Tag(net.ParseIP("1.2.3.4"), 100)
	b := p.Tag(net.ParseIP("1.2.3.5"), 100)
	if a == b {
		t.Fatal("different IPs must yield different tags")
	}
}

func TestTagBucketBinding(t *testing.T) {
	p := newTagger(t, "bucket")
	ip := net.ParseIP("1.2.3.4")
	if p.Tag(ip, 100) == p.Tag(ip, 101) {
		t.Fatal("different buckets must yield different tags")
	}
}

func TestTagDomainSeparation(t *testing.T) {
	a, _ := NewPortTagger([]byte("secret"), nil, "info-a")
	b, _ := NewPortTagger([]byte("secret"), nil, "info-b")
	ip := net.ParseIP("1.2.3.4")
	if a.Tag(ip, 0) == b.Tag(ip, 0) {
		t.Fatal("different info strings must yield different tags")
	}
}

func TestTagKeySeparation(t *testing.T) {
	a, _ := NewPortTagger([]byte("secret-a"), nil, "info")
	b, _ := NewPortTagger([]byte("secret-b"), nil, "info")
	ip := net.ParseIP("1.2.3.4")
	if a.Tag(ip, 0) == b.Tag(ip, 0) {
		t.Fatal("different secrets must yield different tags")
	}
}

func TestPortFromTagRange(t *testing.T) {
	// Every possible 16-bit tag must map to an unprivileged port.
	for tag := 0; tag < 1<<16; tag++ {
		port := PortFromTag(uint16(tag))
		if port < 1024 || port > 65535 {
			t.Fatalf("tag %d mapped to out-of-range port %d", tag, port)
		}
	}
}

func TestPortFromTagDeterministic(t *testing.T) {
	if PortFromTag(0xdead) != PortFromTag(0xdead) {
		t.Fatal("PortFromTag must be deterministic")
	}
}

func TestIPv4MappedEquivalence(t *testing.T) {
	// net.ParseIP("1.2.3.4") returns a 16-byte v4-in-v6 form; To4() reduces
	// to 4 bytes. Both must produce the same tag so backend normalization
	// doesn't desync from the server.
	p := newTagger(t, "v4mapped")
	v4 := net.ParseIP("1.2.3.4").To4()
	v4mapped := net.ParseIP("1.2.3.4") // 16-byte form
	if p.Tag(v4, 0) != p.Tag(v4mapped, 0) {
		t.Fatal("v4 and v4-mapped-v6 of the same address must tag equally")
	}
}
