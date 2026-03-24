package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// isGREASE returns true if v is a GREASE value (RFC 8701).
// GREASE values follow the pattern 0xXAXA (e.g. 0x0a0a, 0x1a1a, ..., 0xfafa).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// tlsVersionStr maps a TLS version uint16 to its JA4 two-char representation.
func tlsVersionStr(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

// sha256hex12 returns the first 12 lowercase hex chars of SHA-256(s).
func sha256hex12(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:12]
}

// ClientHelloFields holds the extracted data needed for JA4 computation.
type ClientHelloFields struct {
	Version           uint16   // Legacy ClientHello version field
	HasSNI            bool
	HasGREASE         bool     // True if any GREASE value was present in ciphers or extensions
	CipherSuites      []uint16 // All cipher suites (including GREASE)
	Extensions        []uint16 // Extension type codes in wire order (including GREASE)
	SigAlgs           []uint16 // From supported_signature_algorithms (0x000d)
	ALPNProtocols     []string // From ALPN extension (0x0010)
	SupportedVersions []uint16 // From supported_versions extension (0x002b)
}

// parseClientHello parses raw handshake bytes (starting with the 0x01 ClientHello
// type byte, i.e. the TLS record payload without the 5-byte record header).
func parseClientHello(data []byte) (*ClientHelloFields, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("handshake data too short")
	}
	if data[0] != 0x01 {
		return nil, fmt.Errorf("not ClientHello (type=0x%02x)", data[0])
	}

	// 3-byte big-endian length after the type byte
	hLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+hLen {
		return nil, fmt.Errorf("truncated ClientHello")
	}
	d := data[4 : 4+hLen]

	f := &ClientHelloFields{}

	// Legacy version (2 bytes)
	if len(d) < 2 {
		return nil, fmt.Errorf("truncated at version")
	}
	f.Version = binary.BigEndian.Uint16(d[0:2])
	d = d[2:]

	// Random (32 bytes)
	if len(d) < 32 {
		return nil, fmt.Errorf("truncated at random")
	}
	d = d[32:]

	// Session ID
	if len(d) < 1 {
		return nil, fmt.Errorf("truncated at session_id_len")
	}
	sidLen := int(d[0])
	d = d[1:]
	if len(d) < sidLen {
		return nil, fmt.Errorf("truncated at session_id")
	}
	d = d[sidLen:]

	// Cipher suites
	if len(d) < 2 {
		return nil, fmt.Errorf("truncated at cipher_suites_len")
	}
	csLen := int(binary.BigEndian.Uint16(d[0:2]))
	d = d[2:]
	if len(d) < csLen || csLen%2 != 0 {
		return nil, fmt.Errorf("truncated at cipher_suites")
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(d[i : i+2])
		if isGREASE(cs) {
			f.HasGREASE = true
		}
		f.CipherSuites = append(f.CipherSuites, cs)
	}
	d = d[csLen:]

	// Compression methods
	if len(d) < 1 {
		return nil, fmt.Errorf("truncated at compression_methods_len")
	}
	cmLen := int(d[0])
	d = d[1:]
	if len(d) < cmLen {
		return nil, fmt.Errorf("truncated at compression_methods")
	}
	d = d[cmLen:]

	// Extensions (optional — absent in SSLv2 hellos)
	if len(d) < 2 {
		return f, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(d[0:2]))
	d = d[2:]
	if len(d) < extTotalLen {
		return nil, fmt.Errorf("truncated at extensions block")
	}
	ed := d[:extTotalLen]

	for len(ed) >= 4 {
		extType := binary.BigEndian.Uint16(ed[0:2])
		extLen := int(binary.BigEndian.Uint16(ed[2:4]))
		ed = ed[4:]
		if len(ed) < extLen {
			break
		}
		extBody := ed[:extLen]
		ed = ed[extLen:]

		if isGREASE(extType) {
			f.HasGREASE = true
		}
		f.Extensions = append(f.Extensions, extType)

		switch extType {
		case 0x0000: // server_name (SNI)
			// list_len(2) + name_type(1) + name_len(2) + name
			if len(extBody) >= 5 {
				f.HasSNI = true
			}

		case 0x000d: // signature_algorithms
			// list_len(2) + pairs of sigalg(2)
			if len(extBody) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extBody[0:2]))
				body := extBody[2:]
				for i := 0; i+1 < len(body) && i < listLen; i += 2 {
					f.SigAlgs = append(f.SigAlgs, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}

		case 0x0010: // application_layer_protocol_negotiation
			// list_len(2) + list of (proto_len(1) + proto_bytes)
			if len(extBody) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extBody[0:2]))
				body := extBody[2:]
				if len(body) > listLen {
					body = body[:listLen]
				}
				for len(body) >= 1 {
					protoLen := int(body[0])
					body = body[1:]
					if len(body) < protoLen {
						break
					}
					f.ALPNProtocols = append(f.ALPNProtocols, string(body[:protoLen]))
					body = body[protoLen:]
				}
			}

		case 0x002b: // supported_versions
			// In ClientHello: versions_len(1) + list of version(2)
			if len(extBody) >= 1 {
				versLen := int(extBody[0])
				body := extBody[1:]
				for i := 0; i+1 < len(body) && i < versLen; i += 2 {
					f.SupportedVersions = append(f.SupportedVersions, binary.BigEndian.Uint16(body[i:i+2]))
				}
			}
		}
	}

	return f, nil
}

// computeJA4 produces the JA4 fingerprint string from parsed ClientHello fields.
//
// Format: t{ver}{sni}{cc:02d}{ec:02d}{alpn}_{ciphers_hash}_{exts_sigalgs_hash}
//
// References: https://github.com/FoxIO-LLC/ja4
func computeJA4(f *ClientHelloFields) string {
	// TLS version: prefer highest non-GREASE value from supported_versions
	tlsVer := f.Version
	for _, v := range f.SupportedVersions {
		if !isGREASE(v) && v > tlsVer {
			tlsVer = v
		}
	}
	version := tlsVersionStr(tlsVer)

	sni := "i"
	if f.HasSNI {
		sni = "d"
	}

	// Non-GREASE cipher suites
	var ciphers []uint16
	for _, c := range f.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}

	// Non-GREASE extensions (all counted for ext_count)
	var exts []uint16
	for _, e := range f.Extensions {
		if !isGREASE(e) {
			exts = append(exts, e)
		}
	}

	// ALPN: first 2 chars of first protocol, or "00"
	alpn := "00"
	if len(f.ALPNProtocols) > 0 {
		p := f.ALPNProtocols[0]
		switch {
		case len(p) >= 2:
			alpn = p[:2]
		case len(p) == 1:
			alpn = p + "0"
		}
	}

	// Part a
	a := fmt.Sprintf("t%s%s%02d%02d%s", version, sni, len(ciphers), len(exts), alpn)

	// Part b: sort ciphers ascending, hex-format, comma-join, SHA256[:12]
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherStrs := make([]string, len(sortedCiphers))
	for i, c := range sortedCiphers {
		cipherStrs[i] = fmt.Sprintf("%04x", c)
	}
	b := sha256hex12(strings.Join(cipherStrs, ","))

	// Part c: extensions excluding SNI (0x0000), sorted ascending + "_" + sorted sigalgs
	var filteredExts []uint16
	for _, e := range exts {
		if e != 0x0000 { // Exclude SNI; SNI presence is already captured in the sni field
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })
	extStrs := make([]string, len(filteredExts))
	for i, e := range filteredExts {
		extStrs[i] = fmt.Sprintf("%04x", e)
	}

	sortedSigAlgs := make([]uint16, len(f.SigAlgs))
	copy(sortedSigAlgs, f.SigAlgs)
	sort.Slice(sortedSigAlgs, func(i, j int) bool { return sortedSigAlgs[i] < sortedSigAlgs[j] })
	sigAlgStrs := make([]string, len(sortedSigAlgs))
	for i, s := range sortedSigAlgs {
		sigAlgStrs[i] = fmt.Sprintf("%04x", s)
	}

	c := sha256hex12(strings.Join(extStrs, ",") + "_" + strings.Join(sigAlgStrs, ","))

	return a + "_" + b + "_" + c
}
