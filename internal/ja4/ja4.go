// Package ja4 computes the JA4 TLS client fingerprint from a raw ClientHello.
//
// Why this matters here: the Permit gate matches on the domain, and ECH
// (RFC 9849) encrypts the SNI — the ClientHello a gateway sees will increasingly
// carry a cover name instead of the real one. A fingerprint describes the client
// *stack* rather than its destination, so it keeps working when the name stops
// being informative, and it is the standard way to spot an embedded TLS library
// (malware, a C2 implant) among browsers.
//
// Format (FoxIO JA4 spec):
//
//	(protocol)(version)(sni)(cipher_count)(ext_count)(alpn)_(cipher_hash)_(ext_hash)
//
// GREASE values are ignored everywhere. The cipher hash covers the sorted cipher
// list; the extension hash covers the sorted extension list EXCLUDING SNI and
// ALPN, followed by the signature algorithms in their original order.
package ja4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Fingerprint is a parsed JA4 plus the parts a human wants to see.
type Fingerprint struct {
	JA4        string   `json:"ja4"`
	Version    string   `json:"version"`        // 13 / 12 / …
	ALPN       string   `json:"alpn,omitempty"` // first offered protocol
	SNI        bool     `json:"sni"`            // did the hello carry a server name
	Ciphers    int      `json:"ciphers"`        // count, GREASE excluded
	Exts       int      `json:"extensions"`     // count, GREASE excluded
	Extensions []uint16 `json:"-"`
}

var (
	// ErrNotClientHello means the bytes are not a TLS ClientHello record.
	ErrNotClientHello = errors.New("not a TLS ClientHello")
	// ErrTruncated means the record was cut short (we only capture a bounded
	// prefix, and a fingerprint from a partial hello would be a lie).
	ErrTruncated = errors.New("ClientHello truncated")
)

const (
	extSNI              = 0x0000
	extALPN             = 0x0010
	extSupportedVersion = 0x002b
	extSigAlgs          = 0x000d
)

// Compute parses a raw TLS record containing a ClientHello and returns its JA4.
// transport is "t" for TCP or "q" for QUIC.
func Compute(record []byte, transport string) (Fingerprint, error) {
	var fp Fingerprint
	if transport != "q" {
		transport = "t"
	}
	hello, err := clientHelloBody(record)
	if err != nil {
		return fp, err
	}
	p := &parser{b: hello}

	legacyVersion, ok := p.uint16()
	if !ok {
		return fp, ErrTruncated
	}
	if !p.skip(32) { // random
		return fp, ErrTruncated
	}
	if _, ok := p.vector(1); !ok { // session id
		return fp, ErrTruncated
	}
	cipherBytes, ok := p.vector(2)
	if !ok {
		return fp, ErrTruncated
	}
	if _, ok := p.vector(1); !ok { // compression methods
		return fp, ErrTruncated
	}

	ciphers := make([]uint16, 0, len(cipherBytes)/2)
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		v := binary.BigEndian.Uint16(cipherBytes[i:])
		if isGREASE(v) {
			continue
		}
		ciphers = append(ciphers, v)
	}

	var (
		exts       []uint16
		sigAlgs    []uint16
		alpnFirst  string
		hasSNI     bool
		negotiated = legacyVersion
	)
	extBytes, ok := p.vector(2)
	if !ok {
		// A hello with no extensions at all is legal (and ancient).
		extBytes = nil
	}
	ep := &parser{b: extBytes}
	for ep.remaining() >= 4 {
		typ, _ := ep.uint16()
		body, ok := ep.vector(2)
		if !ok {
			return fp, ErrTruncated
		}
		if isGREASE(typ) {
			continue
		}
		exts = append(exts, typ)
		switch typ {
		case extSNI:
			hasSNI = true
		case extALPN:
			alpnFirst = firstALPN(body)
		case extSigAlgs:
			sp := &parser{b: body}
			if list, ok := sp.vector(2); ok {
				for i := 0; i+1 < len(list); i += 2 {
					v := binary.BigEndian.Uint16(list[i:])
					if isGREASE(v) {
						continue
					}
					sigAlgs = append(sigAlgs, v)
				}
			}
		case extSupportedVersion:
			sp := &parser{b: body}
			if list, ok := sp.vector(1); ok {
				best := uint16(0)
				for i := 0; i+1 < len(list); i += 2 {
					v := binary.BigEndian.Uint16(list[i:])
					if isGREASE(v) {
						continue
					}
					if v > best {
						best = v
					}
				}
				if best != 0 {
					negotiated = best
				}
			}
		}
	}

	sniChar := "i"
	if hasSNI {
		sniChar = "d"
	}
	alpnCode := "00"
	if alpnFirst != "" {
		alpnCode = alpnChars(alpnFirst)
	}

	// The counts include SNI and ALPN; the extension hash does not.
	fp = Fingerprint{
		Version: versionCode(negotiated), ALPN: alpnFirst, SNI: hasSNI,
		Ciphers: len(ciphers), Exts: len(exts), Extensions: exts,
	}
	hashExts := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e == extSNI || e == extALPN {
			continue
		}
		hashExts = append(hashExts, e)
	}
	fp.JA4 = fmt.Sprintf("%s%s%s%s%s%s_%s_%s",
		transport, fp.Version, sniChar,
		twoDigits(len(ciphers)), twoDigits(len(exts)), alpnCode,
		hash12(hexList(sortedCopy(ciphers))),
		hash12(extHashInput(sortedCopy(hashExts), sigAlgs)),
	)
	return fp, nil
}

// clientHelloBody unwraps the TLS record and handshake headers, returning the
// ClientHello body (from legacy_version onwards).
func clientHelloBody(record []byte) ([]byte, error) {
	if len(record) < 9 {
		return nil, ErrTruncated
	}
	if record[0] != 0x16 { // handshake record
		return nil, ErrNotClientHello
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	body := record[5:]
	if len(body) < recLen {
		// The capture is bounded; a hello spanning more than we kept cannot be
		// fingerprinted honestly.
		if len(body) < 4 {
			return nil, ErrTruncated
		}
	} else {
		body = body[:recLen]
	}
	if body[0] != 0x01 { // client_hello
		return nil, ErrNotClientHello
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	body = body[4:]
	if len(body) < hsLen {
		return nil, ErrTruncated
	}
	return body[:hsLen], nil
}

// extHashInput renders the JA4_c input: sorted extensions, then an underscore
// and the signature algorithms in their original order.
func extHashInput(exts, sigAlgs []uint16) string {
	if len(exts) == 0 && len(sigAlgs) == 0 {
		return ""
	}
	if len(sigAlgs) == 0 {
		return hexList(exts)
	}
	return hexList(exts) + "_" + hexList(sigAlgs)
}

func hexList(vals []uint16) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%04x", v))
	}
	return strings.Join(parts, ",")
}

// hash12 is the spec's 12-character truncated sha256; an empty list hashes to
// twelve zeroes rather than to sha256("").
func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func sortedCopy(in []uint16) []uint16 {
	out := append([]uint16(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// twoDigits renders a count, capped at 99 as the spec requires.
func twoDigits(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// versionCode maps a TLS version to the spec's two-character form.
func versionCode(v uint16) string {
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
	case 0x0200:
		return "s2"
	case 0x0100:
		return "s1"
	}
	return "00"
}

// firstALPN returns the first protocol offered in an ALPN extension body.
func firstALPN(body []byte) string {
	p := &parser{b: body}
	list, ok := p.vector(2)
	if !ok {
		return ""
	}
	lp := &parser{b: list}
	first, ok := lp.vector(1)
	if !ok {
		return ""
	}
	return string(first)
}

// alpnChars is the spec's first/last alphanumeric pair ("h2" -> "h2",
// "http/1.1" -> "h1").
func alpnChars(alpn string) string {
	if alpn == "" {
		return "00"
	}
	f, l := alpn[0], alpn[len(alpn)-1]
	if !isAlnum(f) || !isAlnum(l) {
		// Non-printable ALPNs are rendered from their hex, per the spec's note.
		h := hex.EncodeToString([]byte{f, l})
		return h[:1] + h[len(h)-1:]
	}
	return string([]byte{f, l})
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isGREASE reports whether a value is one of the reserved GREASE codepoints
// (RFC 8701): clients insert them at random, so including them would make every
// connection look unique.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// parser walks length-prefixed TLS structures.
type parser struct {
	b []byte
	i int
}

func (p *parser) remaining() int { return len(p.b) - p.i }

func (p *parser) uint16() (uint16, bool) {
	if p.remaining() < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(p.b[p.i:])
	p.i += 2
	return v, true
}

func (p *parser) skip(n int) bool {
	if p.remaining() < n {
		return false
	}
	p.i += n
	return true
}

// vector reads a length-prefixed byte slice whose length field is lenBytes wide.
func (p *parser) vector(lenBytes int) ([]byte, bool) {
	if p.remaining() < lenBytes {
		return nil, false
	}
	n := 0
	for i := 0; i < lenBytes; i++ {
		n = n<<8 | int(p.b[p.i+i])
	}
	p.i += lenBytes
	if p.remaining() < n {
		return nil, false
	}
	out := p.b[p.i : p.i+n]
	p.i += n
	return out, true
}
