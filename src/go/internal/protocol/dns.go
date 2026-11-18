package protocol

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// DNS codec: payload bytes are base32hex-encoded (lowercase, no padding) and
// split into labels of at most 50 characters. The query name is
//
//	<payload labels>.<suffix>
//
// Responses are TXT records whose rdata is a length-prefixed concatenation of
// base32hex chunks.

var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// EncodeDNSName encodes payload into a query name under suffix.
func EncodeDNSName(payload []byte, suffix string, labelLen int) string {
	if labelLen <= 0 || labelLen > 63 {
		labelLen = 50
	}
	enc := strings.ToLower(b32.EncodeToString(payload))
	if enc == "" {
		enc = "x"
	}
	var labels []string
	for len(enc) > labelLen {
		labels = append(labels, enc[:labelLen])
		enc = enc[labelLen:]
	}
	labels = append(labels, enc)
	name := strings.Join(labels, ".")
	if suffix = strings.TrimSuffix(suffix, "."); suffix != "" {
		name += "." + suffix
	}
	// DNS names are limited to 253 octets.
	if len(name) > 253 {
		name = name[:253]
	}
	return name
}

// DecodeDNSName extracts payload bytes from the query name.
func DecodeDNSName(name, suffix string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	suffix = strings.TrimSuffix(strings.ToLower(suffix), ".")
	if suffix != "" {
		if !strings.HasSuffix(name, "."+suffix) && name != suffix {
			return nil, fmt.Errorf("suffix %q not found in %q", suffix, name)
		}
		name = strings.TrimSuffix(name, suffix)
		name = strings.TrimSuffix(name, ".")
	}
	labels := strings.Split(name, ".")
	enc := strings.Join(labels, "")
	enc = strings.ToUpper(enc)
	if enc == "X" || enc == "" {
		return nil, nil
	}
	// Restore padding.
	if m := len(enc) % 8; m != 0 {
		enc += strings.Repeat("=", 8-m)
	}
	return base32.HexEncoding.DecodeString(enc)
}

// ParseQueryName returns the first question name of a DNS query.
func ParseQueryName(msg []byte) (string, error) {
	names, err := ParseQueryNames(msg)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return names[0], nil
}

// ParseQueryNames returns every question name in a DNS query.  Multi-question
// queries are used to carry a full handshake payload, which does not fit in a
// single 253-octet QNAME.
func ParseQueryNames(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("short dns query")
	}
	qd := int(msg[4])<<8 | int(msg[5])
	if qd < 1 {
		return nil, errors.New("no question")
	}
	off := 12
	var names []string
	for i := 0; i < qd; i++ {
		var labels []string
		for {
			if off >= len(msg) {
				return names, errors.New("truncated qname")
			}
			l := int(msg[off])
			if l == 0 {
				off++
				break
			}
			if msg[off]&0xC0 == 0xC0 {
				return names, errors.New("compressed qname unsupported")
			}
			if l > 63 || off+1+l > len(msg) {
				return names, errors.New("bad label")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
		off += 4 // qtype + qclass
		names = append(names, strings.Join(labels, "."))
	}
	return names, nil
}

// EncodeDNSQuery builds one query whose questions together carry payload.
// A single QNAME is limited to 253 octets, so a full handshake (public key,
// nonce and PSK tag) is split over multiple questions.  Each chunk is 200
// base32 characters, which keeps every name comfortably below the limit.
func EncodeDNSQuery(payload []byte, suffix string, labelLen int) []byte {
	if labelLen <= 0 || labelLen > 50 {
		labelLen = 50
	}
	enc := strings.ToLower(b32.EncodeToString(payload))
	if enc == "" {
		enc = "x"
	}
	const chunkChars = 200
	var names []string
	for len(enc) > 0 {
		take := chunkChars
		if take > len(enc) {
			take = len(enc)
		}
		part := enc[:take]
		enc = enc[take:]
		var labels []string
		for len(part) > labelLen {
			labels = append(labels, part[:labelLen])
			part = part[labelLen:]
		}
		if part != "" {
			labels = append(labels, part)
		}
		name := strings.Join(labels, ".")
		if s := strings.TrimSuffix(suffix, "."); s != "" {
			name += "." + s
		}
		names = append(names, name)
	}
	out := make([]byte, 12)
	out[0], out[1] = 0x12, 0x34
	out[2] = 0x01 // RD
	out[4], out[5] = byte(len(names)>>8), byte(len(names))
	for _, name := range names {
		for _, label := range strings.Split(name, ".") {
			if len(label) > 63 {
				label = label[:63]
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
		out = append(out, 0, 0, 16, 0, 1)
	}
	return out
}

// ParseDNSQueryPayload reconstructs payload bytes from all questions.
func ParseDNSQueryPayload(msg []byte, suffix string) ([]byte, error) {
	names, err := ParseQueryNames(msg)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, n := range names {
		b, err := DecodeDNSName(n, suffix)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// DNSAnswer is a decoded TXT response chunk list.
type DNSResponse struct {
	Chunks [][]byte
}

// BuildTXTResponse builds a minimal DNS response for a query, echoing the
// question and appending one TXT record per chunk.
func BuildTXTResponse(query []byte, chunks [][]byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short dns query")
	}
	// Copy header.
	resp := make([]byte, 12)
	copy(resp, query[:12])
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x80 // RA=1, RCODE=0
	// Skip EDNS OPT additionals: we only echo the question section.
	qdCount := int(query[4])<<8 | int(query[5])
	off := 12
	for i := 0; i < qdCount; i++ {
		start := off
		for off < len(query) && query[off] != 0 {
			off += int(query[off]) + 1
		}
		if off+4 >= len(query) {
			off = start
			break
		}
		off += 5 // zero byte + qtype + qclass
	}
	if off < 12 || off > len(query) {
		off = 12
	}
	resp = append(resp, query[12:off]...)
	resp[6] = 0
	resp[7] = 0 // ANCOUNT placeholder
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0
	an := 0
	for _, chunk := range chunks {
		if len(chunk) > 255 {
			chunk = chunk[:255]
		}
		// name pointer to offset 12
		resp = append(resp, 0xC0, 0x0C)
		resp = append(resp, 0x00, 0x10, 0x00, 0x01) // TXT IN
		ttl := []byte{0, 0, 0, 1}
		resp = append(resp, ttl...)
		rdlen := len(chunk) + 1
		resp = append(resp, byte(rdlen>>8), byte(rdlen))
		resp = append(resp, byte(len(chunk)))
		resp = append(resp, chunk...)
		an++
	}
	resp[6] = byte(an >> 8)
	resp[7] = byte(an)
	// We do not echo OPT; some resolvers tolerate this for a lab transport.
	return resp, nil
}

// ParseTXTResponse extracts TXT rdata chunks from a DNS response.
func ParseTXTResponse(msg []byte) (*DNSResponse, error) {
	if len(msg) < 12 {
		return nil, errors.New("short dns response")
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	skipName := func(o int) (int, error) {
		for o < len(msg) {
			l := int(msg[o])
			if l == 0 {
				return o + 1, nil
			}
			if msg[o]&0xC0 == 0xC0 {
				if o+2 > len(msg) {
					return 0, errors.New("bad pointer")
				}
				return o + 2, nil
			}
			o += 1 + l
		}
		return 0, errors.New("truncated name")
	}
	var err error
	for i := 0; i < qd; i++ {
		off, err = skipName(off)
		if err != nil {
			return nil, err
		}
		off += 4
	}
	out := &DNSResponse{}
	for i := 0; i < an; i++ {
		off, err = skipName(off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("truncated rr")
		}
		rtype := int(msg[off])<<8 | int(msg[off+1])
		rdlen := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("truncated rdata")
		}
		if rtype == 16 {
			rdata := msg[off : off+rdlen]
			p := 0
			for p < len(rdata) {
				l := int(rdata[p])
				p++
				if p+l > len(rdata) {
					break
				}
				chunk := append([]byte{}, rdata[p:p+l]...)
				out.Chunks = append(out.Chunks, chunk)
				p += l
			}
		}
		off += rdlen
	}
	return out, nil
}

