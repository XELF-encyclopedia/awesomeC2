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
	return b32.DecodeString(enc)
}

// ParseQueryName returns the first question name of a DNS query.
func ParseQueryName(msg []byte) (string, error) {
	if len(msg) < 12 {
		return "", errors.New("short dns query")
	}
	qd := int(msg[4])<<8 | int(msg[5])
	if qd < 1 {
		return "", errors.New("no question")
	}
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return "", errors.New("truncated qname")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if msg[off]&0xC0 == 0xC0 {
			return "", errors.New("compressed qname unsupported")
		}
		if l > 63 || off+1+l > len(msg) {
			return "", errors.New("bad label")
		}
		labels = append(labels, string(msg[off+1:off+1+l]))
		off += 1 + l
	}
	return strings.Join(labels, "."), nil
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
