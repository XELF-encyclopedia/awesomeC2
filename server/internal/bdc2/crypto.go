package bdc2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrBadFrame    = errors.New("bdc2: malformed frame")
	ErrBadTag      = errors.New("bdc2: authentication tag mismatch")
	ErrReplay      = errors.New("bdc2: replay/out-of-order sequence")
	ErrBadHello    = errors.New("bdc2: bad hello proof")
	ErrPSK         = errors.New("bdc2: unknown identity or bad psk")
	ErrUnsupported = errors.New("bdc2: unsupported")
)

// hmacSHA256 returns HMAC-SHA256(key, part...).
func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// HKDF implements RFC 5869 with SHA-256.
func HKDF(ikm, salt []byte, info string, n int) ([]byte, error) {
	if n <= 0 || n > 255*32 {
		return nil, fmt.Errorf("hkdf: bad length %d", n)
	}
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	prk := hmacSHA256(salt, ikm)
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		t = hmacSHA256(prk, t, []byte(info), []byte{i})
		out = append(out, t...)
	}
	return out[:n], nil
}

// HelloKey derives the per-connection AES-128-GCM key.
func HelloKey(psk, clientID, helloNonce []byte) ([]byte, error) {
	salt := append(append([]byte{}, clientID...), helloNonce...)
	return HKDF(psk, salt, HelloSalt, 16)
}

// OperatorKey derives the operator channel key.
func OperatorKey(psk []byte, user string) ([]byte, error) {
	return HKDF(psk, []byte("op:"+user), HelloSalt, 16)
}

// HelloMAC computes the HELLO proof.
func HelloMAC(psk, clientID, helloNonce []byte) []byte {
	return hmacSHA256(psk, []byte("hello"), clientID, helloNonce)
}

// OperatorAuthMAC computes the operator AUTH proof.
func OperatorAuthMAC(psk []byte, user string, nonce []byte) []byte {
	return hmacSHA256(psk, []byte("opauth"), []byte(user), nonce)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// nonce builds the deterministic per-frame nonce.
func nonce(direction uint8, seq uint32) []byte {
	n := make([]byte, 12)
	n[0] = direction
	binary.BigEndian.PutUint32(n[8:], seq)
	return n
}

// SealFrame builds a full wire frame.
func SealFrame(key []byte, typ, flags uint8, sid uint64, seq uint32, direction uint8, payload []byte) ([]byte, error) {
	hdr := make([]byte, HeaderLen)
	copy(hdr[0:4], []byte("BDC2"))
	hdr[4] = ProtoVersion
	hdr[5] = typ
	hdr[6] = flags
	binary.BigEndian.PutUint64(hdr[8:16], sid)
	binary.BigEndian.PutUint32(hdr[16:20], seq)

	if flags&FlagCleartext != 0 {
		binary.BigEndian.PutUint32(hdr[20:24], uint32(len(payload)))
		return append(hdr, payload...), nil
	}
	if key == nil {
		return nil, ErrPSK
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(hdr[20:24], uint32(len(payload)+aead.Overhead()))
	ct := aead.Seal(nil, nonce(direction, seq), payload, hdr)
	return append(hdr, ct...), nil
}

// ParseHeader reads the fixed header and returns a Frame with raw payload.
func ParseHeader(b []byte) (typ, flags uint8, sid uint64, seq uint32, plen int, err error) {
	if len(b) < HeaderLen || string(b[0:4]) != "BDC2" {
		return 0, 0, 0, 0, 0, ErrBadFrame
	}
	if b[4] != ProtoVersion {
		return 0, 0, 0, 0, 0, fmt.Errorf("bdc2: version %d", b[4])
	}
	typ, flags = b[5], b[6]
	sid = binary.BigEndian.Uint64(b[8:16])
	seq = binary.BigEndian.Uint32(b[16:20])
	plen = int(binary.BigEndian.Uint32(b[20:24]))
	if plen < 0 || plen > MaxFrame {
		return 0, 0, 0, 0, 0, ErrBadFrame
	}
	return typ, flags, sid, seq, plen, nil
}

// OpenFrame decrypts the payload of a whole frame buffer.
func OpenFrame(key []byte, frame []byte, direction uint8) (typ, flags uint8, sid uint64, seq uint32, payload []byte, err error) {
	typ, flags, sid, seq, plen, err := ParseHeader(frame)
	if err != nil {
		return
	}
	if len(frame) != HeaderLen+plen {
		return typ, flags, sid, seq, nil, ErrBadFrame
	}
	body := frame[HeaderLen:]
	if flags&FlagCleartext != 0 {
		return typ, flags, sid, seq, body, nil
	}
	if key == nil {
		return typ, flags, sid, seq, nil, ErrPSK
	}
	aead, err2 := newGCM(key)
	if err2 != nil {
		return typ, flags, sid, seq, nil, err2
	}
	payload, err = aead.Open(nil, nonce(direction, seq), body, frame[0:HeaderLen])
	if err != nil {
		return typ, flags, sid, seq, nil, ErrBadTag
	}
	return
}

// ---- TLV payload encoding ----
//
// [klen u8][key][vlen u32][value] repeated.

type KV struct {
	K string
	V []byte
}

func S(k, v string) KV        { return KV{K: k, V: []byte(v)} }
func B(k string, v []byte) KV { return KV{K: k, V: v} }

func EncodeTLV(kvs []KV) []byte {
	var out []byte
	for _, kv := range kvs {
		if len(kv.K) == 0 || len(kv.K) > 63 {
			continue
		}
		out = append(out, byte(len(kv.K)))
		out = append(out, kv.K...)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(kv.V)))
		out = append(out, l[:]...)
		out = append(out, kv.V...)
	}
	return out
}

func DecodeTLV(b []byte) (map[string][]byte, error) {
	m := make(map[string][]byte)
	for len(b) > 0 {
		if len(b) < 1 {
			return nil, ErrBadFrame
		}
		kl := int(b[0])
		b = b[1:]
		if kl == 0 || len(b) < kl+4 {
			return nil, ErrBadFrame
		}
		k := string(b[:kl])
		b = b[kl:]
		vl := int(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
		if vl < 0 || vl > MaxFrame || len(b) < vl {
			return nil, ErrBadFrame
		}
		m[k] = b[:vl]
		b = b[vl:]
	}
	return m, nil
}

// DecodePSK accepts "base64:..." / bare base64 / hex(32..) forms.
func DecodePSK(s string) ([]byte, error) {
	if len(s) > 7 && s[:7] == "base64:" {
		return base64.StdEncoding.DecodeString(s[7:])
	}
	if len(s) > 4 && s[:4] == "hex:" {
		return decodeHex(s[4:])
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) >= 16 {
		return b, nil
	}
	return decodeHex(s)
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("bad hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			var d byte
			switch {
			case c >= '0' && c <= '9':
				d = c - '0'
			case c >= 'a' && c <= 'f':
				d = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				d = c - 'A' + 10
			default:
				return nil, fmt.Errorf("bad hex")
			}
			v = v<<4 | d
		}
		out[i] = v
	}
	return out, nil
}
