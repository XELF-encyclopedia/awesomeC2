// Package protocol implements the C2V2 wire protocol: framing, handshake key
// derivation, AEAD envelopes and the JSON message catalog shared by server,
// operator, GUI and builder.
package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Version  = 2
	MaxFrame = 8 << 20
)

// Frame kinds.
const (
	KindPlain  byte = 0
	KindSealed byte = 1
)

// Direction bytes used as AEAD AAD discriminator.
const (
	DirClientToServer byte = 1
	DirServerToClient byte = 2
)

// CipherSuite identifies the negotiated AEAD.
type CipherSuite byte

const (
	CipherAES256GCM        CipherSuite = 1
	CipherChaCha20Poly1305 CipherSuite = 2
)

func (c CipherSuite) String() string {
	switch c {
	case CipherChaCha20Poly1305:
		return "chacha20poly1305"
	default:
		return "aes256gcm"
	}
}

// ParseCipher maps a profile string to a suite.
func ParseCipher(s string) CipherSuite {
	switch s {
	case "chacha20poly1305", "chacha20-poly1305", "chacha":
		return CipherChaCha20Poly1305
	default:
		return CipherAES256GCM
	}
}

// Keys is the per-session key material.
type Keys struct {
	SID    string
	Cipher CipherSuite
	C2S    []byte
	S2C    []byte
}

// NewEphemeral creates an X25519 key pair.
func NewEphemeral() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// PublicRaw returns the raw 32-byte public key.
func PublicRaw(k *ecdh.PrivateKey) []byte { return k.PublicKey().Bytes() }

// SharedRaw computes the X25519 shared secret with a raw peer public key.
func SharedRaw(k *ecdh.PrivateKey, peer []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("bad x25519 public key: %w", err)
	}
	return k.ECDH(pub)
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk []byte, info string, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write([]byte(info))
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// DeriveKeys derives the two directional AEAD keys.
// ikm = X25519 shared secret || PSK (PSK may be empty for TLS-only lab use).
func DeriveKeys(shared, psk, nonceC, nonceS []byte, cs CipherSuite) (*Keys, error) {
	if len(shared) != 32 {
		return nil, fmt.Errorf("shared secret must be 32 bytes, got %d", len(shared))
	}
	saltHash := sha256.Sum256(append(append([]byte{}, nonceC...), nonceS...))
	ikm := append(append([]byte{}, shared...), psk...)
	prk := hkdfExtract(saltHash[:], ikm)
	sidHash := sha256.Sum256(append(append(append([]byte{}, shared...), nonceC...), nonceS...))
	return &Keys{
		SID:    hex.EncodeToString(sidHash[:8]),
		Cipher: cs,
		C2S:    hkdfExpand(prk, "c2v2/c2s/v2", 32),
		S2C:    hkdfExpand(prk, "c2v2/s2c/v2", 32),
	}, nil
}

func newAEAD(cs CipherSuite, key []byte) (cipher.AEAD, error) {
	switch cs {
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unknown cipher suite %d", cs)
	}
}

// Seal encrypts plaintext into a sealed envelope.
func (k *Keys) Seal(dir byte, plain []byte) ([]byte, error) {
	var key []byte
	if dir == DirClientToServer {
		key = k.C2S
	} else {
		key = k.S2C
	}
	aead, err := newAEAD(k.Cipher, key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := append([]byte("C2V2"), dir)
	buf := make([]byte, 0, 4+len(nonce)+len(plain)+aead.Overhead())
	buf = append(buf, Version, KindSealed, byte(k.Cipher), dir)
	buf = append(buf, nonce...)
	buf = aead.Seal(buf, nonce, plain, aad)
	return buf, nil
}

// Open decrypts a sealed envelope, verifying the direction byte.
func (k *Keys) Open(wantDir byte, env []byte) ([]byte, error) {
	if len(env) < 4 {
		return nil, errors.New("envelope too short")
	}
	if env[0] != Version {
		return nil, fmt.Errorf("bad version %d", env[0])
	}
	if env[1] != KindSealed {
		return nil, errors.New("not a sealed envelope")
	}
	cs := CipherSuite(env[2])
	if cs != k.Cipher {
		return nil, fmt.Errorf("cipher mismatch: %s vs %s", cs, k.Cipher)
	}
	dir := env[3]
	if dir != wantDir {
		return nil, fmt.Errorf("direction mismatch: %d want %d", dir, wantDir)
	}
	var key []byte
	if dir == DirClientToServer {
		key = k.C2S
	} else {
		key = k.S2C
	}
	aead, err := newAEAD(cs, key)
	if err != nil {
		return nil, err
	}
	if len(env) < 4+aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("sealed envelope too short")
	}
	nonce := env[4 : 4+aead.NonceSize()]
	ct := env[4+aead.NonceSize():]
	aad := append([]byte("C2V2"), dir)
	return aead.Open(nil, nonce, ct, aad)
}

// Plain JSON envelope (handshake only).
func PlainEnvelope(plain []byte) []byte {
	return append([]byte{Version, KindPlain}, plain...)
}

// ParsePlain returns the JSON body of a plaintext envelope.
func ParsePlain(env []byte) ([]byte, error) {
	if len(env) < 2 {
		return nil, errors.New("envelope too short")
	}
	if env[0] != Version {
		return nil, fmt.Errorf("bad version %d", env[0])
	}
	if env[1] != KindPlain {
		return nil, errors.New("not a plain envelope")
	}
	return env[2:], nil
}

// WriteStreamFrame writes a length-prefixed frame.
func WriteStreamFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return fmt.Errorf("frame too large: %d", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadStreamFrame reads a length-prefixed frame.
func ReadStreamFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// HMACSign returns hex HMAC-SHA256 over the canonical parts joined by '|'.
func HMACSign(key []byte, parts ...string) string {
	m := hmac.New(sha256.New, key)
	for i, p := range parts {
		if i > 0 {
			m.Write([]byte("|"))
		}
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil))
}

func HMACVerify(key []byte, sig string, parts ...string) bool {
	want := HMACSign(key, parts...)
	return hmac.Equal([]byte(want), []byte(sig))
}

// RandomHex returns n random bytes hex encoded.
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

// B64 helpers.
func B64(b []byte) string { return base64Encode(b) }

func DecodeB64(s string) ([]byte, error) { return base64Decode(s) }

// zeroize wipes a slice.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// CanonicalParts joins values for signing without ambiguity.
func CanonicalParts(parts ...string) string {
	var buf bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			buf.WriteByte('|')
		}
		buf.WriteString(p)
	}
	return buf.String()
}
