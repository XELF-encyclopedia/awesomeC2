package protocol

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFragReassemblyOutOfOrder(t *testing.T) {
	plain := bytes.Repeat([]byte("abcdefghij"), 1500) // 15 KB
	parts, err := FragmentJSON(plain, 700, "f1")
	if err != nil {
		t.Fatalf("fragment: %v", err)
	}
	if len(parts) < 20 {
		t.Fatalf("expected many parts, got %d", len(parts))
	}
	r := NewReassembler()
	// feed in reverse order, and duplicate one part
	order := make([]int, 0, len(parts)*2)
	for i := len(parts) - 1; i >= 0; i-- {
		order = append(order, i)
	}
	order = append(order, len(parts)/2)
	var got []byte
	for _, idx := range order {
		var f Frag
		if err := json.Unmarshal(parts[idx], &f); err != nil {
			t.Fatalf("unmarshal frag: %v", err)
		}
		out, done, err := r.Add(&f)
		if err != nil {
			t.Fatalf("add: %v", err)
		}
		if done {
			got = out
			break
		}
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("reassembled payload mismatch: %d vs %d bytes", len(got), len(plain))
	}
	// a second complete message with the same fid must work again
	r2 := NewReassembler()
	var again []byte
	for _, p := range parts {
		var f Frag
		_ = json.Unmarshal(p, &f)
		out, done, err := r2.Add(&f)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			again = out
		}
	}
	if !bytes.Equal(again, plain) {
		t.Fatalf("second reassembly failed")
	}
}

func TestFragRejectsBadInput(t *testing.T) {
	r := NewReassembler()
	if _, _, err := r.Add(&Frag{T: TFrag, FID: "x", Idx: -1, Total: 2, Data: B64([]byte("a"))}); err == nil {
		t.Fatalf("negative index accepted")
	}
	if _, _, err := r.Add(&Frag{T: TFrag, FID: "x", Idx: 5, Total: 2, Data: B64([]byte("a"))}); err == nil {
		t.Fatalf("out of range index accepted")
	}
	if _, _, err := r.Add(&Frag{T: TFrag, FID: "x", Idx: 0, Total: 2, Data: "!!!"}); err == nil {
		t.Fatalf("bad base64 accepted")
	}
}

func TestDNSMultiQuestionRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xA5, 0x01, 0x7F}, 200) // 600 bytes > single QNAME
	q := EncodeDNSQuery(payload, "test.example.com", 50)
	names, err := ParseQueryNames(q)
	if err != nil {
		t.Fatalf("parse names: %v", err)
	}
	if len(names) < 2 {
		t.Fatalf("expected multi-question query, got %d", len(names))
	}
	for _, n := range names {
		if len(n) > 253 {
			t.Fatalf("question name %d octets exceeds the DNS limit", len(n))
		}
		if !strings.HasSuffix(n, "test.example.com") {
			t.Fatalf("suffix missing: %s", n)
		}
	}
	got, err := ParseDNSQueryPayload(q, "test.example.com")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d vs %d", len(got), len(payload))
	}
	// small payloads still work
	small := []byte(`{"hello":"world"}`)
	got2, err := ParseDNSQueryPayload(EncodeDNSQuery(small, "t.example.com", 50), "t.example.com")
	if err != nil || !bytes.Equal(got2, small) {
		t.Fatalf("small payload failed: %v %q", err, got2)
	}
}

func TestKeyDerivationAndEnvelopes(t *testing.T) {
	a, _ := NewEphemeral()
	b, _ := NewEphemeral()
	sharedA, err := SharedRaw(a, PublicRaw(b))
	if err != nil {
		t.Fatal(err)
	}
	sharedB, err := SharedRaw(b, PublicRaw(a))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sharedA, sharedB) {
		t.Fatalf("x25519 shared secret mismatch")
	}
	psk := bytes.Repeat([]byte{7}, 32)
	nc := make([]byte, 32)
	ns := make([]byte, 32)
	_, _ = rand.Read(nc)
	_, _ = rand.Read(ns)

	for _, cs := range []CipherSuite{CipherAES256GCM, CipherChaCha20Poly1305} {
		ka, err := DeriveKeys(sharedA, psk, nc, ns, cs)
		if err != nil {
			t.Fatalf("derive %v: %v", cs, err)
		}
		kb, err := DeriveKeys(sharedB, psk, nc, ns, cs)
		if err != nil {
			t.Fatal(err)
		}
		if ka.SID != kb.SID || ka.SID == "" {
			t.Fatalf("sid not deterministic: %q %q", ka.SID, kb.SID)
		}
		env, err := ka.Seal(DirClientToServer, []byte("ping"))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := kb.Open(DirClientToServer, env)
		if err != nil || string(plain) != "ping" {
			t.Fatalf("%v open: %v %q", cs, err, plain)
		}
		// direction confusion must fail
		if _, err := kb.Open(DirServerToClient, env); err == nil {
			t.Fatalf("%v accepted envelope in the wrong direction", cs)
		}
		// tampered ciphertext must fail
		env[len(env)-1] ^= 0xFF
		if _, err := kb.Open(DirClientToServer, env); err == nil {
			t.Fatalf("%v accepted tampered envelope", cs)
		}
	}
	// A different PSK must not decrypt envelopes sealed with the real one.
	other, _ := DeriveKeys(sharedA, bytes.Repeat([]byte{8}, 32), nc, ns, CipherAES256GCM)
	ka, _ := DeriveKeys(sharedA, psk, nc, ns, CipherAES256GCM)
	env, _ := ka.Seal(DirClientToServer, []byte("secret"))
	if _, err := other.Open(DirClientToServer, env); err == nil {
		t.Fatalf("wrong PSK decrypted the envelope")
	}
}

func TestPlainEnvelopeAndFraming(t *testing.T) {
	env := PlainEnvelope([]byte(`{"t":"hello"}`))
	body, err := ParsePlain(env)
	if err != nil || string(body) != `{"t":"hello"}` {
		t.Fatalf("plain envelope: %v %q", err, body)
	}
	var buf bytes.Buffer
	if err := WriteStreamFrame(&buf, env); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStreamFrame(&buf)
	if err != nil || !bytes.Equal(got, env) {
		t.Fatalf("stream frame: %v", err)
	}
	// truncated frame must error, not hang
	short := buf.Bytes()[:4]
	if _, err := ReadStreamFrame(bytes.NewReader(short)); err == nil {
		t.Fatalf("truncated frame accepted")
	}
}

func TestHMACAndCanonical(t *testing.T) {
	key := []byte("k")
	sig := HMACSign(key, "a", "b")
	if !HMACVerify(key, sig, "a", "b") {
		t.Fatalf("valid sig rejected")
	}
	if HMACVerify(key, sig, "a", "c") {
		t.Fatalf("wrong parts accepted")
	}
	if HMACVerify([]byte("other"), sig, "a", "b") {
		t.Fatalf("wrong key accepted")
	}
	if CanonicalParts("a", "b") != CanonicalParts("a", "b") {
		t.Fatalf("canonical not stable")
	}
	if CanonicalParts("a", "b") == CanonicalParts("ab", "") {
		t.Fatalf("canonical is ambiguous")
	}
}

func TestWebSocketRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsWebSocketUpgrade(r) {
			http.Error(w, "upgrade required", http.StatusBadRequest)
			return
		}
		ws, err := UpgradeWebSocket(w, r)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			msg, err := ws.Recv()
			if err != nil {
				return
			}
			if err := ws.Send(append([]byte("echo:"), msg...)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := DialWebSocket(conn, addr, "/ws")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()
	if err := ws.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = ws.NetConn().SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := ws.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(got) != "echo:hello" {
		t.Fatalf("got %q", got)
	}
	// large (>64KB control limit) binary message must survive fragmentation
	big := bytes.Repeat([]byte("x"), 200*1024)
	if err := ws.Send(big); err != nil {
		t.Fatal(err)
	}
	_ = ws.NetConn().SetReadDeadline(time.Now().Add(5 * time.Second))
	gotBig, err := ws.Recv()
	if err != nil {
		t.Fatalf("big recv: %v", err)
	}
	if len(gotBig) != len(big)+5 {
		t.Fatalf("big message length %d", len(gotBig))
	}
}

func TestX25519KeyIsECDH(t *testing.T) {
	if _, err := ecdh.X25519().GenerateKey(rand.Reader); err != nil {
		t.Fatalf("x25519 unavailable: %v", err)
	}
}

