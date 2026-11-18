package bdc2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestParseTunnelNoticeData(t *testing.T) {
	data := make([]byte, 4+5)
	binary.BigEndian.PutUint32(data[:4], 0xA1B2C3D4)
	copy(data[4:], []byte("hello"))
	kv := map[string][]byte{"sub": []byte("tunnel"), "ftype": []byte("65"), "data": data}

	tn, ok := ParseTunnelNotice(kv)
	if !ok {
		t.Fatal("expected tunnel notice")
	}
	if !tn.IsData() || tn.FType != TunnelFTypeData {
		t.Fatalf("ftype = %d, want data", tn.FType)
	}
	if tn.TID != 0xA1B2C3D4 {
		t.Fatalf("tid = %#x", tn.TID)
	}
	if string(tn.Data) != "hello" {
		t.Fatalf("data = %q", tn.Data)
	}
}

func TestParseTunnelNoticeClose(t *testing.T) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 7)
	kv := map[string][]byte{"sub": []byte("tunnel"), "ftype": []byte("66"), "data": data}

	tn, ok := ParseTunnelNotice(kv)
	if !ok || !tn.IsClose() || tn.TID != 7 || len(tn.Data) != 0 {
		t.Fatalf("unexpected close notice: %+v ok=%v", tn, ok)
	}
}

func TestParseTunnelNoticeIgnoresOtherNotices(t *testing.T) {
	if _, ok := ParseTunnelNotice(map[string][]byte{"reason": []byte("killed")}); ok {
		t.Fatal("plain notice must not parse as tunnel")
	}
	if _, ok := ParseTunnelNotice(map[string][]byte{"sub": []byte("other")}); ok {
		t.Fatal("non-tunnel sub must not parse as tunnel")
	}
	if tn, ok := ParseTunnelNotice(map[string][]byte{"sub": []byte("tunnel"), "ftype": []byte("65")}); !ok || tn.TID != 0 || len(tn.Data) != 0 {
		t.Fatalf("truncated payload should degrade to empty tid/data: %+v", tn)
	}
}

func TestParseEndpoint(t *testing.T) {
	cases := []struct {
		in               string
		tls              bool
		host, port, path string
		family           string
		wantErr          bool
	}{
		{"wss://oprand.example.com/ws", true, "oprand.example.com", "443", "/ws", "auto", false},
		{"wss://oprand.example.com", true, "oprand.example.com", "443", "/ws", "auto", false},
		{"ws://127.0.0.1:9910/ws", false, "127.0.0.1", "9910", "/ws", "auto", false},
		{"127.0.0.1:9910", false, "127.0.0.1", "9910", "/ws", "auto", false},
		{"[::1]:9910", false, "::1", "9910", "/ws", "auto", false},
		{"wss://h/", true, "h", "443", "/ws", "6", false},
		{"http://h/ws", false, "", "", "", "auto", true},
		{"", false, "", "", "", "auto", true},
		{"wss://h/ws", false, "", "", "", "bogus", true},
	}
	for _, c := range cases {
		fam := c.family
		ep, err := ParseEndpoint(c.in, "/ws", fam)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if ep.TLS != c.tls || ep.Host != c.host || ep.Port != c.port || ep.Path != c.path || ep.Family != c.family {
			t.Fatalf("%q -> %+v", c.in, ep)
		}
	}
}

func TestParsePin(t *testing.T) {
	sum := sha256.Sum256([]byte("cert-der"))
	hexUpper := hex.EncodeToString(sum[:])
	if b, err := ParsePin(hexUpper); err != nil || string(b) != string(sum[:]) {
		t.Fatalf("hex pin: %v", err)
	}
	colon := "sha256:" + hexUpper[0:2] + ":" + hexUpper[2:]
	if b, err := ParsePin(colon); err != nil || string(b) != string(sum[:]) {
		t.Fatalf("colon pin: %v", err)
	}
	if b, err := ParsePin(base64.StdEncoding.EncodeToString(sum[:])); err != nil || string(b) != string(sum[:]) {
		t.Fatalf("b64 pin: %v", err)
	}
	if _, err := ParsePin("abcd"); err == nil {
		t.Fatal("short pin should fail")
	}
}
