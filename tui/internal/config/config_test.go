package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	c, path, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if path == "" || c.Family != "auto" || c.TimeoutS != 45 || c.RefreshS != 4 {
		t.Fatalf("unexpected defaults: %+v path=%q", c, path)
	}
	if c.Complete() {
		t.Fatal("empty endpoint/user/psk must not be complete")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("C2_OPERATOR_ADDR", "wss://operator.example/ws")
	t.Setenv("C2_OPERATOR_USER", "alice")
	t.Setenv("C2_OPERATOR_PSK", "base64:AAAA")
	t.Setenv("C2_OPERATOR_SNI", "operator.example")
	t.Setenv("C2_OPERATOR_FAMILY", "6")
	c, _, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Endpoint != "wss://operator.example/ws" || c.User != "alice" || c.SNI != "operator.example" || c.Family != "6" {
		t.Fatalf("env not applied: %+v", c)
	}
	if !c.Complete() {
		t.Fatalf("config should be complete: %v", c.Validate())
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf", "config.json")
	in := Defaults()
	in.Endpoint = "wss://h/ws"
	in.PSK = "base64:secret-material"
	if err := in.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
		t.Fatalf("config permissions = %o, want 600", fi.Mode().Perm())
	}
	out, _, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.Endpoint != in.Endpoint || out.PSK != in.PSK || out.User != in.User {
		t.Fatalf("round trip mismatch: %+v", out)
	}
}

func TestValidateFamily(t *testing.T) {
	c := Defaults()
	c.Endpoint = "ws://x/ws"
	c.PSK = "x"
	c.Family = "5"
	if err := c.Validate(); err == nil {
		t.Fatal("family 5 should be rejected")
	}
	c.Family = "auto"
	if err := c.Validate(); err != nil {
		t.Fatalf("auto should validate: %v", err)
	}
}

func TestMaskPSK(t *testing.T) {
	cases := map[string]string{
		"":                        "(unset)",
		"base64:0123456789abcdef": "base64:0123…cdef",
		"hex:deadbeef":            "hex:********",
		"short":                   "*****",
	}
	for in, want := range cases {
		if got := MaskPSK(in); got != want {
			t.Fatalf("MaskPSK(%q) = %q, want %q", in, got, want)
		}
	}
}
