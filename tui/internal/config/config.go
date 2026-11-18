// Package config stores the operator-TUI settings.
//
// Nothing here contains a built-in endpoint or credential: the zero value is
// incomplete and must be filled from the config file, flags or environment.
// This keeps the single binary reusable across deployments (no IP / domain
// literals compiled in).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the on-disk TUI configuration. It intentionally mirrors the
// transport knobs of the frozen BDC2 v1 operator CLI so existing deployments
// can be reused unchanged.
type Config struct {
	// Endpoint is a ws:// or wss:// URL, e.g. wss://<operator-host>/ws.
	// Empty by default: no address is compiled into the binary.
	Endpoint string `json:"endpoint"`
	User     string `json:"user"`
	// PSK is in the same format as the operator CLI: base64:..., hex:... or
	// raw base64. It is stored with 0600 permissions and masked in the UI.
	PSK       string `json:"psk"`
	SNI       string `json:"sni,omitempty"`
	DialIP    string `json:"dial_ip,omitempty"`
	Family    string `json:"family,omitempty"` // auto|4|6
	TLSCA     string `json:"tls_ca,omitempty"`
	TLSPin    string `json:"tls_pin,omitempty"`
	Insecure  bool   `json:"insecure,omitempty"`
	TimeoutS  int    `json:"timeout_sec,omitempty"`
	RefreshS  int    `json:"refresh_sec,omitempty"`
	Download  string `json:"download_dir,omitempty"`
	TunnelOut string `json:"tunnel_out_dir,omitempty"`
	// ActionLog is an optional local JSONL file where the TUI appends the
	// operator actions it performed (local trail; the server keeps the
	// tamper-evident hash-chain audit log).
	ActionLog string `json:"action_log,omitempty"`
}

// Defaults returns a conservative configuration with no endpoint.
func Defaults() *Config {
	return &Config{
		User:     "ops",
		Family:   "auto",
		TimeoutS: 45,
		RefreshS: 4,
		Download: "downloads",
	}
}

// DefaultPath returns the per-user config path.
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "backd-c2tui", "config.json")
}

// Load reads path (if it exists), then applies environment overrides. A
// missing file is not an error: the caller can show the login screen.
// It returns the configuration and the path actually used.
func Load(path string) (*Config, string, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	c := Defaults()
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, path, fmt.Errorf("parse %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, path, fmt.Errorf("read %s: %w", path, err)
	}
	c.ApplyEnv()
	c.normalize()
	return c, path, nil
}

// ApplyEnv overlays C2_OPERATOR_* (shared with the CLI) and C2TUI_* vars.
func (c *Config) ApplyEnv() {
	set := func(dst *string, keys ...string) {
		for _, k := range keys {
			if v := os.Getenv(k); v != "" {
				*dst = v
				return
			}
		}
	}
	set(&c.Endpoint, "C2_OPERATOR_ADDR", "C2TUI_ENDPOINT")
	set(&c.User, "C2_OPERATOR_USER", "C2TUI_USER")
	set(&c.PSK, "C2_OPERATOR_PSK", "C2TUI_PSK")
	set(&c.SNI, "C2_OPERATOR_SNI", "C2TUI_SNI")
	set(&c.DialIP, "C2_OPERATOR_DIAL_IP", "C2TUI_DIAL_IP")
	set(&c.Family, "C2_OPERATOR_FAMILY", "C2TUI_FAMILY")
	set(&c.TLSCA, "C2_OPERATOR_TLS_CA", "C2TUI_TLS_CA")
	set(&c.TLSPin, "C2_OPERATOR_TLS_PIN", "C2TUI_TLS_PIN")
	set(&c.Download, "C2TUI_DOWNLOAD_DIR")
	set(&c.TunnelOut, "C2TUI_TUNNEL_OUT")
	set(&c.ActionLog, "C2TUI_ACTION_LOG")
	if os.Getenv("C2_OPERATOR_INSECURE") == "1" || os.Getenv("C2TUI_INSECURE") == "1" {
		c.Insecure = true
	}
}

func (c *Config) normalize() {
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	c.User = strings.TrimSpace(c.User)
	c.PSK = strings.TrimSpace(c.PSK)
	c.SNI = strings.TrimSpace(c.SNI)
	c.DialIP = strings.TrimSpace(c.DialIP)
	c.Family = strings.ToLower(strings.TrimSpace(c.Family))
	if c.Family == "" {
		c.Family = "auto"
	}
	if c.TimeoutS <= 0 {
		c.TimeoutS = 45
	}
	if c.RefreshS <= 0 {
		c.RefreshS = 4
	}
	if strings.TrimSpace(c.Download) == "" {
		c.Download = "downloads"
	}
}

// Validate reports whether enough information is present to connect.
func (c *Config) Validate() error {
	switch {
	case strings.TrimSpace(c.Endpoint) == "":
		return errors.New("endpoint is required (e.g. wss://<operator-host>/ws)")
	case !strings.HasPrefix(c.Endpoint, "ws://") && !strings.HasPrefix(c.Endpoint, "wss://"):
		return errors.New("endpoint must start with ws:// or wss://")
	case strings.TrimSpace(c.User) == "":
		return errors.New("operator user is required")
	case strings.TrimSpace(c.PSK) == "":
		return errors.New("operator PSK is required")
	}
	switch c.Family {
	case "auto", "4", "6":
	default:
		return fmt.Errorf("family must be auto, 4 or 6 (got %q)", c.Family)
	}
	return nil
}

// Complete reports whether the config can be used without a login screen.
func (c *Config) Complete() bool { return c.Validate() == nil }

// Clone returns a deep copy (Config only holds strings/bools).
func (c *Config) Clone() *Config {
	if c == nil {
		return Defaults()
	}
	cp := *c
	return &cp
}

// Save writes the config atomically with restrictive permissions.
func (c *Config) Save(path string) error {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}

// MaskedPSK is the value shown in the UI / logs.
func (c *Config) MaskedPSK() string { return MaskPSK(c.PSK) }

// MaskPSK keeps the encoding prefix and the last four characters, e.g.
// "base64:q7Xf…9kLm". Short or empty values are fully hidden.
func MaskPSK(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(unset)"
	}
	prefix := ""
	body := s
	for _, p := range []string{"base64:", "hex:"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			prefix = s[:len(p)]
			body = s[len(p):]
			break
		}
	}
	if len(body) <= 8 {
		return prefix + strings.Repeat("*", len(body))
	}
	return prefix + body[:4] + "…" + body[len(body)-4:]
}

// Summary is a one-line, secret-free description for the status bar.
func (c *Config) Summary() string {
	return fmt.Sprintf("%s user=%s psk=%s family=%s", c.Endpoint, c.User, c.MaskedPSK(), c.Family)
}
