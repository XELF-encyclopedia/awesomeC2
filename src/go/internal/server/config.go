package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ListenerConfig describes one client-facing transport listener.
type ListenerConfig struct {
	Transport   string `json:"transport"` // tls|tcp|ws|wss|udp|dns|doh
	Addr        string `json:"addr"`
	Path        string `json:"path,omitempty"`
	Suffix      string `json:"suffix,omitempty"` // DNS suffix
	CertFile    string `json:"cert_file,omitempty"`
	KeyFile     string `json:"key_file,omitempty"`
	MaxDatagram int    `json:"max_datagram,omitempty"`
}

// OperatorConfig provisions an operator and role.
type OperatorConfig struct {
	User   string `json:"user"`
	Role   string `json:"role"` // admin|operator|viewer
	Tenant string `json:"tenant"`
	KeyB64 string `json:"key_b64"`
}

// AIConfig configures the optional post-exploitation assistant.  Any
// OpenAI-compatible endpoint works; the API key is read from the environment
// variable named by KeyEnv so it never lands in the config file.
type AIConfig struct {
	Enabled      bool    `json:"enabled"`
	BaseURL      string  `json:"base_url,omitempty"`
	Model        string  `json:"model,omitempty"`
	KeyEnv       string  `json:"key_env,omitempty"` // default C2V2_AI_KEY
	AutoReadOnly *bool   `json:"auto_read_only,omitempty"`
	MaxRounds    int     `json:"max_rounds,omitempty"`
	Temperature  float64 `json:"temperature,omitempty"`
}

// Config is the server configuration.
type Config struct {
	ServerName       string           `json:"server_name"`
	Storage          string           `json:"storage"` // sqlite|postgres|memory
	DSN              string           `json:"dsn"`
	Tenant           string           `json:"tenant"`
	CertFile         string           `json:"cert_file,omitempty"`
	KeyFile          string           `json:"key_file,omitempty"`
	AutoCert         bool             `json:"auto_cert"`
	CertNames        []string         `json:"cert_names,omitempty"`
	Listeners        []ListenerConfig `json:"listeners"`
	OperatorListener ListenerConfig   `json:"operator_listener"`
	Operators        []OperatorConfig `json:"operators"`
	PSKB64           string           `json:"psk_b64"`
	KillKeyB64       string           `json:"kill_key_b64"`
	UpdateKeyB64     string           `json:"update_key_b64"`
	Sleep            int              `json:"sleep"`
	Jitter           int              `json:"jitter"`
	DeadmanSecs      int              `json:"deadman_secs,omitempty"`
	MaxFrame         int              `json:"max_frame,omitempty"`
	Verbose          bool             `json:"verbose"`
	ModulesDir       string           `json:"modules_dir,omitempty"`
	UpdatePin        string           `json:"update_pin,omitempty"`
	AI               AIConfig         `json:"ai,omitempty"`
}

// DefaultConfig returns a lab-safe configuration with example placeholders.
func DefaultConfig() *Config {
	return &Config{
		ServerName: "c2v2",
		Storage:    "sqlite",
		DSN:        "file:c2v2.db?_pragma=busy_timeout(5000)",
		Tenant:     "default",
		AutoCert:   true,
		CertNames:  []string{"localhost", "c2.example.com"},
		Listeners: []ListenerConfig{
			{Transport: "tls", Addr: "127.0.0.1:9443"},
			{Transport: "wss", Addr: "127.0.0.1:9444", Path: "/ws"},
			{Transport: "udp", Addr: "127.0.0.1:9445"},
			{Transport: "dns", Addr: "127.0.0.1:9446", Suffix: "c2.example.com"},
			{Transport: "doh", Addr: "127.0.0.1:9447", Path: "/doh"},
		},
		OperatorListener: ListenerConfig{Transport: "wss", Addr: "127.0.0.1:9448", Path: "/op"},
		Operators: []OperatorConfig{
			{User: "admin", Role: "admin", Tenant: "default", KeyB64: "REPLACE_ME"},
		},
		PSKB64:       "REPLACE_ME",
		KillKeyB64:   "REPLACE_ME",
		UpdateKeyB64: "REPLACE_ME",
		Sleep:        60,
		Jitter:       20,
		DeadmanSecs:  0,
		ModulesDir:   "profiles/modules",
		AI:           AIConfig{KeyEnv: "C2V2_AI_KEY", MaxRounds: 6},
	}
}

// LoadConfig reads a JSON config file and applies defaults.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Sleep <= 0 {
		cfg.Sleep = 60
	}
	if cfg.Tenant == "" {
		cfg.Tenant = "default"
	}
	if cfg.ModulesDir == "" {
		cfg.ModulesDir = "profiles/modules"
	}
	if cfg.AI.KeyEnv == "" {
		cfg.AI.KeyEnv = "C2V2_AI_KEY"
	}
	return cfg, nil
}

// DecodeKey decodes a base64 key, tolerating "base64:" prefix and placeholders.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "base64:")
	if s == "" || s == "REPLACE_ME" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad base64 key: %w", err)
	}
	return b, nil
}
