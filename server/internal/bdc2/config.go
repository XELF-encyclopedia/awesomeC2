package bdc2

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientCfg struct {
	ID  string `json:"id"`
	PSK string `json:"psk"`
}

type OperatorCfg struct {
	Name string `json:"name"`
	PSK  string `json:"psk"`
}

type TLSConfig struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type Config struct {
	ClientListen      string        `json:"client_listen"`
	OperatorListen    string        `json:"operator_listen"`
	ClientPSK         string        `json:"client_psk"`
	Clients           []ClientCfg   `json:"clients"`
	Operators         []OperatorCfg `json:"operators"`
	HeartbeatSec      int           `json:"heartbeat_sec"`
	JitterPct         int           `json:"jitter_pct"`
	SessionTimeoutSec int           `json:"session_timeout_sec"`
	MaxSessions       int           `json:"max_sessions"`
	MaxFrameBytes     int           `json:"max_frame_bytes"`
	FilesDir          string        `json:"files_dir"`
	AuditLog          string        `json:"audit_log"`
	AllowShell        bool          `json:"allow_shell"`
	AllowAdvanced     bool          `json:"allow_advanced"`
	// Merged server capability set (see docs/MERGE.md). All values are
	// optional and default to conservative settings, so old configs keep
	// working unchanged.
	ClientMsgsPerSec   int       `json:"client_msgs_per_sec"`
	OperatorMsgsPerSec int       `json:"operator_msgs_per_sec"`
	TaskMaxInflight    int       `json:"task_max_inflight"`
	TaskMaxAttempts    int       `json:"task_max_attempts"`
	TaskOutputMax      int       `json:"task_output_max"`
	MaxFileSize        int64     `json:"max_file_size"`
	AuditHashChain     *bool     `json:"audit_hash_chain"`
	TLS                TLSConfig `json:"tls"`
}

// HashChain returns whether the tamper-evident audit chain is enabled
// (default on).
func (c *Config) HashChain() bool {
	if c.AuditHashChain == nil {
		return true
	}
	return *c.AuditHashChain
}

func DefaultConfig() *Config {
	return &Config{
		ClientListen:       "127.0.0.1:9909",
		OperatorListen:     "127.0.0.1:9910",
		HeartbeatSec:       15,
		JitterPct:          20,
		SessionTimeoutSec:  90,
		MaxSessions:        512,
		MaxFrameBytes:      MaxFrame,
		FilesDir:           "./files",
		AuditLog:           "./audit.log",
		ClientMsgsPerSec:   100,
		OperatorMsgsPerSec: 50,
		TaskMaxInflight:    4,
		TaskMaxAttempts:    1,
		TaskOutputMax:      1 << 20,
		MaxFileSize:        64 << 20,
	}
}

func LoadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if c.HeartbeatSec <= 0 {
		c.HeartbeatSec = 15
	}
	if c.SessionTimeoutSec < c.HeartbeatSec*2 {
		c.SessionTimeoutSec = c.HeartbeatSec * 2
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 512
	}
	if c.MaxFrameBytes <= 0 || c.MaxFrameBytes > 8<<20 {
		c.MaxFrameBytes = MaxFrame
	}
	if c.ClientMsgsPerSec <= 0 {
		c.ClientMsgsPerSec = 100
	}
	if c.OperatorMsgsPerSec <= 0 {
		c.OperatorMsgsPerSec = 50
	}
	if c.TaskMaxInflight <= 0 {
		c.TaskMaxInflight = 4
	}
	if c.TaskMaxInflight > 64 {
		c.TaskMaxInflight = 64
	}
	if c.TaskMaxAttempts <= 0 {
		c.TaskMaxAttempts = 1
	}
	if c.TaskMaxAttempts > 5 {
		c.TaskMaxAttempts = 5
	}
	if c.TaskOutputMax <= 0 || c.TaskOutputMax > 64<<20 {
		c.TaskOutputMax = 1 << 20
	}
	if c.MaxFileSize <= 0 {
		c.MaxFileSize = 64 << 20
	}
	return c, nil
}

// ClientKeys resolves client id -> psk. A per-client entry wins over the global
// client_psk. An empty id uses the global psk.
func (c *Config) ClientKeys() (map[string][]byte, error) {
	m := make(map[string][]byte)
	if c.ClientPSK != "" {
		k, err := DecodePSK(c.ClientPSK)
		if err != nil {
			return nil, fmt.Errorf("client_psk: %w", err)
		}
		m[""] = k
	}
	for _, cl := range c.Clients {
		k, err := DecodePSK(cl.PSK)
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", cl.ID, err)
		}
		m[cl.ID] = k
	}
	return m, nil
}

func (c *Config) OperatorKeys() (map[string][]byte, error) {
	m := make(map[string][]byte)
	for _, op := range c.Operators {
		k, err := DecodePSK(op.PSK)
		if err != nil {
			return nil, fmt.Errorf("operator %s: %w", op.Name, err)
		}
		m[op.Name] = k
	}
	return m, nil
}
