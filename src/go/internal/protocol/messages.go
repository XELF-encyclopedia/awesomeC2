package protocol

import (
	"encoding/json"
	"fmt"
)

// Message type tags.
const (
	THello        = "hello"
	THelloAck     = "hello_ack"
	THB           = "hb"
	THBAck        = "hb_ack"
	TTask         = "task"
	TResult       = "result"
	TFrag         = "frag"
	TKillPrepare  = "kill_prepare"
	TKill         = "kill"
	TKillAck      = "kill_ack"
	TUpdate       = "update"
	TUpdateResult = "update_result"
	TOpHello      = "op_hello"
	TOpHelloAck   = "op_hello_ack"
	TOpCmd        = "op_cmd"
	TOpResp       = "op_resp"
	TPresence     = "presence"
	TTunnelOpen   = "tunnel_open"
	TTunnelClose  = "tunnel_close"
	TTunnelData   = "tunnel_data"
	TError        = "error"
)

// Machine describes the client host.
type Machine struct {
	Host    string   `json:"host"`
	OS      string   `json:"os"`
	Arch    string   `json:"arch"`
	User    string   `json:"user"`
	PID     int      `json:"pid"`
	Version string   `json:"version"`
	Addrs   []string `json:"addrs,omitempty"`
}

// Hello is the first client->server message, sent in a plain envelope.
type Hello struct {
	V         int      `json:"v"`
	T         string   `json:"t"`
	ClientID  string   `json:"client_id"`
	Nonce     string   `json:"nonce"`
	Pub       string   `json:"pub"`
	Cipher    string   `json:"cipher"`
	Transport string   `json:"transport"`
	Caps      []string `json:"caps"`
	TS        int64    `json:"ts"`
	Machine   Machine  `json:"machine"`
	NonceSig  string   `json:"nonce_sig,omitempty"` // optional HMAC(psk, client_id|nonce|ts)
}

// HelloAck is the server response, also plain.
type HelloAck struct {
	V          int    `json:"v"`
	T          string `json:"t"`
	Nonce      string `json:"nonce"`
	Pub        string `json:"pub"`
	Cipher     string `json:"cipher"`
	SID        string `json:"sid"`
	ServerTime int64  `json:"server_time"`
	Sleep      int    `json:"sleep"`
	Jitter     int    `json:"jitter"`
	Protocol   int    `json:"protocol"`
	Tenant     string `json:"tenant,omitempty"`
	Error      string `json:"error,omitempty"`
}

// HB is a client heartbeat.
type HB struct {
	T     string `json:"t"`
	TS    int64  `json:"ts"`
	Seq   uint64 `json:"seq"`
	Queue int    `json:"queue,omitempty"`
}

// HBAck acknowledges a heartbeat (server time lets the client measure skew).
type HBAck struct {
	T  string `json:"t"`
	TS int64  `json:"ts"`
}

// Task is a module invocation.
type Task struct {
	T         string          `json:"t"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Args      json.RawMessage `json:"args,omitempty"`
	TimeoutMS int             `json:"timeout_ms,omitempty"`
	Op        string          `json:"op,omitempty"`
	Created   int64           `json:"created,omitempty"`
}

// Result is the task outcome. Large payloads are split with Frag.
type Result struct {
	T       string          `json:"t"`
	ID      string          `json:"id"`
	OK      bool            `json:"ok"`
	Data    json.RawMessage `json:"data,omitempty"`
	Err     string          `json:"err,omitempty"`
	Elapsed int64           `json:"elapsed_ms,omitempty"`
	Frag    bool            `json:"frag,omitempty"`
}

// Frag is one fragment of an oversized JSON message.
type Frag struct {
	T     string `json:"t"`
	FID   string `json:"fid"`
	Idx   int    `json:"idx"`
	Total int    `json:"total"`
	Data  string `json:"data"` // base64
}

// KillPrepare is the first of two kill-switch steps.
type KillPrepare struct {
	T       string `json:"t"`
	Nonce   string `json:"nonce"`
	Expires int64  `json:"expires"`
	Issuer  string `json:"issuer"`
	Reason  string `json:"reason,omitempty"`
}

// Kill carries the signed kill order.
type Kill struct {
	T         string `json:"t"`
	Nonce     string `json:"nonce"`
	Expires   int64  `json:"expires"`
	WipeKeys  bool   `json:"wipe_keys"`
	Uninstall bool   `json:"uninstall"`
	Sig       string `json:"sig"`
	Issuer    string `json:"issuer,omitempty"`
}

// Canonical returns the signing string for a Kill message.
func (k *Kill) Canonical(sid string) string {
	return CanonicalParts(sid, k.Nonce, fmt.Sprint(k.Expires), fmt.Sprint(k.WipeKeys), fmt.Sprint(k.Uninstall))
}

// KillAck reports the kill-switch outcome.
type KillAck struct {
	T     string `json:"t"`
	Nonce string `json:"nonce"`
	OK    bool   `json:"ok"`
	Note  string `json:"note,omitempty"`
}

// UpdateManifest describes a signed release.
type UpdateManifest struct {
	Version    string `json:"version"`
	Platform   string `json:"platform"`
	Arch       string `json:"arch"`
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size,omitempty"`
	Rollout    int    `json:"rollout"` // 0-100
	MinVersion string `json:"min_version,omitempty"`
	Rollback   string `json:"rollback,omitempty"`
	Created    int64  `json:"created,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// Canonical returns the signing string for a manifest.
func (m *UpdateManifest) Canonical() string {
	return CanonicalParts(m.Version, m.Platform, m.Arch, m.URL, m.SHA256, fmt.Sprint(m.Rollout), m.MinVersion, m.Rollback)
}

// Update is a server push carrying a signed manifest.
type Update struct {
	T        string         `json:"t"`
	Manifest UpdateManifest `json:"manifest"`
	Sig      string         `json:"sig"`
	DryRun   bool           `json:"dry_run,omitempty"`
}

// Matches applies platform/arch/rollout selection.
func (m UpdateManifest) Matches(clientID, osName, arch string) bool {
	if m.Platform != "" && m.Platform != osName {
		return false
	}
	if m.Arch != "" && m.Arch != arch {
		return false
	}
	if m.Rollout <= 0 {
		return false
	}
	if m.Rollout >= 100 {
		return true
	}
	h := HMACSign([]byte("rollout"), clientID)
	v := 0
	for i := 0; i < 2 && i < len(h); i++ {
		d := 0
		c := h[i]
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		}
		v = v*16 + d
	}
	return (v*100)/256 < m.Rollout
}

// UpdateResult reports staging/apply progress.
type UpdateResult struct {
	T       string `json:"t"`
	Version string `json:"version"`
	State   string `json:"state"` // staged|applied|rejected|rolled_back|error
	Note    string `json:"note,omitempty"`
}

// OpHello authenticates an operator.
type OpHello struct {
	V     int    `json:"v"`
	T     string `json:"t"`
	User  string `json:"user"`
	Nonce string `json:"nonce"`
	Pub   string `json:"pub"`
	TS    int64  `json:"ts"`
	MAC   string `json:"mac"` // HMAC(op_key, user|nonce|pub|ts)
}

// OpHelloAck agrees on the operator session.
type OpHelloAck struct {
	V     int    `json:"v"`
	T     string `json:"t"`
	User  string `json:"user"`
	Role  string `json:"role"`
	Tenant string `json:"tenant,omitempty"`
	Nonce string `json:"nonce"`
	Pub   string `json:"pub"`
	SID   string `json:"sid"`
	TS    int64  `json:"ts"`
	Error string `json:"error,omitempty"`
}

// OpCmd is an operator request.
type OpCmd struct {
	T    string          `json:"t"`
	Req  uint64          `json:"req"`
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
	TS   int64           `json:"ts"`
}

// OpResp is the matching reply.
type OpResp struct {
	T    string          `json:"t"`
	Req  uint64          `json:"req"`
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data,omitempty"`
	Err  string          `json:"err,omitempty"`
}

// Presence lists connected operators.
type Presence struct {
	T         string     `json:"t"`
	Operators []PresenceEntry `json:"operators"`
	At        int64      `json:"at"`
}

// PresenceEntry is one operator presence record.
type PresenceEntry struct {
	User     string `json:"user"`
	Role     string `json:"role"`
	Tenant   string `json:"tenant"`
	Since    int64  `json:"since"`
	LastSeen int64  `json:"last_seen"`
}

// Tunnel messages implement a server-side listener that forwards to the client.
type TunnelOpen struct {
	T       string `json:"t"`
	TID     string `json:"tid"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Local   int    `json:"local"`
	Err     string `json:"err,omitempty"`
	OK      bool   `json:"ok,omitempty"`
}

type TunnelClose struct {
	T   string `json:"t"`
	TID string `json:"tid"`
}

type TunnelData struct {
	T    string `json:"t"`
	TID  string `json:"tid"`
	Data string `json:"data"` // base64
	FIN  bool   `json:"fin,omitempty"`
}

// Error is a generic protocol error.
type Error struct {
	T   string `json:"t"`
	Msg string `json:"msg"`
}

// Marshal marshals any message.
func Marshal(v any) ([]byte, error) { return json.Marshal(v) }

// EncodePlain marshals v and wraps it in a plaintext envelope.
func EncodePlain(v any) ([]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	return PlainEnvelope(b), nil
}

// MessageType peeks at the "t" field.
func MessageType(b []byte) string {
	var probe struct {
		T string `json:"t"`
	}
	_ = json.Unmarshal(b, &probe)
	return probe.T
}
