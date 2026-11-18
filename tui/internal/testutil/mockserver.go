// Package testutil provides a protocol-accurate mock BDC2 v1 operator server
// for the client / ops tests. It speaks the frozen frame format only.
package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"backd/c2/mvp/internal/bdc2"
)

// PushRecord captures one OP_FILE_PUSH.
type PushRecord struct {
	File string
	Off  int64
	Data []byte
}

// Mock is a minimal operator endpoint.
type Mock struct {
	t    testing.TB
	User string
	PSK  []byte

	Sessions []map[string]any
	Stats    map[string]any

	TaskStatus string
	TaskOut    []byte
	TaskErr    string

	Files     map[string][]byte
	ChunkSize int

	NoticeAfterAuth bool
	RejectAuth      bool

	mu         sync.Mutex
	closeAfter int
	reqs       []string
	pushes     []PushRecord
	srv        *httptest.Server
}

// NewMock starts a mock server on a loopback port.
func NewMock(t testing.TB) *Mock {
	m := &Mock{
		t:          t,
		User:       "ops",
		PSK:        []byte("0123456789abcdef0123456789abcdef"),
		TaskStatus: "ok",
		Files:      map[string][]byte{},
		ChunkSize:  3,
		Stats:      map[string]any{"sessions": 1, "advanced": true},
		Sessions: []map[string]any{{
			"id":        1,
			"client_id": "HOST-TEST",
			"os":        "windows",
			"arch":      "amd64",
			"ver":       "0.1.0",
			"addr":      "10.0.0.5:5555",
			"last_seen": time.Now().UTC().Format(time.RFC3339),
		}},
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(func() { m.srv.Close() })
	return m
}

// URL is the ws:// endpoint for the client.
func (m *Mock) URL() string {
	return "ws" + strings.TrimPrefix(m.srv.URL, "http") + "/ws"
}

// SetCloseAfter makes the server close the connection after n requests.
func (m *Mock) SetCloseAfter(n int) {
	m.mu.Lock()
	m.closeAfter = n
	m.mu.Unlock()
}

// Requests returns the handled operator requests.
func (m *Mock) Requests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.reqs...)
}

// Pushes returns recorded uploads.
func (m *Mock) Pushes() []PushRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]PushRecord(nil), m.pushes...)
}

func (m *Mock) record(s string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reqs = append(m.reqs, s)
	return len(m.reqs)
}

func (m *Mock) shouldClose(n int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeAfter > 0 && n >= m.closeAfter
}

func (m *Mock) handle(w http.ResponseWriter, r *http.Request) {
	ws, err := bdc2.UpgradeServer(w, r, 1<<20)
	if err != nil {
		return
	}
	defer ws.Close()
	_ = ws.SetReadDeadline(time.Now().Add(20 * time.Second))

	_, data, err := ws.ReadMessage()
	if err != nil {
		return
	}
	typ, flags, _, _, payload, err := bdc2.OpenFrame(nil, data, bdc2.DirOperToServer)
	if err != nil || typ != bdc2.TypeAuth || flags&bdc2.FlagCleartext == 0 {
		return
	}
	kv, err := bdc2.DecodeTLV(payload)
	if err != nil {
		return
	}
	user := string(kv["user"])
	nonce := kv["nonce"]
	mac := kv["mac"]
	if m.RejectAuth || user != m.User || len(nonce) != 16 ||
		!equalMAC(mac, bdc2.OperatorAuthMAC(m.PSK, user, nonce)) {
		return
	}
	key, err := bdc2.OperatorKey(m.PSK, user)
	if err != nil {
		return
	}

	seq := uint32(0)
	send := func(t uint8, kvs []bdc2.KV) bool {
		seq++
		fr, err := bdc2.SealFrame(key, t, 0, 0, seq, bdc2.DirServerToOper, bdc2.EncodeTLV(kvs))
		if err != nil {
			return false
		}
		return ws.WriteBinary(fr) == nil
	}

	if !send(bdc2.TypeAuthOK, []bdc2.KV{bdc2.S("ok", "1")}) {
		return
	}
	if m.NoticeAfterAuth {
		tf := bdc2.TunnelNoticeFrame(bdc2.TunnelFTypeData, 7, []byte("hello-tunnel"))
		kvs := []bdc2.KV{}
		for k, v := range tf {
			kvs = append(kvs, bdc2.B(k, v))
		}
		if !send(bdc2.TypeNotice, kvs) {
			return
		}
	}

	recvSeq := uint32(0)
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		typ, _, _, sq, payload, err := bdc2.OpenFrame(key, data, bdc2.DirOperToServer)
		if err != nil || sq <= recvSeq {
			return
		}
		recvSeq = sq
		kv, err := bdc2.DecodeTLV(payload)
		if err != nil {
			return
		}
		n := m.dispatch(typ, kv, send)
		if m.shouldClose(n) {
			return
		}
	}
}

func (m *Mock) dispatch(typ uint8, kv map[string][]byte, send func(uint8, []bdc2.KV) bool) int {
	switch typ {
	case bdc2.TypeOpList:
		sess, _ := json.Marshal(m.Sessions)
		st, _ := json.Marshal(m.Stats)
		kvs := []bdc2.KV{bdc2.B("sessions", sess), bdc2.B("stats", st)}
		if string(kv["reload"]) == "1" && string(kv["config"]) == "bad" {
			kvs = append(kvs, bdc2.S("reload_err", "mock reload failure"))
		}
		n := m.record("list")
		send(bdc2.TypeOpListResult, kvs)
		return n

	case bdc2.TypeOpTask:
		sid := string(kv["session"])
		kind := string(kv["kind"])
		args := string(kv["args"])
		n := m.record("task " + sid + " " + kind + " " + args)
		out := m.TaskOut
		if out == nil {
			out = []byte("mock-out:" + kind)
		}
		status := m.TaskStatus
		if status == "" {
			status = "ok"
		}
		send(bdc2.TypeOpResult, []bdc2.KV{
			bdc2.S("status", status),
			bdc2.S("session", sid),
			bdc2.B("out", out),
			bdc2.S("err", m.TaskErr),
		})
		return n

	case bdc2.TypeOpFilePush:
		file := string(kv["file"])
		off, _ := strconv.ParseInt(string(kv["off"]), 10, 64)
		data := append([]byte(nil), kv["data"]...)
		m.mu.Lock()
		m.pushes = append(m.pushes, PushRecord{File: file, Off: off, Data: data})
		m.mu.Unlock()
		sum := sha256.Sum256(data)
		n := m.record("push " + file + " off=" + strconv.FormatInt(off, 10) + " len=" + strconv.Itoa(len(data)))
		send(bdc2.TypeOpResult, []bdc2.KV{bdc2.S("status", "ok"), bdc2.S("sha", hex.EncodeToString(sum[:]))})
		return n

	case bdc2.TypeOpFilePull:
		file := string(kv["file"])
		data := m.Files[file]
		if data == nil {
			n := m.record("pull-miss " + file)
			send(bdc2.TypeOpResult, []bdc2.KV{bdc2.S("status", "error"), bdc2.S("err", "file not found")})
			return n
		}
		sum := sha256.Sum256(data)
		xfer := "x-" + path.Base(file)
		n := m.record("pull " + file)
		send(bdc2.TypeOpResult, []bdc2.KV{
			bdc2.S("status", "ok"),
			bdc2.S("xfer", xfer),
			bdc2.S("size", strconv.Itoa(len(data))),
			bdc2.S("sha", hex.EncodeToString(sum[:])),
		})
		return n

	case bdc2.TypeOpFileFetch:
		xfer := string(kv["xfer"])
		name := strings.TrimPrefix(xfer, "x-")
		data := m.fileByName(name)
		n := m.record("fetch " + xfer)
		chunk := m.ChunkSize
		if chunk <= 0 {
			chunk = 3
		}
		for i := 0; i < len(data); i += chunk {
			end := i + chunk
			if end > len(data) {
				end = len(data)
			}
			if !send(bdc2.TypeOpFileChunk, []bdc2.KV{bdc2.B("data", data[i:end])}) {
				return n
			}
		}
		sum := sha256.Sum256(data)
		send(bdc2.TypeOpFileDone, []bdc2.KV{
			bdc2.S("sha", hex.EncodeToString(sum[:])),
			bdc2.S("size", strconv.Itoa(len(data))),
		})
		return n

	case bdc2.TypeOpKill:
		n := m.record("kill " + string(kv["session"]))
		send(bdc2.TypeOpResult, []bdc2.KV{bdc2.S("status", "ok")})
		return n

	default:
		n := m.record(fmt.Sprintf("unknown-%d", typ))
		send(bdc2.TypeError, []bdc2.KV{bdc2.S("msg", "unsupported")})
		return n
	}
}

func (m *Mock) fileByName(name string) []byte {
	if d, ok := m.Files[name]; ok {
		return d
	}
	for k, d := range m.Files {
		if path.Base(strings.ReplaceAll(k, "\\", "/")) == name {
			return d
		}
	}
	return nil
}

func equalMAC(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
