// Package store provides persistence for sessions, tasks, operators, locks,
// audit trail and update manifests. SQLite is the default backend; Postgres
// can be selected through configuration. A memory backend exists for tests.
package store

import (
	"context"
	"crypto/sha256"
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Session is a persisted agent session record.
type Session struct {
	SID       string `json:"sid"`
	ClientID  string `json:"client_id"`
	Host      string `json:"host"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	User      string `json:"user"`
	Transport string `json:"transport"`
	Tenant    string `json:"tenant"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	State     string `json:"state"`
	Meta      string `json:"meta,omitempty"`
	Caps      string `json:"caps,omitempty"`
}

// Task is a persisted task record.
type Task struct {
	ID       string `json:"id"`
	SID      string `json:"sid"`
	Name     string `json:"name"`
	Args     string `json:"args"`
	State    string `json:"state"`
	Created  int64  `json:"created"`
	Finished int64  `json:"finished"`
	Result   string `json:"result"`
	Op       string `json:"op"`
	Err      string `json:"err"`
}

// Operator is an authenticated console user.
type Operator struct {
	User    string `json:"user"`
	Role    string `json:"role"`
	Tenant  string `json:"tenant"`
	KeyHash string `json:"key_hash"`
	Created int64  `json:"created"`
}

// AuditEntry is one tamper-evident log entry.
type AuditEntry struct {
	ID       string `json:"id"`
	TS       int64  `json:"ts"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Lock is a session conflict lock.
type Lock struct {
	SID     string `json:"sid"`
	Owner   string `json:"owner"`
	Expires int64  `json:"expires"`
}

// Manifest is a stored update manifest.
type Manifest struct {
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Sig      string `json:"sig"`
	Rollout  int    `json:"rollout"`
	Created  int64  `json:"created"`
}

// Store is the persistence interface.
type Store interface {
	Init(ctx context.Context) error
	Close() error
	UpsertOperator(ctx context.Context, o Operator) error
	GetOperator(ctx context.Context, user string) (*Operator, error)
	ListOperators(ctx context.Context, tenant string) ([]Operator, error)
	DeleteOperator(ctx context.Context, user string) error
	UpsertSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, sid string) (*Session, error)
	ListSessions(ctx context.Context, tenant string) ([]Session, error)
	CreateTask(ctx context.Context, t Task) error
	FinishTask(ctx context.Context, t Task) error
	ListTasks(ctx context.Context, sid string, limit int) ([]Task, error)
	Audit(ctx context.Context, actor, action, target, detail string) (*AuditEntry, error)
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
	AcquireLock(ctx context.Context, l Lock) error
	GetLock(ctx context.Context, sid string) (*Lock, error)
	ReleaseLock(ctx context.Context, sid string) error
	SaveManifest(ctx context.Context, m Manifest) error
	ListManifests(ctx context.Context) ([]Manifest, error)
}

// Open builds a store from a backend name and DSN.
func Open(backend, dsn string) (Store, error) {
	switch strings.ToLower(backend) {
	case "", "sqlite":
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1)
		s := &sqlStore{db: db, pg: false}
		if err := s.Init(context.Background()); err != nil {
			_ = db.Close()
			return nil, err
		}
		return s, nil
	case "postgres", "pgx", "postgresql":
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, err
		}
		s := &sqlStore{db: db, pg: true}
		if err := s.Init(context.Background()); err != nil {
			_ = db.Close()
			return nil, err
		}
		return s, nil
	case "memory", "mem":
		return NewMemory(), nil
	default:
		return nil, fmt.Errorf("unknown storage backend %q", backend)
	}
}

type sqlStore struct {
	db *sql.DB
	pg bool
}

func (s *sqlStore) q(query string) string {
	if !s.pg {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

const schema = `
CREATE TABLE IF NOT EXISTS operators (
  user TEXT PRIMARY KEY, role TEXT NOT NULL, tenant TEXT NOT NULL,
  key_hash TEXT NOT NULL, created BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY, client_id TEXT, host TEXT, os TEXT, arch TEXT, user TEXT,
  transport TEXT, tenant TEXT, first_seen BIGINT, last_seen BIGINT, state TEXT,
  meta TEXT, caps TEXT);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, sid TEXT, name TEXT, args TEXT, state TEXT, created BIGINT,
  finished BIGINT, result TEXT, op TEXT, err TEXT);
CREATE TABLE IF NOT EXISTS audit (
  id TEXT PRIMARY KEY, ts BIGINT, actor TEXT, action TEXT, target TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS locks (
  sid TEXT PRIMARY KEY, owner TEXT, expires BIGINT);
CREATE TABLE IF NOT EXISTS manifests (
  version TEXT, platform TEXT, arch TEXT, url TEXT, sha256 TEXT, sig TEXT,
  rollout INTEGER, created BIGINT, PRIMARY KEY(version, platform, arch));
`

func (s *sqlStore) Init(ctx context.Context) error {
	for _, stmt := range strings.Split(schema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("schema: %w", err)
		}
	}
	return nil
}

func (s *sqlStore) Close() error { return s.db.Close() }

func (s *sqlStore) UpsertOperator(ctx context.Context, o Operator) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO operators(user,role,tenant,key_hash,created)
		VALUES(?,?,?,?,?) ON CONFLICT(user) DO UPDATE SET role=excluded.role, tenant=excluded.tenant, key_hash=excluded.key_hash`),
		o.User, o.Role, o.Tenant, o.KeyHash, o.Created)
	return err
}

func (s *sqlStore) GetOperator(ctx context.Context, user string) (*Operator, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT user,role,tenant,key_hash,created FROM operators WHERE user=?`), user)
	var o Operator
	if err := row.Scan(&o.User, &o.Role, &o.Tenant, &o.KeyHash, &o.Created); err != nil {
		return nil, err
	}
	return &o, nil
}

func (s *sqlStore) ListOperators(ctx context.Context, tenant string) ([]Operator, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT user,role,tenant,key_hash,created FROM operators ORDER BY user`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Operator
	for rows.Next() {
		var o Operator
		if err := rows.Scan(&o.User, &o.Role, &o.Tenant, &o.KeyHash, &o.Created); err != nil {
			return nil, err
		}
		if tenant != "" && o.Tenant != tenant {
			continue
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *sqlStore) DeleteOperator(ctx context.Context, user string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM operators WHERE user=?`), user)
	return err
}

func (s *sqlStore) UpsertSession(ctx context.Context, sess Session) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO sessions
		(sid,client_id,host,os,arch,user,transport,tenant,first_seen,last_seen,state,meta,caps)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(sid) DO UPDATE SET client_id=excluded.client_id, host=excluded.host,
		os=excluded.os, arch=excluded.arch, user=excluded.user, transport=excluded.transport,
		tenant=excluded.tenant, last_seen=excluded.last_seen, state=excluded.state,
		meta=excluded.meta, caps=excluded.caps`),
		sess.SID, sess.ClientID, sess.Host, sess.OS, sess.Arch, sess.User, sess.Transport,
		sess.Tenant, sess.FirstSeen, sess.LastSeen, sess.State, sess.Meta, sess.Caps)
	return err
}

func (s *sqlStore) GetSession(ctx context.Context, sid string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT sid,client_id,host,os,arch,user,transport,tenant,
		first_seen,last_seen,state,COALESCE(meta,''),COALESCE(caps,'') FROM sessions WHERE sid=?`), sid)
	var x Session
	if err := row.Scan(&x.SID, &x.ClientID, &x.Host, &x.OS, &x.Arch, &x.User, &x.Transport,
		&x.Tenant, &x.FirstSeen, &x.LastSeen, &x.State, &x.Meta, &x.Caps); err != nil {
		return nil, err
	}
	return &x, nil
}

func (s *sqlStore) ListSessions(ctx context.Context, tenant string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT sid,client_id,host,os,arch,user,transport,tenant,
		first_seen,last_seen,state,COALESCE(meta,''),COALESCE(caps,'') FROM sessions ORDER BY last_seen DESC`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var x Session
		if err := rows.Scan(&x.SID, &x.ClientID, &x.Host, &x.OS, &x.Arch, &x.User, &x.Transport,
			&x.Tenant, &x.FirstSeen, &x.LastSeen, &x.State, &x.Meta, &x.Caps); err != nil {
			return nil, err
		}
		if tenant != "" && x.Tenant != tenant {
			continue
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *sqlStore) CreateTask(ctx context.Context, t Task) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO tasks(id,sid,name,args,state,created,finished,result,op,err)
		VALUES(?,?,?,?,?,?,?,?,?,?)`), t.ID, t.SID, t.Name, t.Args, t.State, t.Created, t.Finished, t.Result, t.Op, t.Err)
	return err
}

func (s *sqlStore) FinishTask(ctx context.Context, t Task) error {
	_, err := s.db.ExecContext(ctx, s.q(`UPDATE tasks SET state=?, finished=?, result=?, err=? WHERE id=?`),
		t.State, t.Finished, t.Result, t.Err, t.ID)
	return err
}

func (s *sqlStore) ListTasks(ctx context.Context, sid string, limit int) ([]Task, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id,sid,name,args,state,created,finished,COALESCE(result,''),COALESCE(op,''),COALESCE(err,'')
		FROM tasks WHERE sid=? ORDER BY created DESC LIMIT ?`), sid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.SID, &t.Name, &t.Args, &t.State, &t.Created, &t.Finished, &t.Result, &t.Op, &t.Err); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// HashEntry computes the audit hash.
func HashEntry(prev, ts, actor, action, target, detail string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	for _, s := range []string{ts, actor, action, target, detail} {
		h.Write([]byte{0})
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *sqlStore) Audit(ctx context.Context, actor, action, target, detail string) (*AuditEntry, error) {
	var prev string
	row := s.db.QueryRowContext(ctx, s.q(`SELECT COALESCE(hash,'') FROM audit ORDER BY rowid DESC LIMIT 1`))
	_ = row.Scan(&prev)
	e := AuditEntry{
		ID:       fmt.Sprintf("%d-%s", time.Now().UnixNano(), randHex(6)),
		TS:       time.Now().Unix(),
		Actor:    actor,
		Action:   action,
		Target:   target,
		Detail:   detail,
		PrevHash: prev,
	}
	e.Hash = HashEntry(prev, fmt.Sprint(e.TS), actor, action, target, detail)
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO audit(id,ts,actor,action,target,detail,prev_hash,hash)
		VALUES(?,?,?,?,?,?,?,?)`), e.ID, e.TS, e.Actor, e.Action, e.Target, e.Detail, e.PrevHash, e.Hash)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *sqlStore) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 200
	}
	// rowid preserves insertion order (the hash chain order); ts has only
	// second granularity and id is a string, so neither can be ordered on.
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id,ts,actor,action,target,detail,prev_hash,hash FROM
		(SELECT rowid AS r, * FROM audit ORDER BY rowid DESC LIMIT ?) ORDER BY r ASC`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *sqlStore) AcquireLock(ctx context.Context, l Lock) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO locks(sid,owner,expires) VALUES(?,?,?)
		ON CONFLICT(sid) DO UPDATE SET owner=excluded.owner, expires=excluded.expires`), l.SID, l.Owner, l.Expires)
	return err
}

func (s *sqlStore) GetLock(ctx context.Context, sid string) (*Lock, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT sid,owner,expires FROM locks WHERE sid=?`), sid)
	var l Lock
	if err := row.Scan(&l.SID, &l.Owner, &l.Expires); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *sqlStore) ReleaseLock(ctx context.Context, sid string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM locks WHERE sid=?`), sid)
	return err
}

func (s *sqlStore) SaveManifest(ctx context.Context, m Manifest) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO manifests(version,platform,arch,url,sha256,sig,rollout,created)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(version,platform,arch) DO UPDATE SET
		url=excluded.url, sha256=excluded.sha256, sig=excluded.sig, rollout=excluded.rollout`),
		m.Version, m.Platform, m.Arch, m.URL, m.SHA256, m.Sig, m.Rollout, m.Created)
	return err
}

func (s *sqlStore) ListManifests(ctx context.Context) ([]Manifest, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT version,platform,arch,url,sha256,sig,rollout,created FROM manifests ORDER BY created DESC`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		var m Manifest
		if err := rows.Scan(&m.Version, &m.Platform, &m.Arch, &m.URL, &m.SHA256, &m.Sig, &m.Rollout, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- memory backend ----------

type Memory struct {
	mu        sync.Mutex
	ops       map[string]Operator
	sessions  map[string]Session
	tasks     map[string]Task
	audits    []AuditEntry
	locks     map[string]Lock
	manifests []Manifest
}

func NewMemory() *Memory {
	return &Memory{ops: map[string]Operator{}, sessions: map[string]Session{}, tasks: map[string]Task{}, locks: map[string]Lock{}}
}

func (m *Memory) Init(context.Context) error { return nil }
func (m *Memory) Close() error               { return nil }

func (m *Memory) UpsertOperator(_ context.Context, o Operator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops[o.User] = o
	return nil
}

func (m *Memory) GetOperator(_ context.Context, user string) (*Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.ops[user]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return &o, nil
}

func (m *Memory) ListOperators(_ context.Context, tenant string) ([]Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Operator
	for _, o := range m.ops {
		if tenant == "" || o.Tenant == tenant {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out, nil
}

func (m *Memory) DeleteOperator(_ context.Context, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ops, user)
	return nil
}

func (m *Memory) UpsertSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.sessions[s.SID]; ok && old.FirstSeen > 0 {
		s.FirstSeen = old.FirstSeen
	}
	m.sessions[s.SID] = s
	return nil
}

func (m *Memory) GetSession(_ context.Context, sid string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return &s, nil
}

func (m *Memory) ListSessions(_ context.Context, tenant string) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Session
	for _, s := range m.sessions {
		if tenant == "" || s.Tenant == tenant {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out, nil
}

func (m *Memory) CreateTask(_ context.Context, t Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[t.ID] = t
	return nil
}

func (m *Memory) FinishTask(_ context.Context, t Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.tasks[t.ID]; ok {
		old.State, old.Finished, old.Result, old.Err = t.State, t.Finished, t.Result, t.Err
		m.tasks[t.ID] = old
	} else {
		m.tasks[t.ID] = t
	}
	return nil
}

func (m *Memory) ListTasks(_ context.Context, sid string, limit int) ([]Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Task
	for _, t := range m.tasks {
		if t.SID == sid {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) Audit(_ context.Context, actor, action, target, detail string) (*AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := ""
	if len(m.audits) > 0 {
		prev = m.audits[len(m.audits)-1].Hash
	}
	e := AuditEntry{ID: fmt.Sprintf("%d-%s", time.Now().UnixNano(), randHex(6)), TS: time.Now().Unix(),
		Actor: actor, Action: action, Target: target, Detail: detail, PrevHash: prev}
	e.Hash = HashEntry(prev, fmt.Sprint(e.TS), actor, action, target, detail)
	m.audits = append(m.audits, e)
	return &e, nil
}

func (m *Memory) ListAudit(_ context.Context, limit int) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]AuditEntry{}, m.audits...)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (m *Memory) AcquireLock(_ context.Context, l Lock) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.locks[l.SID] = l
	return nil
}

func (m *Memory) GetLock(_ context.Context, sid string) (*Lock, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.locks[sid]
	if !ok {
		return nil, sql.ErrNoRows
	}
	return &l, nil
}

func (m *Memory) ReleaseLock(_ context.Context, sid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.locks, sid)
	return nil
}

func (m *Memory) SaveManifest(_ context.Context, x Manifest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, old := range m.manifests {
		if old.Version == x.Version && old.Platform == x.Platform && old.Arch == x.Arch {
			m.manifests[i] = x
			return nil
		}
	}
	m.manifests = append(m.manifests, x)
	return nil
}

func (m *Memory) ListManifests(context.Context) ([]Manifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Manifest{}, m.manifests...), nil
}

func randHex(n int) string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	h := sha256.Sum256(append(b, byte(n), byte(time.Now().UnixNano())))
	return hex.EncodeToString(h[:n])
}

// VerifyAudit checks the hash chain.
func VerifyAudit(entries []AuditEntry) (bool, string) {
	prev := ""
	for i, e := range entries {
		if e.PrevHash != prev {
			return false, fmt.Sprintf("entry %d prev_hash mismatch", i)
		}
		want := HashEntry(e.PrevHash, fmt.Sprint(e.TS), e.Actor, e.Action, e.Target, e.Detail)
		if e.Hash != want {
			return false, fmt.Sprintf("entry %d hash mismatch", i)
		}
		prev = e.Hash
	}
	return true, "ok"
}

// MarshalJSON is a helper for operator payloads.
func MarshalJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

