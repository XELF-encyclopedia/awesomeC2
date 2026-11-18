package main

// Session registry: connected clients, their metadata, and task/result routing.

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Result struct {
	TaskID string
	Kind   string
	OK     bool
	Data   string
	Err    string
	At     time.Time
}

type Session struct {
	ID         string
	ClientID   string
	Hostname   string
	OS         string
	Arch       string
	User       string
	Suite      string
	Version    string
	PID        int64
	RemoteAddr string
	Connected  time.Time

	sendCh  chan msg
	mu      sync.Mutex
	last    time.Time
	results map[string]*Result
	waiters map[string]chan *Result
}

func newSession(clientID string) *Session {
	return &Session{
		ID:       newID("s"),
		ClientID: clientID,
		sendCh:   make(chan msg, 32),
		last:     time.Now(),
		results:  make(map[string]*Result),
		waiters:  make(map[string]chan *Result),
	}
}

func (s *Session) touch() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
}

func (s *Session) lastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// deliver routes a result frame to either a waiting operator or the result map.
func (s *Session) deliver(r *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = time.Now()
	s.results[r.TaskID] = r
	// Bound memory: keep the most recent 256 results per session.
	if len(s.results) > 256 {
		var oldest string
		var oldestAt time.Time
		for k, v := range s.results {
			if oldest == "" || v.At.Before(oldestAt) {
				oldest, oldestAt = k, v.At
			}
		}
		delete(s.results, oldest)
	}
	if ch, ok := s.waiters[r.TaskID]; ok {
		select {
		case ch <- r:
		default:
		}
		delete(s.waiters, r.TaskID)
	}
}

// await returns a stored result for taskID immediately, otherwise blocks up to
// timeout for the client to report it.
func (s *Session) await(taskID string, timeout time.Duration) (*Result, bool) {
	s.mu.Lock()
	if r, ok := s.results[taskID]; ok {
		s.mu.Unlock()
		return r, true
	}
	ch := make(chan *Result, 1)
	s.waiters[taskID] = ch
	s.mu.Unlock()
	select {
	case r := <-ch:
		return r, true
	case <-time.After(timeout):
		s.mu.Lock()
		delete(s.waiters, taskID)
		s.mu.Unlock()
		return nil, false
	}
}

func (s *Session) snapshot() msg {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	return msg{
		"session_id":  s.ID,
		"client_id":   s.ClientID,
		"hostname":    s.Hostname,
		"os":          s.OS,
		"arch":        s.Arch,
		"user":        s.User,
		"suite":       s.Suite,
		"version":     s.Version,
		"pid":         s.PID,
		"remote_addr": s.RemoteAddr,
		"connected":   s.Connected.UTC().Format(time.RFC3339),
		"last_seen":   last.UTC().Format(time.RFC3339),
	}
}

type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	byClient map[string]*Session
}

func newRegistry() *Registry {
	return &Registry{
		sessions: make(map[string]*Session),
		byClient: make(map[string]*Session),
	}
}

func (r *Registry) add(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID] = s
	r.byClient[s.ClientID] = s
}

func (r *Registry) remove(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.sessions[s.ID]; ok && cur == s {
		delete(r.sessions, s.ID)
	}
	if cur, ok := r.byClient[s.ClientID]; ok && cur == s {
		delete(r.byClient, s.ClientID)
	}
}

func (r *Registry) get(id string) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[id]
}

func (r *Registry) byClientID(clientID string) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byClient[clientID]
}

func (r *Registry) list() []msg {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]msg, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s.snapshot())
	}
	return out
}

func (r *Registry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func newID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal for session ids; fall back to time.
		return prefix + "-" + hex.EncodeToString([]byte(time.Now().Format("150405.000000")))
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}
