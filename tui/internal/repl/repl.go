// Package repl is the no-TTY fallback: the same operator commands, one line
// at a time, with no terminal UI.
package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"backd/c2/mvp/tui/internal/client"
	"backd/c2/mvp/tui/internal/config"
	"backd/c2/mvp/tui/internal/ops"
)

// Emitter implements ops.Emitter for a plain terminal/pipe.
type Emitter struct {
	out io.Writer
	in  *bufio.Reader

	mu         sync.Mutex
	sel        uint64
	lastPct    int
	lastPrint  time.Time
	progressOn bool
}

// NewEmitter returns a line-mode emitter over in/out.
func NewEmitter(in io.Reader, out io.Writer) *Emitter {
	return &Emitter{in: bufio.NewReader(in), out: out}
}

// Selected returns the current session (first listed unless "use" pins one).
func (e *Emitter) Selected() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sel
}

func (e *Emitter) Printf(format string, args ...any) {
	e.finishProgress()
	fmt.Fprintf(e.out, format+"\n", args...)
}

func (e *Emitter) Status(text string) {
	fmt.Fprintf(e.out, "-- %s\n", text)
}

func (e *Emitter) Progress(done, total int64, label string) {
	pct := 0
	if total > 0 {
		pct = int(done * 100 / total)
	}
	if done != total && pct < e.lastPct+10 && time.Since(e.lastPrint) < 300*time.Millisecond {
		return
	}
	e.lastPct = pct
	e.lastPrint = time.Now()
	e.progressOn = true
	if total > 0 {
		fmt.Fprintf(e.out, "\r  %s %s / %s (%d%%)", label, human(done), human(total), pct)
	} else {
		fmt.Fprintf(e.out, "\r  %s %s", label, human(done))
	}
	if done >= total {
		fmt.Fprintln(e.out)
		e.progressOn = false
		e.lastPct = -100
	}
}

func (e *Emitter) finishProgress() {
	if e.progressOn {
		fmt.Fprintln(e.out)
		e.progressOn = false
		e.lastPct = -100
	}
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (e *Emitter) Clear() {
	fmt.Fprint(e.out, "\x1b[2J\x1b[H")
}

func (e *Emitter) Confirm(title, prompt string) bool {
	e.finishProgress()
	fmt.Fprintf(e.out, "%s\n%s\nType 'yes' to confirm: ", title, prompt)
	line, _ := e.in.ReadString('\n')
	line = strings.ToLower(cleanLine(line))
	return line == "yes" || line == "y"
}

// cleanLine trims surrounding whitespace and removes a UTF-8 BOM. Windows
// shells — notably `powershell -Command "…" | c2tui.exe` and cmd's UTF-8
// pipeline — may prepend U+FEFF to the first line, which is not whitespace and
// would otherwise turn "list" into an unknown command.
func cleanLine(s string) string {
	return strings.TrimSpace(strings.TrimPrefix(s, "\ufeff"))
}

func (e *Emitter) SetSessions(sessions []client.Session, stats map[string]any) {
	e.mu.Lock()
	if e.sel == 0 && len(sessions) > 0 {
		e.sel = sessions[0].ID
	}
	e.mu.Unlock()
	fmt.Fprintf(e.out, "%-6s %-28s %-18s %-7s %s\n", "ID", "HOST", "OS/ARCH", "STATE", "LAST SEEN")
	for _, s := range sessions {
		st := "online"
		ref := 4 * time.Second
		if t, ok := parseSeen(s.LastSeen); !ok || time.Since(t) > 2*ref {
			st = "stale"
		}
		fmt.Fprintf(e.out, "%-6d %-28s %-18s %-7s %s\n",
			s.ID, s.Name(), s.OS+"/"+s.Arch, st, s.LastSeen)
	}
	if len(stats) > 0 {
		fmt.Fprintf(e.out, "stats: %v\n", stats)
	}
}

func (e *Emitter) Tunnel(n client.Notice) {
	e.finishProgress()
	fmt.Fprintf(e.out, "[tunnel] ftype=0x%02x id=%d len=%d data=%q\n",
		n.FType, n.TID, len(n.Data), string(n.Data))
}

func parseSeen(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Run connects and reads commands until EOF/quit.
func Run(ctx context.Context, cfg *config.Config, cfgPath string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	em := NewEmitter(os.Stdin, os.Stdout)
	cli := client.New(client.Options{
		Endpoint: cfg.Endpoint,
		User:     cfg.User,
		PSK:      cfg.PSK,
		SNI:      cfg.SNI,
		DialIP:   cfg.DialIP,
		Family:   cfg.Family,
		TLSCA:    cfg.TLSCA,
		TLSPin:   cfg.TLSPin,
		Insecure: cfg.Insecure,
		Timeout:  time.Duration(cfg.TimeoutS) * time.Second,
		OnNotice: em.Tunnel,
		OnState: func(s client.State, detail string) {
			if s == client.StateDisconnected {
				fmt.Fprintf(os.Stderr, "!! disconnected: %s\n", detail)
			}
		},
	})
	disp := ops.New(cli, em, cfg.Download, em.Selected)
	disp.ActionLog = cfg.ActionLog

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := cli.Connect(cctx)
	cancel()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer cli.Close()
	_ = cfg.Save(cfgPath)
	fmt.Printf("connected: %s user=%s psk=%s\n(type 'help' for commands, 'quit' to exit)\n",
		cfg.Endpoint, cfg.User, cfg.MaskedPSK())

	for {
		fmt.Print("c2tui> ")
		line, err := em.in.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = cleanLine(line)
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "quit", "exit":
			return nil
		case "help", "?":
			fmt.Println(ops.HelpText)
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_ = disp.Exec(ctx, line)
	}
}
