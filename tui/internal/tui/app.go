package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"backd/c2/mvp/tui/internal/client"
	"backd/c2/mvp/tui/internal/config"
	"backd/c2/mvp/tui/internal/ops"
)

// App is the tview operator console.
type App struct {
	app   *tview.Application
	pages *tview.Pages

	cfg     *config.Config
	cfgPath string
	auto    bool

	ctx    context.Context
	cancel context.CancelFunc

	cli  *client.Client
	disp *ops.Dispatcher

	login *loginPage
	main  *mainPage

	modalOpen bool
	helpOpen  bool
	quitting  atomic.Bool

	refreshMu  sync.Mutex
	refreshing bool

	reconnecting atomic.Bool
	tickerOnce   sync.Once

	// posts is drained by a helper goroutine that marshals updates onto the
	// tview event loop. It is asynchronous so that functions called *from*
	// the event loop (key handlers, form buttons) can never deadlock on
	// QueueUpdateDraw.
	posts chan func()
}

// New builds the UI graph. cfg may be incomplete: the login page is then shown.
func New(cfg *config.Config, cfgPath string, autoConnect bool) *App {
	a := &App{
		app:     tview.NewApplication(),
		pages:   tview.NewPages(),
		cfg:     cfg,
		cfgPath: cfgPath,
		auto:    autoConnect,
		posts:   make(chan func(), 2048),
	}
	a.login = newLoginPage(a)
	a.main = newMainPage(a)

	a.pages.AddPage("login", a.login.root, true, true)
	a.pages.AddPage("main", a.main.root, true, false)
	a.app.SetRoot(a.pages, true)
	a.app.SetInputCapture(a.capture)
	if cfg.Complete() {
		a.app.SetFocus(a.login.connectButton())
	} else {
		a.app.SetFocus(a.login.endpoint)
	}
	return a
}

// Run blocks until the operator quits.
func (a *App) Run() error {
	go a.uiLoop()
	if a.auto && a.cfg.Complete() {
		go a.connect(a.cfg.Clone())
	}
	return a.app.Run()
}

// post schedules f on the tview event loop without ever blocking the caller.
func (a *App) post(f func()) {
	select {
	case a.posts <- f:
	default:
		// The queue is saturated (a very chatty transfer): never block the
		// caller — run the update from a helper goroutine instead.
		go func() {
			select {
			case a.posts <- f:
			case <-time.After(5 * time.Second):
			}
		}()
	}
}

func (a *App) uiLoop() {
	for f := range a.posts {
		a.app.QueueUpdateDraw(f)
	}
}

// quit stops background work and leaves the alternate screen.
func (a *App) quit() {
	if a.quitting.Swap(true) {
		return
	}
	if a.cancel != nil {
		a.cancel()
	}
	if a.cli != nil {
		a.cli.Close()
	}
	a.app.Stop()
}

func (a *App) connect(cfg *config.Config) {
	if err := cfg.Validate(); err != nil {
		a.post(func() { a.login.setError(err.Error(), true) })
		return
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.cfg = cfg

	opts := client.Options{
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
		OnNotice: a.onNotice,
		OnState:  a.onState,
	}
	a.cli = client.New(opts)
	a.disp = ops.New(a.cli, a, cfg.Download, func() uint64 { return a.main.selectedID() })
	a.disp.ActionLog = cfg.ActionLog
	// configure() touches tview widgets (the header) and the table model, so it
	// must run on the tview event loop rather than this worker goroutine.
	a.post(func() { a.main.configure(cfg, a.cli) })

	a.post(func() {
		a.login.setError("connecting to "+cfg.Endpoint+" ...", false)
	})

	go func() {
		err := a.cli.Connect(a.ctx)
		if err != nil {
			a.post(func() {
				a.login.setError("connect failed: "+err.Error(), true)
			})
			return
		}
		if err := cfg.Save(a.cfgPath); err != nil {
			a.main.Printf("config not saved: %v", err)
		}
		a.post(func() {
			a.pages.SwitchToPage("main")
			a.login.setError("", false)
			a.main.setConnState(client.StateConnected, cfg.Endpoint)
			a.app.SetFocus(a.main.command)
		})
		a.startTicker()
		a.refreshNow()
	}()
}

func (a *App) startTicker() {
	a.tickerOnce.Do(func() {
		refresh := time.Duration(a.cfg.RefreshS) * time.Second
		if refresh < 2*time.Second {
			refresh = 2 * time.Second
		}
		go func() {
			t := time.NewTicker(refresh)
			defer t.Stop()
			for {
				select {
				case <-a.ctx.Done():
					return
				case <-t.C:
					if a.cli == nil || a.disp == nil || a.disp.Busy() {
						continue
					}
					a.refreshNow()
				}
			}
		}()
	})
}

func (a *App) refreshNow() {
	if a.cli == nil || a.ctx == nil || a.ctx.Err() != nil {
		return
	}
	if a.disp != nil && a.disp.Busy() {
		return
	}
	a.refreshMu.Lock()
	if a.refreshing {
		a.refreshMu.Unlock()
		return
	}
	a.refreshing = true
	a.refreshMu.Unlock()

	go func() {
		defer func() {
			a.refreshMu.Lock()
			a.refreshing = false
			a.refreshMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
		defer cancel()
		sessions, stats, err := a.cli.List(ctx)
		if err != nil {
			a.post(func() { a.main.setRefreshError(err) })
			return
		}
		a.post(func() {
			a.main.setSessions(sessions, stats)
			a.main.setRefreshError(nil)
		})
	}()
}

func (a *App) onNotice(n client.Notice) {
	a.main.Tunnel(n)
}

func (a *App) onState(s client.State, detail string) {
	if a.app == nil {
		return
	}
	a.post(func() { a.main.setConnState(s, detail) })
	if s == client.StateDisconnected && !a.quitting.Load() && a.ctx != nil && a.ctx.Err() == nil {
		go a.reconnectLoop()
	}
}

func (a *App) reconnectLoop() {
	if !a.reconnecting.CompareAndSwap(false, true) {
		return
	}
	defer a.reconnecting.Store(false)
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		if a.ctx == nil || a.ctx.Err() != nil || a.quitting.Load() {
			return
		}
		a.post(func() {
			a.main.setConnState(client.StateReconnecting, fmt.Sprintf("attempt %d", attempt))
		})
		err := a.cli.Connect(a.ctx)
		if err == nil {
			a.refreshNow()
			return
		}
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

func (a *App) showHelp() {
	if a.helpOpen {
		return
	}
	a.helpOpen = true
	text := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(false).
		SetText("[b]BDC2 v1 operator TUI — keys[-]\n\n" +
			"  F1 or ?    this help\n" +
			"  Tab        next panel (sessions → output → command → search)\n" +
			"  /          focus the session filter\n" +
			"  Enter      run the command / activate the focused list\n" +
			"  Esc        cancel the running operation / clear the filter / close\n" +
			"  q          quit (while not typing)\n" +
			"  Ctrl+C     quit immediately\n" +
			"  PgUp/PgDn  scroll the focused output\n\n" + ops.HelpText)
	text.SetBorder(true).SetTitle(" Help (F1 / Esc closes) ")
	wrap := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(text, 0, 1, true)
	a.pages.AddPage("help", wrap, true, true)
	a.app.SetFocus(text)
}

func (a *App) closeHelp() {
	if !a.helpOpen {
		return
	}
	a.helpOpen = false
	a.pages.RemovePage("help")
	a.app.SetFocus(a.main.command)
}

// Confirm implements ops.Emitter. It must never be called on the UI goroutine
// (ops.Exec runs in its own goroutine).
func (a *App) Confirm(title, prompt string) bool {
	ch := make(chan bool, 1)
	a.post(func() {
		modal := tview.NewModal().
			SetText("[red]" + title + "[-]\n\n" + prompt).
			AddButtons([]string{"Cancel", "Confirm"}).
			SetDoneFunc(func(idx int, _ string) {
				a.modalOpen = false
				a.pages.RemovePage("confirm")
				a.app.SetFocus(a.main.command)
				ch <- idx == 1
			})
		a.modalOpen = true
		a.pages.AddPage("confirm", modal, true, true)
		a.app.SetFocus(modal)
	})
	return <-ch
}

func (a *App) capture(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyCtrlC {
		a.quit()
		return nil
	}
	if ev.Key() == tcell.KeyF1 {
		if a.helpOpen {
			a.closeHelp()
		} else {
			a.showHelp()
		}
		return nil
	}
	if a.helpOpen {
		if ev.Key() == tcell.KeyEsc || ev.Rune() == '?' || ev.Rune() == 'q' {
			a.closeHelp()
			return nil
		}
		return ev
	}
	if a.modalOpen {
		return ev
	}
	if front, _ := a.pages.GetFrontPage(); front != "main" {
		return ev
	}
	focus := a.app.GetFocus()
	switch {
	case focus == a.main.command || focus == a.main.search:
		if ev.Key() == tcell.KeyEsc {
			if focus == a.main.command && a.disp != nil && a.disp.Busy() {
				a.disp.Cancel()
				a.main.setStatus("cancel requested")
			} else if focus == a.main.search {
				a.main.clearFilter()
				a.app.SetFocus(a.main.table)
			}
			return nil
		}
		return ev
	}
	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyBacktab:
		a.cycleFocus(ev.Key() == tcell.KeyBacktab)
		return nil
	case tcell.KeyEnter:
		a.main.activate()
		return nil
	case tcell.KeyEsc:
		a.app.SetFocus(a.main.command)
		return nil
	}
	switch ev.Rune() {
	case '?':
		a.showHelp()
		return nil
	case 'q', 'Q':
		a.quit()
		return nil
	case '/':
		a.app.SetFocus(a.main.search)
		return nil
	}
	return ev
}

func (a *App) cycleFocus(back bool) {
	order := []tview.Primitive{a.main.table, a.main.output, a.main.command, a.main.search}
	cur := a.app.GetFocus()
	idx := -1
	for i, p := range order {
		if p == cur {
			idx = i
			break
		}
	}
	if idx < 0 {
		a.app.SetFocus(a.main.table)
		return
	}
	if back {
		idx = (idx + len(order) - 1) % len(order)
	} else {
		idx = (idx + 1) % len(order)
	}
	a.app.SetFocus(order[idx])
}

// Emitter forwarding (called from ops goroutines).

func (a *App) Printf(format string, args ...any) { a.main.Printf(format, args...) }
func (a *App) Status(text string)                { a.main.Status(text) }
func (a *App) Progress(done, total int64, label string) {
	a.main.Progress(done, total, label)
}
func (a *App) Clear() { a.main.Clear() }
func (a *App) SetSessions(s []client.Session, st map[string]any) {
	// Called from ops goroutines (list/stats/reload); tview is not
	// goroutine-safe, so marshal onto the event loop like every other emitter.
	a.post(func() { a.main.setSessions(s, st) })
}
func (a *App) Tunnel(n client.Notice) { a.main.Tunnel(n) }

// ensure interfaces
var _ ops.Emitter = (*App)(nil)

func trimLine(s string) string { return strings.TrimSpace(s) }
