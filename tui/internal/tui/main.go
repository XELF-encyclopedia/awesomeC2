package tui

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"backd/c2/mvp/tui/internal/client"
	"backd/c2/mvp/tui/internal/config"
)

type mainPage struct {
	a    *App
	root *tview.Grid

	header   *tview.TextView
	search   *tview.InputField
	table    *tview.Table
	detail   *tview.TextView
	output   *tview.TextView
	progress *tview.TextView
	command  *tview.InputField
	status   *tview.TextView

	cfg      *config.Config
	stmt     *client.Client
	sessions []client.Session
	visible  []client.Session
	selected uint64
	stats    map[string]any
	filter   string
	building bool

	connState   client.State
	connDetail  string
	lastRefresh time.Time
	refreshErr  string

	tunnelDir  string
	tunnelMu   sync.Mutex
	tunnelSeq  map[uint32]int
	pMu        sync.Mutex
	lastUpdate time.Time

	history []string
	histIdx int
}

func newMainPage(a *App) *mainPage {
	m := &mainPage{
		a:         a,
		stats:     map[string]any{},
		tunnelSeq: map[uint32]int{},
	}

	m.header = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	m.search = tview.NewInputField().SetLabel("Filter: ").SetPlaceholder("host / os / addr (/)")
	m.search.SetChangedFunc(func(text string) {
		m.filter = strings.TrimSpace(strings.ToLower(text))
		m.rebuildTable()
	})
	m.search.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			a.app.SetFocus(m.table)
		}
	})
	m.search.SetBorder(true).SetTitle(" Search ")

	m.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	m.table.SetBorder(true).SetTitle(" Sessions ")
	m.table.SetSelectionChangedFunc(func(row, _ int) {
		if m.building || row < 1 || row-1 >= len(m.visible) {
			return
		}
		m.selected = m.visible[row-1].ID
		m.updateDetail()
	})

	m.detail = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	m.detail.SetBorder(true).SetTitle(" Session detail ")

	m.output = tview.NewTextView().SetDynamicColors(false).SetScrollable(true).SetWrap(true)
	m.output.SetBorder(true).SetTitle(" Output / task result ")
	m.output.SetMaxLines(4000)

	m.progress = tview.NewTextView().SetDynamicColors(false).SetWrap(false).SetText("transfer: idle")

	m.command = tview.NewInputField().SetLabel("> ").
		SetPlaceholder("help · list · shell whoami · download <remote> [local] · F1 for commands")
	m.command.SetFieldWidth(0)
	m.command.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			m.runCommand()
		}
	})
	m.command.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyUp:
			m.histMove(-1)
			return nil
		case tcell.KeyDown:
			m.histMove(1)
			return nil
		}
		return ev
	})

	m.status = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	m.status.SetText("[gray]ready[-]")

	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(m.search, 3, 0, false).
		AddItem(m.table, 0, 1, true)

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(m.detail, 8, 0, false).
		AddItem(m.output, 0, 1, false)

	body := tview.NewFlex().
		AddItem(left, 0, 2, true).
		AddItem(right, 0, 3, false)

	prog := tview.NewFlex().
		AddItem(m.progress, 0, 1, false)

	m.root = tview.NewGrid().
		SetRows(2, 0, 1, 1, 1).
		SetColumns(0).
		AddItem(m.header, 0, 0, 1, 1, 0, 0, false).
		AddItem(body, 1, 0, 1, 1, 0, 0, true).
		AddItem(prog, 2, 0, 1, 1, 0, 0, false).
		AddItem(m.command, 3, 0, 1, 1, 0, 0, false).
		AddItem(m.status, 4, 0, 1, 1, 0, 0, false)
	return m
}

func (m *mainPage) configure(cfg *config.Config, cli *client.Client) {
	m.cfg = cfg
	m.stmt = cli
	m.tunnelDir = cfg.TunnelOut
	m.sessions = nil
	m.visible = nil
	m.selected = 0
	m.connState = client.StateConnecting
	m.connDetail = cfg.Endpoint
	m.header.SetText(fmt.Sprintf("[b]%s[-]  [gray]user=%s psk=%s family=%s[-]",
		tview.Escape(cfg.Endpoint), tview.Escape(cfg.User), cfg.MaskedPSK(), cfg.Family))
}

func (m *mainPage) selectedID() uint64 {
	if m.selected != 0 {
		return m.selected
	}
	if len(m.visible) > 0 {
		return m.visible[0].ID
	}
	return 0
}

func (m *mainPage) setConnState(s client.State, detail string) {
	m.connState = s
	m.connDetail = detail
	m.renderHeader()
	if s == client.StateConnected {
		m.setStatus("connected to " + detail)
	} else if s == client.StateDisconnected {
		m.setStatus("disconnected: " + detail + " (auto-reconnect)")
	}
}

func (m *mainPage) setSessions(sessions []client.Session, stats map[string]any) {
	m.sessions = sessions
	if stats != nil {
		m.stats = stats
	}
	m.rebuildTable()
	if m.selected == 0 && len(m.visible) > 0 {
		m.selected = m.visible[0].ID
	}
	m.lastRefresh = time.Now()
	m.renderHeader()
	m.updateDetail()
}

func (m *mainPage) setRefreshError(err error) {
	m.refreshErr = ""
	if err != nil {
		m.refreshErr = err.Error()
		m.setStatus("refresh failed: " + err.Error())
	}
	m.renderHeader()
}

func (m *mainPage) renderHeader() {
	stateColor := "yellow"
	switch m.connState {
	case client.StateConnected:
		stateColor = "green"
	case client.StateDisconnected:
		stateColor = "red"
	}
	ref := "never"
	if !m.lastRefresh.IsZero() {
		ref = HumanAge(time.Since(m.lastRefresh)) + " ago"
	}
	line1 := fmt.Sprintf("[b]BDC2 v1 operator[-]  [gray]%s[-]  [%s]%s[-]  [gray]%s[-]",
		tview.Escape(m.connDetail), stateColor, m.connState.String(), ref)
	line2 := fmt.Sprintf("[gray]sessions=%d  selected=%d  user=%s[-]",
		len(m.sessions), m.selected, tview.Escape(m.cfg.User))
	if m.refreshErr != "" {
		line2 += "  [red]refresh: " + tview.Escape(m.refreshErr) + "[-]"
	}
	m.header.SetText(line1 + "\n" + line2)
}

func (m *mainPage) rebuildTable() {
	m.building = true
	defer func() { m.building = false }()
	m.visible = m.visible[:0]
	for _, s := range m.sessions {
		if m.filter != "" {
			hay := strings.ToLower(s.Name() + " " + s.OS + " " + s.Arch + " " + s.Addr + " " + s.ClientID)
			if !strings.Contains(hay, m.filter) {
				continue
			}
		}
		m.visible = append(m.visible, s)
	}
	m.table.Clear()
	headers := []string{"HOST", "OS", "STATE", "LAST SEEN"}
	for c, h := range headers {
		cell := tview.NewTableCell(h).SetTextColor(tcell.ColorYellow).SetSelectable(false).SetAttributes(tcell.AttrBold)
		m.table.SetCell(0, c, cell)
	}
	now := time.Now()
	refresh := time.Duration(4) * time.Second
	if m.cfg != nil && m.cfg.RefreshS > 0 {
		refresh = time.Duration(m.cfg.RefreshS) * time.Second
	}
	selRow := -1
	for i, s := range m.visible {
		state := SessionState(s, now, refresh)
		color := tcell.ColorGreen
		if state != "online" {
			color = tcell.ColorYellow
		}
		if state == "unknown" {
			color = tcell.ColorGray
		}
		osName := s.OS
		if s.Arch != "" {
			osName += "/" + s.Arch
		}
		m.table.SetCell(i+1, 0, tview.NewTableCell(s.Name()).SetTextColor(tcell.ColorWhite))
		m.table.SetCell(i+1, 1, tview.NewTableCell(osName).SetTextColor(tcell.ColorLightGray))
		m.table.SetCell(i+1, 2, tview.NewTableCell(state).SetTextColor(color))
		m.table.SetCell(i+1, 3, tview.NewTableCell(LastSeenAge(s.LastSeen, now)).SetTextColor(tcell.ColorGray))
		if s.ID == m.selected {
			selRow = i + 1
		}
	}
	if len(m.visible) > 0 {
		if selRow < 1 {
			selRow = 1
		}
		m.table.Select(selRow, 0)
		if selRow-1 < len(m.visible) {
			m.selected = m.visible[selRow-1].ID
		}
	} else {
		m.selected = 0
	}
	m.updateDetail()
}

func (m *mainPage) findSession(id uint64) (client.Session, bool) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, true
		}
	}
	return client.Session{}, false
}

func (m *mainPage) updateDetail() {
	s, ok := m.findSession(m.selected)
	if !ok {
		m.detail.SetText("[gray]no session selected[-]")
		return
	}
	now := time.Now()
	m.detail.SetText(fmt.Sprintf(
		"[b]%s[-]\n"+
			"[gray]session:[-] %d\n"+
			"[gray]os/arch:[-] %s/%s\n"+
			"[gray]version:[-] %s\n"+
			"[gray]addr:[-] %s\n"+
			"[gray]last seen:[-] %s (%s)\n"+
			"[gray]stats:[-] %s",
		tview.Escape(s.Name()), s.ID, s.OS, s.Arch, s.Ver, tview.Escape(s.Addr),
		tview.Escape(s.LastSeen), LastSeenAge(s.LastSeen, now), tview.Escape(StatsLine(m.stats))))
}

func (m *mainPage) setStatus(text string) {
	clean := tview.Escape(text)
	m.a.post(func() {
		m.status.SetText("[gray]" + clean + "[-]")
	})
}

func (m *mainPage) Printf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	ts := time.Now().Format("15:04:05")
	m.a.post(func() {
		fmt.Fprintf(m.output, "%s  %s\n", ts, line)
		m.output.ScrollToEnd()
	})
}

func (m *mainPage) Status(text string) { m.setStatus(text) }

func (m *mainPage) Progress(done, total int64, label string) {
	now := time.Now()
	m.pMu.Lock()
	skip := now.Sub(m.lastUpdate) < 120*time.Millisecond && done < total
	if !skip {
		m.lastUpdate = now
	}
	m.pMu.Unlock()
	if skip {
		return
	}
	pct := 0
	if total > 0 {
		pct = int(done * 100 / total)
		if pct > 100 {
			pct = 100
		}
	}
	const width = 28
	filled := pct * width / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	line := ""
	if total > 0 {
		line = fmt.Sprintf("%s [%s] %s / %s (%d%%)", label, bar, HumanBytes(done), HumanBytes(total), pct)
	} else {
		line = fmt.Sprintf("%s [%s] %s", label, bar, HumanBytes(done))
	}
	m.a.post(func() {
		m.progress.SetText(line)
	})
}

func (m *mainPage) Clear() {
	m.a.post(func() { m.output.Clear() })
}

func (m *mainPage) Tunnel(n client.Notice) {
	line := fmt.Sprintf("[tunnel] ftype=0x%02x id=%d len=%d", n.FType, n.TID, len(n.Data))
	if n.TID != 0 {
		if len(n.Data) > 0 {
			line += " data=" + fmt.Sprintf("%q", truncatePrintable(n.Data, 96))
		}
	}
	if m.tunnelDir != "" {
		if p := m.writeTunnel(n); p != "" {
			line += " -> " + p
		}
	}
	m.a.post(func() {
		fmt.Fprintf(m.output, "%s  %s\n", time.Now().Format("15:04:05"), line)
		m.output.ScrollToEnd()
	})
}

func (m *mainPage) writeTunnel(n client.Notice) string {
	m.tunnelMu.Lock()
	defer m.tunnelMu.Unlock()
	m.tunnelSeq[n.TID]++
	name := fmt.Sprintf("tunnel-%d-%03d-%d.bin", n.TID, m.tunnelSeq[n.TID], time.Now().UnixNano())
	if err := os.MkdirAll(m.tunnelDir, 0o700); err != nil {
		return ""
	}
	p := filepath.Join(m.tunnelDir, name)
	if err := os.WriteFile(p, n.Data, 0o600); err != nil {
		return ""
	}
	return p
}

func truncatePrintable(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r >= 32 && r < 127 {
			out = append(out, r)
		} else {
			out = append(out, '.')
		}
	}
	return string(out) + " hex:" + hex.EncodeToString(b[:min(8, len(b))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *mainPage) runCommand() {
	line := strings.TrimSpace(m.command.GetText())
	if line == "" {
		return
	}
	switch strings.ToLower(line) {
	case "quit", "exit":
		m.a.quit()
		return
	case "help", "?":
		m.a.showHelp()
		return
	}
	m.history = append(m.history, line)
	m.histIdx = len(m.history)
	m.command.SetText("")

	if m.a.disp == nil {
		m.setStatus("not connected")
		return
	}
	if m.a.disp.Busy() {
		m.setStatus("busy — wait or press Esc to cancel")
		return
	}
	m.setStatus("running: " + line)
	go func() { _ = m.a.disp.Exec(m.a.ctx, line) }()
}

func (m *mainPage) histMove(delta int) {
	if len(m.history) == 0 {
		return
	}
	m.histIdx += delta
	if m.histIdx < 0 {
		m.histIdx = 0
	}
	if m.histIdx > len(m.history) {
		m.histIdx = len(m.history)
	}
	if m.histIdx == len(m.history) {
		m.command.SetText("")
		return
	}
	m.command.SetText(m.history[m.histIdx])
}

func (m *mainPage) activate() {
	focus := m.a.app.GetFocus()
	if focus == m.search {
		m.a.app.SetFocus(m.table)
		return
	}
	if focus == m.table {
		m.a.app.SetFocus(m.command)
	}
}

func (m *mainPage) clearFilter() {
	m.search.SetText("")
	m.filter = ""
	m.rebuildTable()
}
