package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"backd/c2/mvp/tui/internal/config"
)

type loginPage struct {
	a    *App
	root *tview.Flex

	endpoint *tview.InputField
	user     *tview.InputField
	psk      *tview.InputField
	sni      *tview.InputField
	dialIP   *tview.InputField
	family   *tview.InputField
	tlsca    *tview.InputField
	tlspin   *tview.InputField
	insecure *tview.Checkbox

	msg  *tview.TextView
	hint *tview.TextView
	conn *tview.Button
}

func newLoginPage(a *App) *loginPage {
	l := &loginPage{a: a}
	cfg := a.cfg

	title := tview.NewTextView().SetDynamicColors(true)
	title.SetText("[b]BDC2 v1 — operator console[-]\n" +
		"[gray]Native TLS/WSS · frozen protocol · configuration-driven (no address built in)[-]")

	left := tview.NewForm()
	left.SetBorder(true).SetTitle(" Login ")
	left.SetButtonsAlign(tview.AlignLeft)
	left.SetFieldBackgroundColor(tcell.ColorBlack)
	left.AddInputField("Endpoint", cfg.Endpoint, 46, nil, nil)
	l.endpoint = left.GetFormItemByLabel("Endpoint").(*tview.InputField)
	l.endpoint.SetPlaceholder("wss://<operator-host>/ws")
	left.AddInputField("User", cfg.User, 28, nil, nil)
	l.user = left.GetFormItemByLabel("User").(*tview.InputField)
	left.AddPasswordField("PSK", cfg.PSK, 46, '*', nil)
	l.psk = left.GetFormItemByLabel("PSK").(*tview.InputField)
	l.psk.SetPlaceholder("base64:… or hex:…")
	left.AddButton("Connect", func() {
		cfg := l.read()
		if err := cfg.Validate(); err != nil {
			l.setError(err.Error(), true)
			return
		}
		l.setError("connecting…", false)
		go a.connect(cfg)
	})
	left.AddButton("Save", func() {
		cfg := l.read()
		if err := cfg.Save(a.cfgPath); err != nil {
			l.setError("save failed: "+err.Error(), true)
			return
		}
		l.updateHint(cfg)
		l.setError("saved to "+a.cfgPath+" (PSK stored 0600, shown masked)", false)
	})
	left.AddButton("Quit", func() { a.quit() })
	l.conn = left.GetButton(0)

	right := tview.NewForm()
	right.SetBorder(true).SetTitle(" TLS / dial ")
	right.AddInputField("SNI", cfg.SNI, 34, nil, nil)
	l.sni = right.GetFormItemByLabel("SNI").(*tview.InputField)
	l.sni.SetPlaceholder("optional")
	right.AddInputField("Dial IP", cfg.DialIP, 34, nil, nil)
	l.dialIP = right.GetFormItemByLabel("Dial IP").(*tview.InputField)
	l.dialIP.SetPlaceholder("optional pin")
	right.AddInputField("Family", cfg.Family, 8, nil, nil)
	l.family = right.GetFormItemByLabel("Family").(*tview.InputField)
	l.family.SetPlaceholder("auto|4|6")
	right.AddInputField("TLS CA", cfg.TLSCA, 34, nil, nil)
	l.tlsca = right.GetFormItemByLabel("TLS CA").(*tview.InputField)
	l.tlsca.SetPlaceholder("optional PEM file")
	right.AddInputField("TLS pin", cfg.TLSPin, 34, nil, nil)
	l.tlspin = right.GetFormItemByLabel("TLS pin").(*tview.InputField)
	l.tlspin.SetPlaceholder("optional SPKI sha256")
	right.AddCheckbox("Allow insecure TLS (test only)", cfg.Insecure, nil)
	l.insecure = right.GetFormItemByLabel("Allow insecure TLS (test only)").(*tview.Checkbox)

	l.msg = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	l.hint = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	l.updateHint(cfg)

	bottom := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(l.msg, 2, 0, false).
		AddItem(l.hint, 3, 0, false)

	cols := tview.NewFlex().
		AddItem(left, 0, 3, true).
		AddItem(right, 0, 2, false)

	l.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(title, 2, 0, false).
		AddItem(cols, 0, 1, true).
		AddItem(bottom, 5, 0, false)
	l.root.SetBorder(true).SetTitle(" BDC2 operator TUI ")
	return l
}

func (l *loginPage) connectButton() *tview.Button { return l.conn }

func (l *loginPage) read() *config.Config {
	timeout := 45
	refresh := 4
	if l.a.cfg != nil {
		timeout = l.a.cfg.TimeoutS
		refresh = l.a.cfg.RefreshS
	}
	c := &config.Config{
		Endpoint:  strings.TrimSpace(l.endpoint.GetText()),
		User:      strings.TrimSpace(l.user.GetText()),
		PSK:       strings.TrimSpace(l.psk.GetText()),
		SNI:       strings.TrimSpace(l.sni.GetText()),
		DialIP:    strings.TrimSpace(l.dialIP.GetText()),
		Family:    strings.ToLower(strings.TrimSpace(l.family.GetText())),
		TLSCA:     strings.TrimSpace(l.tlsca.GetText()),
		TLSPin:    strings.TrimSpace(l.tlspin.GetText()),
		Insecure:  l.insecure.IsChecked(),
		TimeoutS:  timeout,
		RefreshS:  refresh,
		Download:  l.a.cfg.Download,
		TunnelOut: l.a.cfg.TunnelOut,
		ActionLog: l.a.cfg.ActionLog,
	}
	if c.Family == "" {
		c.Family = "auto"
	}
	if c.TimeoutS <= 0 {
		c.TimeoutS = 45
	}
	if c.RefreshS <= 0 {
		c.RefreshS = 4
	}
	return c
}

func (l *loginPage) setError(text string, bad bool) {
	l.a.post(func() {
		if text == "" {
			l.msg.SetText("")
			return
		}
		if bad {
			l.msg.SetText("[red]" + tview.Escape(text) + "[-]")
		} else {
			l.msg.SetText("[yellow]" + tview.Escape(text) + "[-]")
		}
	})
}

func (l *loginPage) updateHint(cfg *config.Config) {
	refresh := strconv.Itoa(cfg.RefreshS)
	timeout := strconv.Itoa(cfg.TimeoutS)
	l.hint.SetText(fmt.Sprintf(
		"[gray]config:[-] %s\n[gray]psk (masked):[-] %s  [gray]refresh=%ss timeout=%ss[-]\n"+
			"[gray]Enter = move field · Tab = next control · Connect saves the config on success[-]",
		tview.Escape(l.a.cfgPath), cfg.MaskedPSK(), refresh, timeout))
}
