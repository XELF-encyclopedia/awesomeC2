package main

// c2operator — M0 operator CLI for the authorized red-team C2 v2 server.
//
// Usage examples (loopback lab):
//   c2operator --addr 127.0.0.1:9910 list
//   c2operator list
//   c2operator sysinfo s-1234abcd
//   c2operator task s-1234abcd sysinfo
//   c2operator task s-1234abcd exec "hostname"
//   c2operator stats
//
// Config via env: C2_OPERATOR_ADDR, C2_OPERATOR_USER, C2_OPERATOR_PSK,
// C2_OPERATOR_PSK_FILE, C2_OPERATOR_TIMEOUT.
// See docs/PROTOCOL.md and docs/AUTHORIZED_USE.md.

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type client struct {
	conn net.Conn
	br   *bufio.Reader
}

func dial(addr, user, psk string, timeout time.Duration) (*client, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	c := &client{conn: conn, br: bufio.NewReader(conn)}
	conn.SetDeadline(time.Now().Add(timeout))
	if err := writeFrame(conn, msg{"t": "login", "user": user, "psk": psk, "client": "c2operator/0.1.0-m0"}); err != nil {
		conn.Close()
		return nil, err
	}
	ack, err := readFrame(c.br)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if ack["ok"] != true {
		conn.Close()
		return nil, fmt.Errorf("login rejected: %s", str(ack, "err"))
	}
	conn.SetDeadline(time.Time{})
	return c, nil
}

func (c *client) call(m msg, timeout time.Duration) (msg, error) {
	c.conn.SetDeadline(time.Now().Add(timeout))
	if err := writeFrame(c.conn, m); err != nil {
		return nil, err
	}
	r, err := readFrame(c.br)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func main() {
	var (
		addr    = flag.String("addr", envOr("C2_OPERATOR_ADDR", "127.0.0.1:9910"), "operator listener address")
		user    = flag.String("user", envOr("C2_OPERATOR_USER", "ops"), "operator username")
		psk     = flag.String("psk", envOr("C2_OPERATOR_PSK", ""), "operator PSK")
		pskFile = flag.String("psk-file", envOr("C2_OPERATOR_PSK_FILE", ""), "file containing the operator PSK")
		timeout = flag.Duration("timeout", envDuration("C2_OPERATOR_TIMEOUT", 5*time.Second), "connect/command timeout")
		asJSON  = flag.Bool("json", false, "emit raw JSON responses")
		wait    = flag.Int("wait", 20, "seconds to wait for task results")
	)
	flag.Usage = usage
	flag.Parse()

	secret := *psk
	if secret == "" && *pskFile != "" {
		b, err := os.ReadFile(*pskFile)
		if err != nil {
			fatal("read psk file: %v", err)
		}
		secret = strings.TrimSpace(string(b))
	}

	args := flag.Args()
	cmd := "list"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	c, err := dial(*addr, *user, secret, *timeout)
	if err != nil {
		fatal("connect %s: %v", *addr, err)
	}
	defer c.conn.Close()

	switch cmd {
	case "list", "sessions":
		r, err := c.call(msg{"t": "list"}, *timeout)
		check(err)
		if *asJSON {
			printJSON(r)
			return
		}
		printSessions(r)
	case "stats":
		r, err := c.call(msg{"t": "stats"}, *timeout)
		check(err)
		if *asJSON {
			printJSON(r)
			return
		}
		fmt.Printf("sessions=%d uptime=%ds server_time=%d protocol=%s version=%s\n",
			num(r, "sessions"), num(r, "uptime_secs"), num(r, "server_time"),
			str(r, "protocol"), str(r, "version"))
	case "task":
		if len(args) < 1 {
			fatal("usage: c2operator task <session_id> <kind> [arg]")
		}
		kind := "sysinfo"
		arg := ""
		if len(args) >= 2 {
			kind = args[1]
		}
		if len(args) >= 3 {
			arg = strings.Join(args[2:], " ")
		}
		r, err := c.call(msg{"t": "task", "session_id": args[0], "kind": kind, "arg": arg, "wait": *wait}, time.Duration(*wait+10)*time.Second)
		check(err)
		printResult(r, *asJSON)
	case "sysinfo":
		if len(args) < 1 {
			fatal("usage: c2operator sysinfo <session_id>")
		}
		r, err := c.call(msg{"t": "task", "session_id": args[0], "kind": "sysinfo", "wait": *wait}, time.Duration(*wait+10)*time.Second)
		check(err)
		printResult(r, *asJSON)
	case "exec":
		if len(args) < 2 {
			fatal("usage: c2operator exec <session_id> <command>")
		}
		cmdline := strings.Join(args[1:], " ")
		r, err := c.call(msg{"t": "task", "session_id": args[0], "kind": "exec", "arg": cmdline, "wait": *wait}, time.Duration(*wait+10)*time.Second)
		check(err)
		printResult(r, *asJSON)
	case "result":
		if len(args) < 2 {
			fatal("usage: c2operator result <session_id> <task_id>")
		}
		r, err := c.call(msg{"t": "result", "session_id": args[0], "task_id": args[1], "wait": *wait}, time.Duration(*wait+10)*time.Second)
		check(err)
		printResult(r, *asJSON)
	case "ping":
		r, err := c.call(msg{"t": "ping"}, *timeout)
		check(err)
		printJSON(r)
	default:
		usage()
	}
	if cmd != "quit" {
		c.call(msg{"t": "quit"}, 2*time.Second)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `c2operator 0.1.0 (M0)

usage: c2operator [--addr HOST:PORT] [--user U] [--psk PSK|--psk-file F] [--json] [--wait SECS] <command>

commands:
  list|sessions              list connected sessions
  stats                      server stats
  sysinfo <session_id>       ask a client for sysinfo
  task <session_id> <kind> [arg]   run a task (sysinfo|ping|exec)
  exec <session_id> <cmd>    convenience for task ... exec
  result <session_id> <task_id>    fetch a previously produced result
  ping                       server round-trip check

env: C2_OPERATOR_ADDR, C2_OPERATOR_USER, C2_OPERATOR_PSK,
     C2_OPERATOR_PSK_FILE, C2_OPERATOR_TIMEOUT
`)
}

func printSessions(r msg) {
	list, _ := r["sessions"].([]any)
	fmt.Printf("sessions=%d\n", int(num(r, "count")))
	if len(list) == 0 {
		return
	}
	rows := make([][]string, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rows = append(rows, []string{
			str(m, "session_id"),
			str(m, "client_id"),
			str(m, "hostname"),
			str(m, "os") + "/" + str(m, "arch"),
			str(m, "user"),
			str(m, "suite"),
			str(m, "remote_addr"),
			str(m, "last_seen"),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	headers := []string{"SESSION", "CLIENT_ID", "HOST", "OS", "USER", "SUITE", "REMOTE", "LAST_SEEN"}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, v := range row {
			if len(v) > widths[i] {
				widths[i] = len(v)
			}
		}
	}
	printRow(headers, widths)
	for _, row := range rows {
		printRow(row, widths)
	}
}

func printRow(row []string, widths []int) {
	for i, v := range row {
		fmt.Printf("%-*s  ", widths[i], v)
	}
	fmt.Println()
}

func printResult(r msg, asJSON bool) {
	if asJSON || r["ok"] != true {
		printJSON(r)
		if r["ok"] != true {
			os.Exit(1)
		}
		return
	}
	fmt.Printf("task_id=%s kind=%s result_ok=%v at=%d\n",
		str(r, "task_id"), str(r, "kind"), r["result_ok"] == true, num(r, "at"))
	if e := str(r, "err"); e != "" {
		fmt.Printf("err: %s\n", e)
	}
	if d := str(r, "data"); d != "" {
		fmt.Println(d)
	}
	if r["result_ok"] != true {
		os.Exit(1)
	}
}

func printJSON(m msg) {
	b, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println(string(b))
}

func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "c2operator: "+format+"\n", a...)
	os.Exit(1)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
		if dd, err := time.ParseDuration(v); err == nil {
			return dd
		}
	}
	return d
}
