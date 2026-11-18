# Windows Client Notes

The client is a static x86-64 C program built with MinGW-w64 and the system `msvcrt` runtime. It targets Windows Server 2008 SP1 and later; it avoids UCRT, VCRUNTIME, and C++ dependencies.

## Build-time configuration

`build.cmd` and `Makefile` generate `src/generated_config.h` from environment variables:

| Variable | Meaning |
| --- | --- |
| `C2_CLIENT_DOMAIN` | default server host (loopback or bridge host) |
| `C2_CLIENT_PORT` | default server port |
| `C2_CLIENT_PATH` | WebSocket path, usually `/ws` |
| `C2_CLIENT_ID` | default client id |
| `C2_ALLOW_SHELL` | `0`/`1` default for shell execution |
| `C2_PSK_B64` | optional compiled-in PSK; leave empty in source control |
| `C2_BUILD_ID` | version string reported in HELLO |

Generated headers are ignored by Git. **Never commit a generated header containing a real PSK.**

## Runtime configuration

Precedence: command line → environment → compiled defaults.

- `--host`, `--port`, `--path`, `--id`
- `--psk base64:...` or `C2_CLIENT_PSK`
- `--allow-shell`, `--allow-adv`
- `--log <path>`, `-v`
- `--sni`, `--pin-sha256`, `--insecure` (only for lab use)

## Modules

| Kind | Purpose |
| --- | --- |
| `sysinfo` | hostname, user, OS, arch, pid, integrity |
| `echo` | connectivity test |
| `shell` | run a command with timeout, capture output |
| `ps` | process list |
| `cat` | read a file with offset/size |
| `put` / `get` | file transfer |
| `persist` | install/remove persistence methods |
| `inject` | inject shellcode into a target process |
| `inject_dll` | load a DLL into a target process |
| `migrate` | process hollowing (lab only; not stealthy) |
| `screenshot` | capture the desktop |
| `keylog` | start/stop a simple key logger |
| `tunnel` | TCP tunnel via the operator |
| `cleanup` | remove local artifacts |
| `timestomp` | set file timestamps |
| `selfdestruct` | remove the client and exit |

Advanced modules are gated by `allow_advanced` where applicable. Persistence should only be used with explicit authorization.

## Encoding

Older Windows consoles emit CP936/GBK. The client uses `CreateProcessW` and captures the raw console bytes; the operator decodes UTF-8, UTF-16, then GBK, and falls back to hex for binary output. This is why `OUT_B64`/`OUT_HEX` may appear in logs.

## Limitations

- User-mode only; no kernel driver, no rootkit.
- No process injection by default; injection is an explicit operator task.
- The client is visible in Task Manager/Process Explorer.
- The client is not signed; signing is deployment-specific.
- Persistence methods and cleanup are intentionally explicit; review them before use.
