# M0 — C2 v2 project, first vertical slice

Status: **M0 complete and verified on 2026-11-19** (Windows 10 host, Windows PowerShell 5.1).

This directory tree holds the M0 slice of the authorized red-team C2 v2 project:

```
src/m0/client-rust    Rust implant client (single binary, zero external crates)
src/m0/server-go      Go C2 server (client listener + operator listener)
src/m0/operator-go    Go operator CLI (login -> list -> task -> result)
src/m0/builder        Go builder CLI (profile generation; binary builds start in M1)
build/m0              build.ps1 / build.sh, binaries land in build/m0/bin
tests/m0              run_loopback.ps1 end-to-end loopback test (+ tmp logs)
docs/m0               README / ARCHITECTURE / PROTOCOL / BUILD / SECURITY /
                      AUTHORIZED_USE / HANDOFF / CHANGELOG / NEXT
profiles/m0           generated profiles (git-ignored contents)
```

**Why `m0/` subdirectories?** A parallel worker is developing the full framework
directly under `src/`, `docs/`, `build/`, `tests/`. The M0 slice is isolated so
neither stream clobbers the other. See `docs/m0/HANDOFF.md` for the known
collision (`src/client-rust/Cargo.toml` and `src/client-rust/src/crypto.rs` in the
shared tree were overwritten by the parallel stream during this session).

## Quickstart (loopback only)

```powershell
# 1) build everything
powershell -ExecutionPolicy Bypass -File build\m0\build.ps1 -Release

# 2) run the end-to-end test (server + client + operator, no external network)
powershell -ExecutionPolicy Bypass -File tests\m0\run_loopback.ps1 -SkipBuild

# 3) manual demo
$env:C2_OPERATOR_PSK = 'REPLACE_ME-with-a-random-32-byte-value'
.\build\m0\bin\c2server.exe --client-addr 127.0.0.1:9909 --operator-addr 127.0.0.1:9910
# in another shell:
.\build\m0\bin\c2builder.exe --platform windows --arch amd64 --transport tcp `
    --host 127.0.0.1 --port 9909 --name demo --out profiles\m0
.\build\m0\bin\c2client.exe --profile profiles\m0\demo.client.conf
# in a third shell:
.\build\m0\bin\c2operator.exe --addr 127.0.0.1:9910 --user ops list
.\build\m0\bin\c2operator.exe --addr 127.0.0.1:9910 sysinfo <SESSION_ID>
```

No binary contains a domain, IP or key: the server takes `--client-addr`,
`--operator-addr`, `--operator-user`, `--psk`; the client takes `--addr` /
`--profile`; everything is also settable through `C2_*` environment variables.

## What M0 actually does (honest scope)

* Rust client connects over TCP, sends `hello` (hostname/os/arch/pid/user/suite),
  sends heartbeats, runs `sysinfo` and `ping` tasks, and refuses `exec` unless
  started with `--allow-exec` / `C2_ALLOW_EXEC=1`.
* Go server keeps a session registry with two listeners, PSK-authenticated
  operator login (constant-time compare over SHA-256), task dispatch with
  per-task result routing, bounded result storage.
* Go operator CLI performs login, `list`, `stats`, `sysinfo`, `task`, `exec`,
  `result`, `ping`, with table and `--json` output.
* Go builder validates platform/arch/transport/suite, refuses non-documentation
  callback hosts by default, and emits `<name>.json` + `<name>.client.conf` +
  `<name>.builder.json`.
* Tests: 8 Rust unit tests, 4 Go unit tests (codec/auth/registry/result routing),
  `go vet` clean, plus the 20-check loopback integration run.

**Not implemented in M0** (deliberate, no pretending): real implant compilation
(`--format exe|elf|macho|apk|dll|service` exits 4 with the M1 command), TLS/WS/
DNS/UDP transports, X25519+AEAD suite (interface present, returns
`Unsupported`), persistence, modules, GUI, AI assistant, RBAC, kill-switch,
remote update. See `NEXT.md`.
