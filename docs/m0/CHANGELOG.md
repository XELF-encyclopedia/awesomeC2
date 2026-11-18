# Changelog

All notable changes to the M0 slice. Dates in UTC.

## [0.1.0-m0] — 2026-11-19

### Added

* Repository skeleton: `src/m0/{client-rust,server-go,operator-go,builder}`,
  `docs/m0`, `build/m0`, `tests/m0`, `profiles/m0`, `.gitignore`.
* **Rust client** (`c2client`, 369,664 B release, zero third-party crates):
  TCP connect with backoff, `hello`/`hello_ack`, heartbeat thread, frame codec
  (4-byte BE length + JSON), `sysinfo`/`ping` tasks, `exec` gated behind
  `--allow-exec`, profile/env/CLI configuration, `SessionCipher` interface with a
  plaintext implementation and an explicit `Unsupported` V2 suite.
* **Go server** (`c2server`, 4,457,984 B): client listener + operator listener,
  session registry with reconnect replacement, PSK login (constant-time
  SHA-256 comparison), task dispatch with per-task waiting, bounded result store,
  graceful signal shutdown.
* **Go operator CLI** (`c2operator`, 4,147,712 B): `list|sessions`, `stats`,
  `sysinfo`, `task`, `exec`, `result`, `ping`; table and `--json` output.
* **Go builder CLI** (`c2builder`, 3,537,920 B): validates
  platform/arch/transport/suite/jitter, documentation-host guard, emits
  `<name>.json`, `<name>.client.conf`, `<name>.builder.json`, optional `--launch`.
* **Build scripts**: `build/m0/build.ps1`, `build/m0/build.sh` (env-injected
  configuration, no hardcoded endpoints).
* **Tests**: 8 Rust unit tests, 4 Go unit tests, `tests/m0/run_loopback.ps1`
  end-to-end (build -> builder -> server -> client -> operator list/sysinfo/ping/
  exec-deny/stats/exec-allow -> teardown), all checks passing.
* **Docs**: README, ARCHITECTURE, PROTOCOL, BUILD, SECURITY, AUTHORIZED_USE,
  HANDOFF, CHANGELOG, NEXT.

### Not implemented (explicitly deferred)

* TLS/WSS/DNS/UDP/DoH transports; X25519+AEAD suite; implant cross-compilation
  (`--format exe|elf|macho|apk|dll|service` exits 4); persistence, modules, GUI,
  AI assistant, RBAC, kill-switch, remote update.
