# HANDOFF — M0 slice

## What this is

The M0 vertical slice of the C2 v2 project: four binaries that build, connect and
complete a task round-trip on loopback, plus tests and documentation. It was
produced by reading (read-only) the project's `HANDOFF.md` / `AGENTS.md` for
authorization scope and protocol lessons, **without copying or modifying the old
BDC2 source under `E:\Program Files\ARTEX-main\data\tasks\4`** and **without
touching the `.58` host, the VPS or any production database**.

## Extracted from HANDOFF.md / AGENTS.md (authorization and lessons only)

* Engagement is an **authorized red-team assessment**; authorized target scope is
  `<engagement scope as recorded in the signed authorization>` and associated hosts confirmed during the engagement. Nothing
  outside that scope may be touched. This M0 work deliberately produced **zero
  target traffic** (loopback only).
* Never write real PSKs, domains, IPs, client ids or logs into source or a public
  repo: endpoints and keys are injected at build/runtime via environment
  variables or CLI flags. This slice follows that rule; docs use
  `example.com` / `203.0.113.x` / `REPLACE_ME` only.
* Protocol lessons carried into the design: keep the wire contract versioned and
  frozen once deployed; separate client-facing and operator-facing listeners;
  terminate edge TLS in nginx/Cloudflare but still run an application-layer
  authenticated encryption suite so the edge sees no plaintext; old Windows
  targets cannot rely on the system TLS stack, so the client must carry its own.
* Build lessons: static, dependency-minimal single binaries; configuration
  injected, never compiled in; verify actual build output and keep full error
  logs instead of asserting success.

## State at handoff

| Item | State |
|------|-------|
| Rust client build (`cargo build --offline`, debug + release) | works; 8 unit tests pass |
| Go server build + `go vet` + 4 unit tests | works |
| Go operator CLI | works (login/list/stats/task/exec/result/ping, `--json`) |
| Go builder CLI | works (`--format profile`; binary formats exit 4 with M1 pointer) |
| Loopback integration test | 20/20 checks pass, incl. exec-deny and exec-allow paths |
| Docs | README/ARCHITECTURE/PROTOCOL/BUILD/SECURITY/AUTHORIZED_USE/HANDOFF/CHANGELOG/NEXT |
| TLS / AEAD / WS / DNS transports | **not implemented** (M1/M3) |
| Implant cross-compilation | **not implemented** (M1) |

## Known collision with parallel work (important)

A parallel worker is building the full framework in the same repository root
(`src/`, `docs/`, `build/`, `tests/`). During this session that stream
**overwrote** `src/client-rust/Cargo.toml` and `src/client-rust/src/crypto.rs`,
so this slice was relocated to `src/m0/`, `docs/m0/`, `build/m0/`, `tests/m0/`,
`profiles/m0/` for isolation. `src/client-rust/src/main.rs` and `proto.rs` are
copies of this slice's code that were left in place in the shared tree; do not
assume `src/client-rust` builds offline (the parallel stream added crates.io
dependencies).

## Where to continue

See `NEXT.md` — it lists M1 with exact commands (Rust targets, TLS listener,
AEAD suite wiring, builder artifact generation, cross-compile matrix).
