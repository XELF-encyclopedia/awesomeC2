# NEXT — M1 plan with exact commands

M0 is done and verified. M1 adds the encrypted transport and real artifact
generation. Nothing below has been executed yet; do not mark it done until the
commands actually run and their output is kept.

## M1.1 Dependency-carrying client build

The M0 client intentionally has no crates. M1 adds the AEAD stack. Suggested
minimal, audited set:

```toml
# src/m0/client-rust/Cargo.toml
[dependencies]
x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }
hkdf = "0.12"
sha2 = "0.10"
aes-gcm = { version = "0.10", default-features = false, features = ["aes", "alloc"] }
chacha20poly1305 = { version = "0.10", default-features = false, features = ["alloc"] }
rand_core = { version = "0.6", features = ["getrandom"] }
```

```powershell
cd src\m0\client-rust
cargo fetch                     # needs network once; commit Cargo.lock
cargo build --release --locked
cargo test --locked
```

Then implement:

1. `crypto::V2` with `ClientHello{eph_pub}` / `ServerHello{eph_pub, salt}`,
   HKDF-SHA256 with info `b"c2v2-session"`, AEAD seal/open using the frame type
   as AAD, 12-byte random nonce prefixed to the ciphertext.
2. Server side (`src/m0/server-go`): add `--tls-cert/--tls-key` and a TLS
   listener; implement the same HKDF/AEAD using `crypto/ecdh`, `crypto/hkdf`,
   `crypto/aes`+`cipher.NewGCM` (std lib, no new dependency).
3. Negotiation: server accepts `suite=plaintext` only when `--allow-plaintext` is
   passed; default requires `v2`.

Verification gate: `tests/m0/run_loopback.ps1` must be extended with a
`-Suite v2` run and must show `suite=v2-x25519-aead` in `operator list`.

## M1.2 Builder artifact generation

```powershell
# Windows x64 (MSVC toolchain installed)
rustup target list --installed
cargo build --release --target x86_64-pc-windows-msvc -p c2client-m0
# Windows x64 via MinGW (if MSVC unavailable)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# Linux static (needs musl target; linking may need `rust-lld` or musl-gcc)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# ARM64 Linux
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl

# macOS (cross-compiling from Windows needs osxcross; otherwise build on macOS)
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

Then make `c2builder --format exe|elf|macho` run the matching
`cargo build --target ...`, copy the artifact, and record the SHA-256 + size in
`<name>.builder.json`. Keep `--format apk` failing with an explicit message until
M3's Android toolchain lands.

Verification gate: builder emits a real binary whose `--help` runs and which
connects to the loopback server (`--launch`).

## M1.3 Server hardening

* Config file (`server.yaml`): listeners, TLS paths, PSK/per-operator keys,
  session DB path. Precedence: defaults < file < env < flags.
* SQLite persistence of sessions/tasks/audit (`modernc.org/sqlite` or
  `github.com/mattn/go-sqlite3` — decide after checking cgo availability).
* Per-connection read limits + handshake timeout (already have frame cap and
  deadlines; add a pre-hello 5 s deadline).
* Operator audit log: JSONL with user, action, session, task id, timestamp, result
  hash.

## M1.4 Docs and tests

* Update `PROTOCOL.md` with the negotiated suite and handshake frames.
* Add `tests/m0/run_loopback.sh` (Linux) and a CI-style `make test`.
* Add a protocol fuzz seed corpus for the frame decoder
  (`go test -fuzz=FuzzReadFrame ./...`).

## Environment facts observed on this host (2026-11-19)

```
rustc 1.97.1 (8901d2a0c 2026-11-13)
cargo 1.97.1
go version go1.26.3 windows/amd64
git version 2.49.0.windows.1
```

No Android SDK/NDK, no osxcross, no MinGW presence was verified in this session —
check with `build/toolchain/capability.md` (parallel workstream) before promising
those targets.
