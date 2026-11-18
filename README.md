# awesomeC2

A compact, research-oriented command-and-control (C2) framework for **authorized adversary emulation and lab use only**.

The project contains a Go server/operator pair, a Go terminal UI, a Windows client written in C, a small TLS/WebSocket bridge, protocol libraries, and deployment examples. It is intentionally small enough to read, audit, and modify.

> **Legal notice**
>
> Use this software only against systems you own or for which you have explicit, written authorization. Running it against third-party systems is illegal in most jurisdictions. The authors and contributors accept no liability for misuse.

## Contents

| Path | What it is |
| --- | --- |
| `server/` | Go C2 server (`cmd/server`) and CLI operator (`cmd/operator`), plus the `bdc2` protocol package |
| `client/` | Windows Server 2008 compatible C client (MinGW-w64, static msvcrt build) |
| `tui/` | Go terminal UI for operators |
| `tlsbridge/` | Small Windows TLS/WebSocket bridge (mbedTLS) for restricted egress |
| `tests/` | Protocol, loopback, and end-to-end tests |
| `deploy/` | Example server config, nginx, systemd, and client/operator launch snippets |
| `docs/` | Protocol, security, deployment, and client notes |

## Features

- 24-byte binary frame header (`BDC2`, version 1), TLV payloads.
- AES-128-GCM payload encryption with the header as AAD.
- Per-connection session key derived with HKDF-SHA256 from a pre-shared key and a fresh client nonce.
- HMAC-SHA256 HELLO proof and operator AUTH proof.
- Monotonic per-direction sequence numbers with replay rejection.
- Minimal RFC 6455 WebSocket implementation (client and server), including TLS.
- Task queue, heartbeat/jitter, reconnect with exponential backoff, file push/pull with SHA-256.
- Windows client modules: shell, process list, file read/write, persistence helpers, credential collection helpers, tunneling, key logging, screenshot, cleanup, self-destruct.
- Operator CLI and TUI with audit hash-chain support (`audit_hash_chain`).
- Example nginx/Cloudflare fronting and a local TLS bridge for hosts whose egress only permits a fixed endpoint.

## Quick start (loopback)

Generate two random PSKs:

```bash
openssl rand -base64 32
openssl rand -base64 32
```

Put them into a copy of `deploy/config.server.example.json` (or use environment-driven config). Then:

```bash
cd server
go build -o ../bin/server.exe ./cmd/server
go build -o ../bin/operator.exe ./cmd/operator

cd ..
./bin/server.exe -config deploy/config.server.example.json
```

On Windows, build the client:

```bat
cd client
set C2_CLIENT_DOMAIN=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:REPLACE_WITH_CLIENT_PSK
set C2_ALLOW_SHELL=1
build.cmd
```

The build regenerates `src/generated_config.h` from environment variables. That file is ignored by Git and must not be committed with real keys.

Run the operator against the local operator listener:

```bat
set C2_OPERATOR_ADDR=127.0.0.1:9910
set C2_OPERATOR_USER=ops
set C2_OPERATOR_PSK=base64:REPLACE_WITH_OPERATOR_PSK
bin\operator.exe list
```

## Configuration

All addresses, ports, PSKs, pins, and build identifiers are supplied at build time or run time. **No real PSK, key, domain, IP address, or target identifier belongs in this repository.**

- Server: `deploy/config.server.example.json`
- Operator: `deploy/config.operator.example.cmd`
- Client build/run: `deploy/config.client.example.cmd`
- TLS bridge: `tlsbridge --listen 127.0.0.1:1443 --connect <origin-ip>:443 --sni <origin-hostname>`
- TUI: environment variables and a local config file; see `tui/README.md`

Generate PSKs with a cryptographically secure source. Prefer a **separate PSK per client and per operator**.

## Build

### Server and operator

```bash
cd server
go test ./...
go build ./cmd/server ./cmd/operator
```

### TUI

```bash
cd tui
go build -o c2tui.exe .
```

The TUI's `go.mod` uses a local `replace` to `../server`; no network module fetch is required beyond the Go toolchain and the pinned dependencies.

### Windows client

Requirements: MinGW-w64 targeting `x86_64-w64-mingw32`, `objdump`, and a Windows-compatible `msvcrt` runtime. The provided `build.cmd` performs an import-table gate so the result is compatible with Windows Server 2008 and avoids UCRT/VCRUNTIME dependencies.

```bat
cd client
build.cmd --clean
set C2_CLIENT_DOMAIN=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:...
set C2_ALLOW_SHELL=1
build.cmd
```

### TLS bridge

```bash
cd tlsbridge
./build.sh
# or, on Windows with MinGW and mbedTLS installed:
build.bat
```

The bridge is a convenience for legacy/egress-restricted hosts. It is **not** a substitute for a proper TLS stack; it currently supports optional certificate verification and should be configured carefully. See `docs/SECURITY.md`.

## Protocol in one page

```text
Frame:
  magic "BDC2" | version=1 | type | flags | reserved
  | session_id (u64) | seq (u32) | payload_len (u32)
  | payload

HELLO (cleartext TLV):
  id, os, arch, ver, pid, nonce, mac

  mac = HMAC-SHA256(psk, "hello" || id || nonce)
  key = HKDF-SHA256(psk, id || nonce, "backd-c2-v1", 16)

Every other frame:
  AES-128-GCM(key, nonce=[dir,0..0,seq], AAD=header[0:24])
```

The full layout, message types, and operator RPCs are in `docs/PROTOCOL.md`.

## Security and limitations

This is **not** a covert implant and does not claim to be undetectable. It is a small, auditable C2 proof of concept. Important limitations:

- Static pre-shared keys by default; there is no forward secrecy.
- The server terminates the inner protocol; TLS is terminated by nginx/Cloudflare in the example deployment.
- The TLS bridge in this repository is intentionally minimal. Certificate verification is optional and must be enabled for production-like use.
- The Windows client is a normal user-mode process. It does not include a kernel driver or rootkit.
- The operator CLI prints task output; do not log secrets to shared systems.
- The audit hash chain is tamper-evident only if the log is protected externally.

See `docs/SECURITY.md` for the threat model and hardening checklist.

## Testing

```bash
cd server
go test ./...
cd ..
python tests/run_all.py --clients 20
```

The Python tests expect a built `server.exe` in a `verify/` directory next to the test runner. See `tests/README.md` for the expected layout.

## License

MIT. See `LICENSE`.
