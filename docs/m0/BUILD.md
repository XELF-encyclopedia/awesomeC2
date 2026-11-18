# M0 build

Verified on: Windows 10 x64, Windows PowerShell 5.1, rustc/cargo 1.97.1,
go 1.26.3, git 2.49. Build date: 2026-11-19.

## One-shot

```powershell
powershell -ExecutionPolicy Bypass -File build\m0\build.ps1 -Release
# Linux/macOS:
sh build/m0/build.sh --release
```

Artifacts (Release, `-trimpath -ldflags "-s -w"`, Rust `opt-level="z"`, `lto`,
`panic=abort`, `strip`):

| binary         | size      | notes |
|----------------|-----------|-------|
| c2client.exe   | 369,664 B | Rust, no external crates, `cargo build --offline` |
| c2server.exe   | 3,078,656 B | Go, single binary, two listeners |
| c2operator.exe | 2,848,256 B | Go, operator CLI |
| c2builder.exe  | 2,421,248 B | Go, profile builder |

Client size is well under the 5 MB client budget; server is under the 50 MB
budget. On Linux the binaries are built with the same commands (no
Windows-only APIs are used outside `cmd /C` for `exec`).

## Exact commands used

```powershell
# Rust client (offline: no crates.io access needed)
cd src\m0\client-rust
cargo build --offline
cargo test --offline
cargo build --release --offline
# -> target\release\c2client.exe (copied to build\m0\bin)

# Go server / operator / builder
cd src\m0\server-go   ; go vet ./... ; go test ./... ; go build -trimpath -ldflags "-s -w" -o ..\..\..\build\m0\bin\c2server.exe .
cd src\m0\operator-go ; go vet ./... ; go test ./... ; go build -trimpath -ldflags "-s -w" -o ..\..\..\build\m0\bin\c2operator.exe .
cd src\m0\builder     ; go vet ./... ; go test ./... ; go build -trimpath -ldflags "-s -w" -o ..\..\..\build\m0\bin\c2builder.exe .
```

## Runtime configuration (no values baked into binaries)

| variable            | component | default (loopback) |
|---------------------|-----------|--------------------|
| `C2_CLIENT_LISTEN`  | server    | `127.0.0.1:9909`   |
| `C2_OPERATOR_LISTEN`| server    | `127.0.0.1:9910`   |
| `C2_OPERATOR_USER`  | server/operator | `ops` |
| `C2_OPERATOR_PSK` / `C2_OPERATOR_PSK_FILE` | server/operator | none (server refuses to start without it) |
| `C2_OPERATOR_ADDR`  | operator  | `127.0.0.1:9910`   |
| `C2_CLIENT_ADDR`    | client    | `127.0.0.1:9909`   |
| `C2_CLIENT_ID`      | client    | `<hostname>-<pid>` |
| `C2_CLIENT_INTERVAL`| client    | `20` (seconds)     |
| `C2_CLIENT_SUITE`   | client    | `plaintext` (`v2` is M1) |
| `C2_ALLOW_EXEC`     | client    | `0`                |

CLI flags override environment variables; a `--profile` file overrides defaults
but not environment variables or CLI flags (precedence: defaults < profile < env
< flags).

## Builder

```powershell
.\build\m0\bin\c2builder.exe --platform windows --arch amd64 --transport tcp `
    --host 127.0.0.1 --port 9909 --name demo --out profiles\m0
```

Outputs `profiles\m0\demo.json`, `demo.client.conf`, `demo.builder.json`.
`--format exe|elf|macho|apk|dll|service` exits 4 in M0 — real artifact generation
starts in M1 (see `NEXT.md` for the exact commands).

Host guard: only `localhost`/`127.0.0.1`/`::1`, `example.com`/`*.example.com`
and `203.0.113.0/24` are accepted unless `--allow-any-host` is passed.

## Tests

```powershell
# integration (builds, starts server+client, runs operator checks, tears down)
powershell -ExecutionPolicy Bypass -File tests\m0\run_loopback.ps1
# skip rebuild:
powershell -ExecutionPolicy Bypass -File tests\m0\run_loopback.ps1 -SkipBuild
```

Test logs land in `tests\m0\tmp\<timestamp>\` (git-ignored). The run exits 1 and
prints every failed check if anything regresses.
