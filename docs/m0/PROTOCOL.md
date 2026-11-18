# M0 protocol (`m0-json/1`)

Transport: TCP. Framing: **4-byte big-endian length + UTF-8 JSON object**.
Maximum frame size: 1 MiB. A frame larger than that closes the connection.
Fields are flat scalars only (string / number / bool / null) in M0.

Later milestones reuse this envelope but add `suite`, `seq`, `nonce` and an
AEAD-sealed body (see `ARCHITECTURE.md`). Nothing in M0 claims confidentiality.

## Client -> server

### `hello` (first frame, mandatory)

```json
{"t":"hello","client_id":"win-amd64-demo","hostname":"BOTRES","os":"windows",
 "arch":"x86_64","pid":36564,"user":"operator","suite":"plaintext",
 "version":"0.1.0"}
```

Server behavior: if `client_id` is empty it synthesizes one from the remote
address. A new connection with an existing `client_id` replaces the old session
and the old connection receives `{"t":"shutdown"}`.

### `heartbeat`

```json
{"t":"heartbeat","ts":1795019681}
```

Refreshes `last_seen`. Send interval defaults to 20 s (`interval` profile key).

### `result`

```json
{"t":"result","task_id":"t-1a2b...","kind":"sysinfo","ok":true,
 "data":"hostname=...;os=windows;...","err":""}
```

`data` is an opaque string for M0. `ok=false` plus `err` carries the refusal or
failure reason.

### `pong` — reply to a server-side `ping` frame (optional in M0).

## Server -> client

### `hello_ack`

```json
{"t":"hello_ack","session_id":"s-50ed2407f6424c8e","interval":20,
 "server_time":1795019681}
```

### `task`

```json
{"t":"task","task_id":"t-9f3c...","kind":"sysinfo","arg":""}
```

Kinds implemented by the M0 client:

| kind      | arg            | gated by                       | data on success            |
|-----------|----------------|--------------------------------|----------------------------|
| `sysinfo` | ignored        | -                              | `hostname=..;os=..;arch=..`|
| `ping`    | ignored        | -                              | `pong`                     |
| `exec`    | shell command  | `--allow-exec`/`C2_ALLOW_EXEC=1`| stdout + `[stderr]` block  |

Unknown kinds produce `ok=false` with `err="unknown task kind: ..."`.

### `ping` / `shutdown`

`ping` asks the client to answer `{"t":"pong","ts":...}`; `shutdown` tells the
client to exit its session loop cleanly.

## Operator <-> server

### Login (first frame)

```json
{"t":"login","user":"ops","psk":"<secret>","client":"c2operator/0.1.0-m0"}
```

Reply on success:

```json
{"t":"login_ack","ok":true,"server_time":1795019681,"sessions":0}
```

On failure: `{"t":"login_ack","ok":false,"err":"invalid credentials"}` and the
connection is closed. The server compares `user` with `subtle.ConstantTimeCompare`
and the PSK via SHA-256 digests in constant time. If the server is started
without a PSK it refuses to start unless `--insecure-no-auth` is given.

### Commands

| request                                                    | reply |
|------------------------------------------------------------|-------|
| `{"t":"list"}`                                             | `{"t":"sessions","ok":true,"count":N,"sessions":[{...}]}` |
| `{"t":"stats"}`                                            | `{"t":"stats","ok":true,"sessions":N,"uptime_secs":S,...}` |
| `{"t":"task","session_id":S,"kind":K,"arg":A,"wait":W}`    | `{"t":"result",...}` or `{"t":"timeout","ok":false,...}` |
| `{"t":"result","session_id":S,"task_id":T,"wait":W}`       | `{"t":"result",...}` or `{"t":"timeout","ok":false,...}` |
| `{"t":"ping"}`                                             | `{"t":"pong","ok":true,"ts":...}` |
| `{"t":"quit"}`                                             | `{"t":"bye","ok":true}` then close |

Session object fields: `session_id, client_id, hostname, os, arch, user, suite,
version, pid, remote_addr, connected, last_seen` (UTC RFC3339).

## Error and robustness rules

* Malformed JSON / wrong first frame: connection closed; server logs the reason.
* Oversized frame: connection closed.
* Task result timeout: operator gets `t=timeout` with the allocated `task_id`;
  a late result is still stored on the session for `result <sid> <task_id>`.
* Server send-queue full (>32 pending frames on one session): operator gets an
  error instead of blocking forever.
