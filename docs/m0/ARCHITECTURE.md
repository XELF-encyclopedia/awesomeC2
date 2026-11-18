# M0 architecture

## Components

```
             +----------------------------+
             |        c2server (Go)       |
 operator -->| operator listener :9910   |
  (PSK)      |  login -> list/task/result |
             |                            |
             | client listener  :9909     |
             |  hello/ack/heartbeat/task  |
             +-------------+--------------+
                           ^
                           | TCP framed JSON (M0)
                           |
                 +---------+---------+
                 |  c2client (Rust)  |
                 |  hello, heartbeat |
                 |  sysinfo/ping/exec|
                 +-------------------+

  c2builder (Go) --> profiles/<name>.json + .client.conf
                   --> optional --launch of c2client against the same endpoint
```

Process boundaries are deliberate: the server is the only component that holds
session state; the operator CLI is a stateless client; the builder only writes
files and optionally spawns the client. No component talks to the internet on
its own in M0.

## Data flow

1. `c2server` listens on the client port and the operator port.
2. `c2client` connects, sends `hello`; server registers a session id and answers
   `hello_ack`; both sides then exchange length-prefixed frames.
3. Operator logs in with user + PSK; server answers `login_ack`.
4. `task` -> server allocates `task_id`, queues the task on the session channel,
   waits for the matching `result` frame (default 20 s), returns it inline.
5. Client heartbeats keep `last_seen` fresh; a newer connection for the same
   `client_id` replaces the older session (shutdown frame is sent to the old one).

## Concurrency model

* Server: one goroutine per connection plus one writer goroutine per client
  session (single-writer rule on the socket). Session state is mutex-guarded.
* Client: reader loop on the main goroutine, one heartbeat thread; writes go
  through `Arc<Mutex<...>>` so frame boundaries are never interleaved.
* Results: each task id is registered in a waiter map before dispatch; the
  result is also stored (bounded at 256/session) so `operator result <sid>
  <task_id>` can retrieve it later.

## Trust boundaries

* Client <-> server: untrusted network assumed in M1 (TLS + X25519/AEAD). In M0
  frames are plaintext and must stay on loopback/lab.
* Operator <-> server: PSK over the same transport; M1 adds per-operator keys,
  RBAC, audit trail and presence.
* Builder output: profiles are secrets-adjacent (they name an endpoint and client
  id). The repo guard refuses non-documentation hosts unless explicitly
  overridden; generated profiles are git-ignored.

## Deliberate M0 simplifications

| Concern        | M0                          | M1/M2 target                              |
|----------------|-----------------------------|-------------------------------------------|
| Transport      | plaintext TCP loopback      | TLS + WSS, rustls in client, nginx/CF edge |
| Key exchange   | none (suite=plaintext)      | X25519 -> HKDF-SHA256 -> AES-256-GCM/ChaCha20 |
| Auth           | operator PSK (SHA-256 ct)   | per-operator Ed25519 keys + RBAC + audit  |
| Storage        | in-memory registry          | SQLite by default, Postgres optional      |
| Implant builds | profile only                | cargo cross-targets, strip, size budget   |
| Modules        | sysinfo/ping/exec           | manifest + schema + capability tagging    |
