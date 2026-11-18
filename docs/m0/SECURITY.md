# Security notes (M0)

## What M0 is and is not

M0 is an engineering slice used to prove the build/run/verify pipeline. It is
**not** safe for any non-lab network:

* transport is plaintext TCP (suite `plaintext`);
* the only authentication is an operator PSK over that plaintext channel;
* there is no replay protection, no forward secrecy, no integrity tag;
* `exec` is a raw shell on the client and is disabled by default.

The `SessionCipher` interface (`src/m0/client-rust/src/crypto.rs`) is the seam
where M1 inserts X25519 -> HKDF-SHA256 -> AES-256-GCM (preferred) or
ChaCha20-Poly1305. `Suite::V2` currently returns `Unsupported` on purpose: a
caller cannot accidentally believe it is encrypted.

## Secret handling

* No PSK, domain, IP or client identifier is compiled into any binary. The server
  requires `--psk`/`C2_OPERATOR_PSK`/`--psk-file`; the client receives its
  endpoint from `--profile`/`--addr`.
* Passwords/PSKs are never written to logs. Server logs contain the operator
  username and peer address only.
* The server warns when the PSK is shorter than 16 characters or in a small
  common-password set, and refuses to run without any PSK unless
  `--insecure-no-auth` is explicitly set (loopback lab only).
* Generated profiles are git-ignored (`profiles/**` except `.gitkeep`) because a
  real engagement profile names a live endpoint and client id.

## Repository guardrails

* `c2builder` refuses non-documentation hosts (`example.com`, `*.example.com`,
  `203.0.113.0/24`, loopback) unless `--allow-any-host` is passed deliberately.
* Documentation, examples and tests use only `example.com`, `203.0.113.x`,
  `REPLACE_ME`, `127.0.0.1` and high loopback ports (19909/19910).
* Tests bind to loopback only and never make outbound connections.

## Operational rules

1. Only run the client/server against hosts listed in the engagement's written
   authorization (see `AUTHORIZED_USE.md`).
2. Keep `exec` disabled unless the engagement explicitly authorizes command
   execution on the target.
3. Do not deploy M0 plaintext binaries anywhere except an isolated lab. Use M1+
   (TLS + AEAD) for anything crossing an untrusted network.
4. Log and audit: every task dispatch and result is logged server-side; keep
   those logs with the engagement record.

## Known gaps (tracked in NEXT.md)

| Gap | Risk | Planned |
|-----|------|---------|
| plaintext transport | traffic disclosure / tampering | M1 TLS + AEAD |
| single shared PSK | no per-operator attribution | M1 per-operator keys + RBAC + audit |
| no kill-switch | cannot revoke an implant | M2 signed KILL + dead-man window |
| no signed config/updates | tampering with profiles | M2 signed manifest + hash pin |
| unbounded `exec` when enabled | accidental damage | M2 allowlist + confirmation + audit |
