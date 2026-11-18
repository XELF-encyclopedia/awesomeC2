# Security Model and Limitations

This document describes what the framework protects, what it does **not** protect, and how to reduce risk in a lab.

## Threat model

The design assumes:

- The operator and server are trusted.
- The pre-shared keys are distributed out of band.
- The target environment may be monitored (network, endpoint, logs).
- An attacker may capture traffic, replay frames, or obtain the client binary.

It does **not** assume that the client is invisible, that the server is unreachable, or that a stolen PSK is harmless.

## Cryptographic construction

- AES-128-GCM for payload encryption and integrity.
- The 24-byte header is used as AAD, so header fields are authenticated.
- Session key: HKDF-SHA256(psk, client_id || hello_nonce, "backd-c2-v1", 16).
- HELLO proof: HMAC-SHA256(psk, "hello" || client_id || nonce).
- Operator proof: HMAC-SHA256(psk, "opauth" || user || nonce).
- Sequence numbers are monotonic per direction; replay is rejected.
- Nonces come from the operating system CSPRNG (`crypto/rand` on Go, `CryptGenRandom` on Windows).

## Known weaknesses

1. **Static PSK / no forward secrecy.** A captured client binary or a leaked config yields a long-lived key. Use one PSK per client/operator and rotate them.
2. **TLS termination.** In the example deployment, Cloudflare and nginx terminate TLS. The inner protocol is still encrypted, but traffic metadata (SNI, timing, connection duration) is visible to those layers.
3. **Minimal TLS bridge.** `tlsbridge` is a small helper, not a hardened TLS terminator. It supports `--tls-ca`/`--tls-pin` in the operator path, but the bridge itself can be configured to skip verification. Do not use `--insecure` outside a lab.
4. **In-memory replay cache.** The server's replay protection is per-process and short-lived. A restart or a very old captured frame may not be caught by the cache alone; sequence checks still apply per connection.
5. **32-bit sequence number.** The reference implementation does not rekey at a sequence limit. Long-lived, high-volume sessions should be reconnected or the protocol extended before deployment.
6. **No kernel/rootkit hiding.** The Windows client is a normal user-mode process. Process names and paths can be made plausible, but Task Manager, Process Explorer, EDR, and Sysmon can see it.
7. **Audit hash chain is not tamper-proof.** It is tamper-evident only if the audit file is copied to a protected external system.
8. **Shell output encoding.** Older Windows consoles emit CP936/GBK. The operator attempts UTF-8, UTF-16, then GBK decoding; binary output falls back to hex.

## Hardening checklist

- Generate 32 random bytes per PSK; never reuse a PSK between clients or operators.
- Put the PSK in a protected file or DPAPI blob, not in the process command line.
- Use a TLS pin or CA validation on the operator; avoid `--insecure`.
- Restrict the operator endpoint by source address at nginx/Cloudflare.
- Use a separate, short-lived client id per engagement and revoke it when done.
- Rotate PSKs after an engagement; treat a captured binary as a key compromise.
- Minimize shell/history/log exposure; do not paste PSKs into chat or ticketing systems.
- Keep audit logs off the target and copy them to a write-once store.
- Prefer a per-client PSK and a server-side allow-list.
- Test in a lab; do not run persistence or destructive modules on production systems.

## Responsible use

This code is for authorized adversary emulation, detection engineering, and protocol research. You are responsible for complying with the law and with the rules of engagement for your engagement.
