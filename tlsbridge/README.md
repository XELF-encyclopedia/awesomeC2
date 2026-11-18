# tlsbridge

A small Windows TLS/WebSocket relay for hosts that can only reach a fixed origin or need a loopback listener.

It accepts plain WebSocket traffic on `--listen`, opens a TLS connection to `--connect`, and relays bytes. The SNI is set from `--sni`.

## Build

Requirements: MinGW-w64 and mbedTLS (`libmbedtls`, `libmbedx509`, `libmbedcrypto`).

```bat
set MBEDTLS_PREFIX=C:\msys64\mingw64
build.bat
```

or:

```bash
MBEDTLS_PREFIX=/mingw64 ./build.sh
```

If `MBEDTLS_PREFIX` is omitted, the compiler's default include/library paths are used.

## Use

```bat
tlsbridge.exe --listen 127.0.0.1:1443 --connect 203.0.113.10:443 --sni c2-client.example.com --log C:\Windows\Temp\c2bridge.log
```

Then point the client at `127.0.0.1:1443` with the same WebSocket path.

## Security

This is a convenience relay, not a hardened TLS terminator. It supports a `--selftest` mode and optional certificate verification (`--tls-ca`, `--tls-pin`, `--insecure`). Do not use `--insecure` outside a lab.

No endpoint, SNI, IP, or key is hardcoded. All values are supplied on the command line.
