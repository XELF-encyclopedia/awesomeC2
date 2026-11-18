# Server and operator

## Build

```bash
go test ./...
go build -o ../bin/server ./cmd/server
go build -o ../bin/operator ./cmd/operator
```

## Run

```bash
../bin/server -config ../deploy/config.server.example.json
```

## Operator

Set the operator address, user, and PSK via environment variables or flags:

```bash
export C2_OPERATOR_ADDR=wss://c2-operator.example.com/ws
export C2_OPERATOR_SNI=c2-operator.example.com
export C2_OPERATOR_USER=ops
export C2_OPERATOR_PSK=base64:REPLACE_ME
../bin/operator list
```

Commands include `list`, `task`, `shell`, `push`, `pull`, `persist`, `kill`, and `stats`. See `--help`.

## Layout

- `cmd/server` — client and operator listeners, config, audit log
- `cmd/operator` — CLI operator, file transfer, task output decoding
- `internal/bdc2` — frame codec, crypto, WebSocket, hub, dialer
- `internal/...` — supporting packages

The server binds both listeners to loopback by default. Put a TLS/WebSocket reverse proxy in front; the example is in `../deploy/nginx/`.
