# Tests

These Python tests exercise the server, protocol, and client in a loopback lab.

Expected layout when running the end-to-end tests:

```text
verify/
  server.exe
  backd-client.exe
```

Build them first:

```bash
cd server && go build -o ../verify/server.exe ./cmd/server
cd ../client && build.cmd
cp out/backd-client.exe ../verify/backd-client.exe
```

Run:

```bash
python tests/run_all.py --clients 20
```

`test_operator_wss.py` uses a self-signed certificate for a documentation-only hostname. It does not contact the public Internet.

Do not point these tests at production systems.
