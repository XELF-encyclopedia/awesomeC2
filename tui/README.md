# c2tui

A terminal UI for the operator channel.

## Build

```bash
go build -o c2tui.exe .
```

## Run

Set the operator environment variables used by the CLI:

```bat
set C2_OPERATOR_ADDR=wss://c2-operator.example.com/ws
set C2_OPERATOR_SNI=c2-operator.example.com
set C2_OPERATOR_USER=ops
set C2_OPERATOR_PSK=base64:REPLACE_ME
c2tui.exe
```

The TUI keeps its own config file; do not commit a config containing a real PSK. Add the config filename to `.gitignore` if you create one locally.

## Notes

- The TUI uses the same BDC2 v1 protocol and operator PSK as the CLI.
- Output is decoded as UTF-8, UTF-16, then GBK, with a hex fallback.
- Press `q`/`Ctrl-C` to exit; see the in-app help for key bindings.
