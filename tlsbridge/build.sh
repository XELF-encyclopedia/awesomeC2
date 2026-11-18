#!/bin/bash
set -e
cd "$(dirname "$0")"
CFLAGS="${CFLAGS:-}"
LDFLAGS="${LDFLAGS:-}"
if [ -n "${MBEDTLS_PREFIX:-}" ]; then
  CFLAGS="$CFLAGS -I${MBEDTLS_PREFIX}/include"
  LDFLAGS="$LDFLAGS -L${MBEDTLS_PREFIX}/lib"
fi
${CC:-x86_64-w64-mingw32-gcc} -O2 -s -static -static-libgcc \
    -D_WIN32_WINNT=0x0600 -DWINVER=0x0600 $CFLAGS \
    tlsbridge.c -o tlsbridge.exe $LDFLAGS \
    -lmbedtls -lmbedx509 -lmbedcrypto -lws2_32 -ladvapi32 -liphlpapi -lbcrypt
ls -l tlsbridge.exe