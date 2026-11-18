@echo off
cd /d "%~dp0"
set "MBEDTLS_INC="
set "MBEDTLS_LIB="
if not "%MBEDTLS_PREFIX%"=="" (
    set "MBEDTLS_INC=-I%MBEDTLS_PREFIX%\include"
    set "MBEDTLS_LIB=-L%MBEDTLS_PREFIX%\lib"
)
gcc -O2 -s -static -static-libgcc -D_WIN32_WINNT=0x0600 -DWINVER=0x0600 ^
    %MBEDTLS_INC% tlsbridge.c -o tlsbridge.exe ^
    %MBEDTLS_LIB% -lmbedtls -lmbedx509 -lmbedcrypto -lws2_32 -ladvapi32 -liphlpapi -lbcrypt
if errorlevel 1 exit /b 1
echo built tlsbridge.exe