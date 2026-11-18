@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem Build + regression for the BDC2 v1 operator TUI.
rem Output: dist\c2tui.exe (Windows amd64) and dist\c2tui-linux-amd64.
rem Optional first argument = version string embedded in the binary.

set "VER=1.0.0"
if not "%~1"=="" set "VER=%~1"

echo [i] go test ./...
go test ./...
if errorlevel 1 (
  echo [x] tests failed
  exit /b 1
)

if not exist dist mkdir dist

set "CGO_ENABLED=0"

echo [i] building dist\c2tui.exe (windows/amd64)
set "GOOS=windows"
set "GOARCH=amd64"
go build -trimpath -ldflags "-s -w -X main.version=%VER%" -o dist\c2tui.exe .
if errorlevel 1 (
  echo [x] windows build failed
  exit /b 1
)

echo [i] building dist\c2tui-linux-amd64 (linux/amd64)
set "GOOS=linux"
set "GOARCH=amd64"
go build -trimpath -ldflags "-s -w -X main.version=%VER%" -o dist\c2tui-linux-amd64 .
if errorlevel 1 (
  echo [x] linux build failed
  exit /b 1
)

echo.
echo [ok] version %VER%
dir /b dist
exit /b 0
