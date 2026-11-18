# tests/m0/run_loopback.ps1 — M0 loopback integration test (Windows PowerShell 5.1+)
#
# Exercises the full chain:
#   c2builder  ->  profile + client conf
#   c2server   ->  client listener + operator listener
#   c2client   ->  connects, hello, heartbeat, sysinfo/exec task handling
#   c2operator ->  login, list, sysinfo, exec(disabled), stats
#
# No external network is used. Everything listens on 127.0.0.1 with high ports.
# Logs land in tests/tmp/<timestamp>/.

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [int]$ClientPort = 19909,
    [int]$OperatorPort = 19910,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Continue'  # native tools write progress to stderr; exit codes are checked explicitly
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$tmp = Join-Path $root "tests\m0\tmp\$stamp"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$bin = Join-Path $root 'build\m0\bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null

$failures = New-Object System.Collections.Generic.List[string]
function Step($name) { Write-Host "`n=== $name ===" -ForegroundColor Cyan }
function Check($cond, $msg) {
    if ($cond) { Write-Host "  PASS: $msg" -ForegroundColor Green }
    else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures.Add($msg) }
}

$procs = @()
try {
    if (-not $SkipBuild) {
        Step 'build: cargo (offline) + go'
        Push-Location (Join-Path $root 'src\m0\client-rust')
        cmd /c "cargo build --offline 2>&1" | Tee-Object -FilePath (Join-Path $tmp 'cargo-build.log')
        Check ($LASTEXITCODE -eq 0) 'cargo build --offline'
        cmd /c "cargo test --offline 2>&1" | Tee-Object -FilePath (Join-Path $tmp 'cargo-test.log')
        Check ($LASTEXITCODE -eq 0) 'cargo test --offline'
        Pop-Location

        foreach ($m in @('server-go', 'operator-go', 'builder')) {
            Push-Location (Join-Path $root "src\m0\$m")
            go vet ./... 2>&1 | Tee-Object -FilePath (Join-Path $tmp "go-vet-$m.log")
            Check ($LASTEXITCODE -eq 0) "go vet ($m)"
            go test ./... 2>&1 | Tee-Object -FilePath (Join-Path $tmp "go-test-$m.log")
            # builder/operator have no tests yet; `go test` exits 0 with "no test files"
            Check ($LASTEXITCODE -eq 0) "go test ($m)"
            Pop-Location
        }

        Step 'build: binaries'
        Push-Location (Join-Path $root 'src\m0\client-rust')
        cmd /c "cargo build --release --offline 2>&1" | Tee-Object -FilePath (Join-Path $tmp 'cargo-release.log')
        Check ($LASTEXITCODE -eq 0) 'cargo build --release --offline'
        Pop-Location
        Copy-Item (Join-Path $root 'src\m0\client-rust\target\release\c2client.exe') (Join-Path $bin 'c2client.exe') -Force

        Push-Location (Join-Path $root 'src\m0\server-go');   go build -o (Join-Path $bin 'c2server.exe') . ; Check ($LASTEXITCODE -eq 0) 'go build c2server'; Pop-Location
        Push-Location (Join-Path $root 'src\m0\operator-go'); go build -o (Join-Path $bin 'c2operator.exe') . ; Check ($LASTEXITCODE -eq 0) 'go build c2operator'; Pop-Location
        Push-Location (Join-Path $root 'src\m0\builder');     go build -o (Join-Path $bin 'c2builder.exe') . ; Check ($LASTEXITCODE -eq 0) 'go build c2builder'; Pop-Location
    }

    $server = Join-Path $bin 'c2server.exe'
    $client = Join-Path $bin 'c2client.exe'
    $op     = Join-Path $bin 'c2operator.exe'
    $bld    = Join-Path $bin 'c2builder.exe'
    foreach ($f in @($server, $client, $op, $bld)) {
        if (-not (Test-Path $f)) { throw "missing binary: $f (run without -SkipBuild)" }
    }

    Step 'builder: generate loopback profile'
    & $bld --platform windows --arch amd64 --transport tcp --host 127.0.0.1 --port $ClientPort --name "test-loopback-$stamp" --out $tmp 2>&1 |
        Tee-Object -FilePath (Join-Path $tmp 'builder.log')
    Check ($LASTEXITCODE -eq 0) 'c2builder exit 0'
    $conf = Join-Path $tmp "test-loopback-$stamp.client.conf"
    Check (Test-Path $conf) 'builder wrote client conf'
    Check ((Get-Content $conf -Raw) -match "addr=127\.0\.0\.1:$ClientPort") 'profile contains loopback addr'

    Step 'server: start'
    $psk = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 } | ForEach-Object { [byte]$_ }))
    $env:C2_OPERATOR_PSK = $psk
    $env:C2_OPERATOR_USER = 'ops-test'
    $srvOut = Join-Path $tmp 'server.out.log'
    $srvErr = Join-Path $tmp 'server.err.log'
    $srv = Start-Process -FilePath $server -ArgumentList @('--client-addr', "127.0.0.1:$ClientPort", '--operator-addr', "127.0.0.1:$OperatorPort") `
        -RedirectStandardOutput $srvOut -RedirectStandardError $srvErr -NoNewWindow -PassThru
    $procs += $srv
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $t = New-Object System.Net.Sockets.TcpClient
            $t.Connect('127.0.0.1', $OperatorPort); $t.Close(); $ready = $true; break
        } catch { }
    }
    Check $ready 'operator listener accepting connections'
    if (-not $ready) { throw "server did not start; see $srvErr" }

    Step 'operator: login + empty list'
    $env:C2_OPERATOR_ADDR = "127.0.0.1:$OperatorPort"
    $emptyJson = & $op --json list 2>&1 | Out-String
    $emptyJson | Set-Content (Join-Path $tmp 'operator-list-empty.json')
    Check ($LASTEXITCODE -eq 0) 'operator list exit 0'
    $parsed = $emptyJson | ConvertFrom-Json
    Check ($parsed.ok -eq $true) 'operator authenticated (login_ack ok=true)'
    Check ([int]$parsed.count -eq 0) 'no sessions before client connects'

    Step 'client: connect via profile'
    $cliOut = Join-Path $tmp 'client.out.log'
    $cliErr = Join-Path $tmp 'client.err.log'
    $cli = Start-Process -FilePath $client -ArgumentList @('--profile', $conf) `
        -RedirectStandardOutput $cliOut -RedirectStandardError $cliErr -NoNewWindow -PassThru
    $procs += $cli

    $sessionId = $null
    for ($i = 0; $i -lt $TimeoutSec * 4; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $j = (& $op --json list 2>$null | Out-String) | ConvertFrom-Json
            if ([int]$j.count -ge 1) { $sessionId = $j.sessions[0].session_id; break }
        } catch { }
    }
    (& $op --json list 2>&1 | Out-String) | Set-Content (Join-Path $tmp 'operator-list-after-connect.json')
    Check ($null -ne $sessionId) "session registered (session_id=$sessionId)"
    if (-not $sessionId) { throw "client never registered; see $cliErr" }

    Step 'operator: sysinfo task'
    $sysinfo = (& $op --json sysinfo $sessionId 2>&1 | Out-String) | ConvertFrom-Json
    $sysinfo | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $tmp 'sysinfo.json')
    Check ($sysinfo.ok -eq $true) 'sysinfo reply received'
    Check ($sysinfo.result_ok -eq $true) 'client reports sysinfo ok'
    Check ($sysinfo.data -match 'os=' -and $sysinfo.data -match 'hostname=') 'sysinfo contains os/hostname'
    Write-Host "  data: $($sysinfo.data)"

    Step 'operator: ping task'
    $pingTask = (& $op --json task $sessionId ping 2>&1 | Out-String) | ConvertFrom-Json
    Check ($pingTask.result_ok -eq $true -and $pingTask.data -eq 'pong') 'ping -> pong'

    Step 'operator: exec must be denied (client default)'
    $exec = (& $op --json exec $sessionId 'echo should-not-run' 2>&1 | Out-String) | ConvertFrom-Json
    $exec | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $tmp 'exec-denied.json')
    Check ($exec.ok -eq $true) 'server accepted exec task'
    Check ($exec.result_ok -eq $false) 'client refused exec without --allow-exec'
    Check ($exec.err -match 'disabled') 'refusal reason mentions disabled'

    Step 'operator: stats'
    $stats = (& $op --json stats 2>&1 | Out-String) | ConvertFrom-Json
    Check ($stats.ok -eq $true -and [int]$stats.sessions -ge 1) 'stats shows >=1 session'

    Step 'client: --allow-exec positive path'
    $conf2 = Join-Path $tmp 'allow-exec.client.conf'
    ((Get-Content $conf -Raw) -replace 'allow_exec=false', 'allow_exec=true') | Set-Content $conf2 -NoNewline
    $cli2 = Start-Process -FilePath $client -ArgumentList @('--profile', $conf2, '--allow-exec') `
        -RedirectStandardOutput (Join-Path $tmp 'client2.out.log') `
        -RedirectStandardError (Join-Path $tmp 'client2.err.log') -NoNewWindow -PassThru
    $procs += $cli2
    $sid2 = $null
    for ($i = 0; $i -lt $TimeoutSec * 4; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $j2 = (& $op --json list 2>$null | Out-String) | ConvertFrom-Json
            $other = @($j2.sessions | Where-Object { $_.session_id -ne $sessionId })
            if ($other.Count -ge 1) { $sid2 = $other[0].session_id; break }
        } catch { }
    }
    Check ($null -ne $sid2) "second session registered (session_id=$sid2)"
    if ($sid2) {
        $execOk = (& $op --json exec $sid2 'echo M0-EXEC-OK' 2>&1 | Out-String) | ConvertFrom-Json
        $execOk | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $tmp 'exec-allowed.json')
        Check ($execOk.result_ok -eq $true) 'exec allowed on --allow-exec client'
        Check ($execOk.data -match 'M0-EXEC-OK') 'exec output captured'
    }
    $cli2 | Stop-Process -Force -ErrorAction SilentlyContinue

    Step 'reconnect: second client with same id replaces first'
    # (skipped in M0: client id is unique per profile; replacement logic covered by unit test)

    Step 'teardown'
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "logs: $tmp"
}
catch {
    Write-Host "`nERROR: $_" -ForegroundColor Red
    $failures.Add("exception: $_")
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}
finally {
    Remove-Item Env:C2_OPERATOR_PSK -ErrorAction SilentlyContinue
    Remove-Item Env:C2_OPERATOR_USER -ErrorAction SilentlyContinue
    Remove-Item Env:C2_OPERATOR_ADDR -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host "`nFAILED ($($failures.Count)):" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "`nALL CHECKS PASSED" -ForegroundColor Green
exit 0
