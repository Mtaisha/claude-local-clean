param(
    [switch]$NoBrowser,
    [ValidateRange(1024, 65535)]
    [int]$Port = 8190
)

$ErrorActionPreference = "Stop"
$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$baseUrl = "http://127.0.0.1:$Port"
$serverPath = Join-Path $baseDir "server.py"
$mutex = [System.Threading.Mutex]::new($false, "Local\ClaudeLocalCleanLaunch-$Port")
$ownsMutex = $false

function Test-LocalConsole {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -DisableKeepAlive -Uri "$baseUrl/api/config" -TimeoutSec 2
        return $response.StatusCode -eq 200
    }
    catch {
        return $false
    }
}

function Find-Python3 {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $python) {
        return $python.Source
    }

    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $launcher) {
        $resolved = & $launcher.Source -3 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $resolved) {
            return ($resolved | Select-Object -First 1).Trim()
        }
    }
    return $null
}

try {
    try {
        $ownsMutex = $mutex.WaitOne(15000)
    }
    catch [System.Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (-not $ownsMutex) {
        throw "Another launch is still in progress."
    }

    if (Test-LocalConsole) {
        Write-Host "Claude Local Clean is already running at $baseUrl"
        if (-not $NoBrowser) {
            Start-Process $baseUrl
        }
        exit 0
    }

    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $listener) {
        throw "Port $Port is already used by process $($listener.OwningProcess)."
    }

    $pythonExe = Find-Python3
    if (-not $pythonExe) {
        throw "Python 3 was not found. Install Python 3 and run clean.bat again."
    }

    Write-Host "Starting Claude Local Clean..."
    $quotedServerPath = '"' + $serverPath.Replace('"', '\"') + '"'
    $process = Start-Process -FilePath $pythonExe `
        -ArgumentList @($quotedServerPath, "--port", $Port) `
        -WorkingDirectory $baseDir `
        -NoNewWindow `
        -PassThru

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 300
        if (Test-LocalConsole) {
            Write-Host "Open $baseUrl"
            Write-Host "Keep this window open. Close it to stop the local console."
            if (-not $NoBrowser) {
                Start-Process $baseUrl
            }
            $mutex.ReleaseMutex()
            $ownsMutex = $false
            $process.WaitForExit()
            exit $process.ExitCode
        }
        if ($process.HasExited) {
            throw "The local server exited with code $($process.ExitCode)."
        }
    }
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw "Claude Local Clean did not become ready in time."
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
