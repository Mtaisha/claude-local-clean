param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8190
)

$ErrorActionPreference = "Stop"
$baseUrl = "http://127.0.0.1:$Port"

try {
    $config = Invoke-RestMethod -Uri "$baseUrl/api/config" -TimeoutSec 2
    $headers = @{ "X-Cleanup-Token" = $config.csrf_token }
    $body = @{ confirmation = "STOP_LOCAL_SERVER" } | ConvertTo-Json -Compress
    Invoke-RestMethod `
        -Uri "$baseUrl/api/shutdown" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body `
        -TimeoutSec 3 | Out-Null
    exit 0
}
catch {
    exit 1
}
