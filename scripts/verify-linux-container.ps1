$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$imageTag = 'privacylinkslim:linux-aot-smoke'
$containerName = "privacylinkslim-smoke-$PID"

Push-Location $repoRoot
try {
    & docker build --pull --tag $imageTag .
    if ($LASTEXITCODE -ne 0) { throw "Linux production image build failed with exit code $LASTEXITCODE." }

    & docker run --detach --name $containerName --publish '127.0.0.1::8080' `
        --env 'ASPNETCORE_ENVIRONMENT=Development' `
        --env 'ASPNETCORE_URLS=http://+:8080' `
        $imageTag
    if ($LASTEXITCODE -ne 0) { throw "Linux production image failed to start with exit code $LASTEXITCODE." }

    $portMapping = (& docker port $containerName '8080/tcp' | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine the published smoke-test port.' }
    $portMatch = [regex]::Match($portMapping.Trim(), ':(\d+)$')
    if (-not $portMatch.Success) { throw "Docker returned an unexpected port mapping: $portMapping" }

    $healthUri = "http://127.0.0.1:$($portMatch.Groups[1].Value)/health"
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $health = Invoke-RestMethod -Uri $healthUri -TimeoutSec 2
            if ($health.status -eq 'ok') {
                $healthy = $true
                break
            }
        } catch {
            # The app may still be starting; check the container before retrying.
        }

        $running = (& docker inspect --format '{{.State.Running}}' $containerName 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -ne 0 -or $running.Trim() -ne 'true') {
            $logs = & docker logs $containerName 2>&1
            throw "Linux AOT container exited before /health became available.`n$($logs -join [Environment]::NewLine)"
        }
        Start-Sleep -Seconds 2
    }

    if (-not $healthy) {
        $logs = & docker logs $containerName 2>&1
        throw "Linux AOT container did not return healthy status from /health.`n$($logs -join [Environment]::NewLine)"
    }

    Write-Host 'Linux Native AOT production image built, started, and returned healthy status from /health.'
} finally {
    try { & docker rm --force $containerName 2>$null | Out-Null } catch { }
    Pop-Location
}
