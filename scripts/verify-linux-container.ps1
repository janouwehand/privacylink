$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$imageTag = 'privacylinkslim:linux-aot-smoke'
$containerName = "privacylinkslim-smoke-$PID"

Push-Location $repoRoot
try {
    & docker build --pull --tag $imageTag .
    if ($LASTEXITCODE -ne 0) { throw "Linux production image build failed with exit code $LASTEXITCODE." }

    $randomBytes = New-Object byte[] 32
    $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $randomNumberGenerator.GetBytes($randomBytes)
        $createProofHmacKey = [Convert]::ToBase64String($randomBytes)
    } finally {
        $randomNumberGenerator.Dispose()
    }

    & docker run --detach --name $containerName --publish '127.0.0.1::8080' `
        --env 'ASPNETCORE_ENVIRONMENT=Development' `
        --env 'ASPNETCORE_URLS=http://+:8080' `
        --env ("Security__CreateProofHmacKey=" + $createProofHmacKey) `
        --env 'Security__CreateProofDifficultyBits=1' `
        $imageTag
    if ($LASTEXITCODE -ne 0) { throw "Linux production image failed to start with exit code $LASTEXITCODE." }

    $portMatch = [regex]::Match('', ':(\d+)$')
    $portError = ''
    for ($attempt = 0; $attempt -lt 20 -and -not $portMatch.Success; $attempt++) {
        $portOutput = & docker port $containerName '8080/tcp' 2>&1
        if ($LASTEXITCODE -eq 0) {
            $portMapping = $portOutput | Select-Object -First 1
            if ($portMapping) { $portMatch = [regex]::Match($portMapping.Trim(), ':(\d+)$') }
        } else {
            $portError = $portOutput -join [Environment]::NewLine
        }
        if (-not $portMatch.Success) { Start-Sleep -Milliseconds 250 }
    }
    if (-not $portMatch.Success) {
        $containerState = & docker inspect --format '{{.State.Status}}' $containerName 2>$null
        $logs = & docker logs $containerName 2>&1
        throw "Docker returned an unexpected port mapping: $portMapping. Last port lookup: $portError. Container state: $containerState.`n$($logs -join [Environment]::NewLine)"
    }

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
