$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('privacylink-persistence-' + [Guid]::NewGuid().ToString('N'))
$blobPath = Join-Path $runRoot 'blobs'
$dumpPath = Join-Path $runRoot 'metadata.dump'
$blobArchive = Join-Path $runRoot 'blobs.zip'
$restoredBlobPath = Join-Path $runRoot 'restored-blobs'
$container = 'privacylink-postgres-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$apiProcess = $null
$oldConnection = $env:ConnectionStrings__PrivacyLink
$oldBlobPath = $env:Storage__BlobPath
$oldEnvironment = $env:ASPNETCORE_ENVIRONMENT
$oldAnalyticsKey = $env:Analytics__Key

function Invoke-Docker([string[]] $Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed with exit code $LASTEXITCODE." }
}

try {
    New-Item -ItemType Directory -Path $blobPath, $restoredBlobPath -Force | Out-Null
    Invoke-Docker @('run', '-d', '--name', $container, '-e', 'POSTGRES_PASSWORD=persistence-test-only', '-e', 'POSTGRES_USER=privacylink', '-e', 'POSTGRES_DB=privacylink', '-p', '127.0.0.1::5432', 'postgres:16-alpine')
    $mapping = (& docker port $container 5432/tcp).Trim()
    if ($mapping -notmatch ':(\d+)$') { throw "Could not resolve the temporary PostgreSQL host port from '$mapping'." }
    $hostPort = $Matches[1]

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & docker exec $container pg_isready -U privacylink -d privacylink *> $null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 1
    }
    if ($LASTEXITCODE -ne 0) { throw 'Temporary PostgreSQL did not become ready.' }

    $env:ConnectionStrings__PrivacyLink = "Host=127.0.0.1;Port=$hostPort;Database=privacylink;Username=privacylink;Password=persistence-test-only"
    $env:Storage__BlobPath = $blobPath
    $env:ASPNETCORE_ENVIRONMENT = 'Development'
    $analyticsKeyBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($analyticsKeyBytes)
    $env:Analytics__Key = [Convert]::ToBase64String($analyticsKeyBytes)
    [Array]::Clear($analyticsKeyBytes, 0, $analyticsKeyBytes.Length)
    $apiLog = Join-Path $runRoot 'api.log'
    $apiErrorLog = Join-Path $runRoot 'api-error.log'
    $apiProcess = Start-Process dotnet -ArgumentList 'run --project src/PrivacyLink.Api/PrivacyLink.Api.csproj --no-launch-profile --urls http://127.0.0.1:5089' -WorkingDirectory $repoRoot -RedirectStandardOutput $apiLog -RedirectStandardError $apiErrorLog -WindowStyle Hidden -PassThru

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-WebRequest 'http://127.0.0.1:5089/health/ready' -UseBasicParsing
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'PrivacyLink API did not become ready against PostgreSQL.' }

    $payload = @{ protocolVersion = 1; expiry = '1d'; message = @{ nonce = 'AAAAAAAAAAAAAAAA'; ciphertext = 'AAAAAAAAAAAAAAAAAAAAAAA' }; files = @() } | ConvertTo-Json -Compress
    $created = Invoke-RestMethod 'http://127.0.0.1:5089/api/v1/secrets' -Method Post -ContentType 'application/json' -Body $payload
    if ([string]::IsNullOrWhiteSpace($created.id)) { throw 'API did not create a persistence test secret.' }

    $creationCount = (& docker exec $container psql -U privacylink -d privacylink -tAc "SELECT COALESCE(SUM(count), 0) FROM stats_daily WHERE day = (NOW() AT TIME ZONE 'UTC')::date AND metric = 'creations' AND dimension = '' AND dimension_value = ''").Trim()
    if ($creationCount -ne '1') { throw "Expected one committed creation statistic, got '$creationCount'." }
    $visitorCount = (& docker exec $container psql -U privacylink -d privacylink -tAc "SELECT COUNT(*) FROM stats_visitors_daily WHERE day = (NOW() AT TIME ZONE 'UTC')::date").Trim()
    if ($visitorCount -ne '1') { throw "Expected one daily HMAC visitor row, got '$visitorCount'." }
    $visitorHashLength = (& docker exec $container psql -U privacylink -d privacylink -tAc "SELECT MIN(octet_length(visitor_hmac)) FROM stats_visitors_daily WHERE day = (NOW() AT TIME ZONE 'UTC')::date").Trim()
    if ($visitorHashLength -ne '32') { throw "Expected a 32-byte visitor HMAC, got '$visitorHashLength'." }

    Invoke-Docker @('exec', $container, 'sh', '-c', 'pg_dump -U privacylink -Fc privacylink > /tmp/metadata.dump')
    Invoke-Docker @('cp', "${container}:/tmp/metadata.dump", $dumpPath)
    Compress-Archive -Path (Join-Path $blobPath '*') -DestinationPath $blobArchive -Force

    Invoke-Docker @('exec', $container, 'createdb', '-U', 'privacylink', 'restored')
    Invoke-Docker @('cp', $dumpPath, "${container}:/tmp/restore.dump")
    Invoke-Docker @('exec', $container, 'pg_restore', '-U', 'privacylink', '-d', 'restored', '/tmp/restore.dump')
    $restoredRows = (& docker exec $container psql -U privacylink -d restored -tAc 'SELECT COUNT(*) FROM secrets').Trim()
    if ($restoredRows -ne '1') { throw "Expected one restored secret, got '$restoredRows'." }

    Expand-Archive -Path $blobArchive -DestinationPath $restoredBlobPath -Force
    $originalHash = (Get-ChildItem $blobPath -Recurse -File | Get-FileHash -Algorithm SHA256 | Sort-Object Path | ForEach-Object Hash) -join ','
    $restoredHash = (Get-ChildItem $restoredBlobPath -Recurse -File | Get-FileHash -Algorithm SHA256 | Sort-Object Path | ForEach-Object Hash) -join ','
    if ($originalHash -ne $restoredHash) { throw 'Blob restore hash does not match the source blob set.' }

    Write-Host "Persistence backup/restore verification passed: $restoredRows metadata row and matching blob hash."
}
finally {
    if ($apiProcess -and -not $apiProcess.HasExited) { Stop-Process -Id $apiProcess.Id -Force }
    & docker rm -f $container *> $null
    $env:ConnectionStrings__PrivacyLink = $oldConnection
    $env:Storage__BlobPath = $oldBlobPath
    $env:ASPNETCORE_ENVIRONMENT = $oldEnvironment
    $env:Analytics__Key = $oldAnalyticsKey
    if (Test-Path $runRoot) { Remove-Item -LiteralPath $runRoot -Recurse -Force }
}
