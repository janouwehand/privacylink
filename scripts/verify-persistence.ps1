$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runRoot = Join-Path ([IO.Path]::GetTempPath()) ('privacylink-persistence-' + [Guid]::NewGuid().ToString('N'))
$blobPath = Join-Path $runRoot 'blobs'
$dumpPath = Join-Path $runRoot 'metadata.dump'
$blobArchive = Join-Path $runRoot 'blobs.zip'
$restoredBlobPath = Join-Path $runRoot 'restored-blobs'
$container = 'privacylink-postgres-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$apiProcess = $null
$apiProcess2 = $null
$oldConnection = $env:ConnectionStrings__PrivacyLink
$oldBlobPath = $env:Storage__BlobPath
$oldEnvironment = $env:ASPNETCORE_ENVIRONMENT
$oldCreateProofKey = $env:Security__CreateProofHmacKey
$oldCreateProofDifficulty = $env:Security__CreateProofDifficultyBits
$oldOpenProofDifficulty = $env:Security__OpenProofDifficultyBits

function Invoke-Docker([string[]] $Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed with exit code $LASTEXITCODE." }
}

function Stop-ApiProcessTree($Process) {
    if ($Process -and -not $Process.HasExited) {
        try { $Process.Kill($true) }
        catch { Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue }
        $Process.WaitForExit()
    }
}

function Get-OpenProof([string] $BaseUrl, [string] $SecretId) {
    $challenge = Invoke-RestMethod "$BaseUrl/api/v1/secrets/$SecretId/open-challenge" -Method Get
    $counter = [UInt64]0
    do {
        $proofText = "PrivacyLink-Open-PoW-v1:$($challenge.challengeId):${SecretId}:open:$($challenge.nonce):$counter"
        $digest = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($proofText))
        $counter++
        $zeroBits = 0
        foreach ($value in $digest) {
            if ($value -eq 0) { $zeroBits += 8; continue }
            $zeroBits += [System.Numerics.BitOperations]::LeadingZeroCount([uint32]$value) - 24
            break
        }
    } while ($zeroBits -lt $challenge.difficultyBits)
    return "$($challenge.challengeId).$($challenge.nonce).$($challenge.difficultyBits).$($challenge.expiresAt).$($challenge.signature).$($counter - 1)"
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
    $env:Security__CreateProofHmacKey = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $env:Security__CreateProofDifficultyBits = '1'
    $env:Security__OpenProofDifficultyBits = '1'
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

    $payload = @{ protocolVersion = 1; expiry = '1d'; message = @{ nonce = 'AAAAAAAAAAAAAAAA'; ciphertext = 'AAAAAAAAAAAAAAAAAAAAAAA' }; files = @(); oneTimeOpen = $true } | ConvertTo-Json -Compress
    $challenge = Invoke-RestMethod 'http://127.0.0.1:5089/api/v1/secrets/create-challenge' -Method Get
    $counter = [UInt64]0
    do {
        $proofText = "PrivacyLink-Create-PoW-v1:$($challenge.challengeId):$($challenge.nonce):$counter"
        $digest = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($proofText))
        $counter++
    } while (($digest[0] -band 0x80) -ne 0)
    $proof = "$($challenge.challengeId).$($challenge.nonce).$($challenge.difficultyBits).$($challenge.expiresAt).$($challenge.signature).$($counter - 1)"
    $created = Invoke-RestMethod 'http://127.0.0.1:5089/api/v1/secrets' -Method Post -ContentType 'application/json' -Headers @{ 'X-PrivacyLink-Proof' = $proof } -Body $payload
    if ([string]::IsNullOrWhiteSpace($created.id)) { throw 'API did not create a persistence test secret.' }

    # Keep a separate consumed fixture for restart/backup checks. The successful
    # open fixture below is expected to be deleted after its response is written.
    $challenge = Invoke-RestMethod 'http://127.0.0.1:5089/api/v1/secrets/create-challenge' -Method Get
    $counter = [UInt64]0
    do {
        $proofText = "PrivacyLink-Create-PoW-v1:$($challenge.challengeId):$($challenge.nonce):$counter"
        $digest = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($proofText))
        $counter++
    } while (($digest[0] -band 0x80) -ne 0)
    $proof = "$($challenge.challengeId).$($challenge.nonce).$($challenge.difficultyBits).$($challenge.expiresAt).$($challenge.signature).$($counter - 1)"
    $consumedFixture = Invoke-RestMethod 'http://127.0.0.1:5089/api/v1/secrets' -Method Post -ContentType 'application/json' -Headers @{ 'X-PrivacyLink-Proof' = $proof } -Body $payload
    if ([string]::IsNullOrWhiteSpace($consumedFixture.id)) { throw 'API did not create a consumed-state persistence fixture.' }

    $api2Log = Join-Path $runRoot 'api-2.log'
    $api2ErrorLog = Join-Path $runRoot 'api-2-error.log'
    $apiProcess2 = Start-Process dotnet -ArgumentList 'run --project src/PrivacyLink.Api/PrivacyLink.Api.csproj --no-launch-profile --urls http://127.0.0.1:5090' -WorkingDirectory $repoRoot -RedirectStandardOutput $api2Log -RedirectStandardError $api2ErrorLog -WindowStyle Hidden -PassThru
    $ready2 = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-WebRequest 'http://127.0.0.1:5090/health/ready' -UseBasicParsing
            if ($response.StatusCode -eq 200) { $ready2 = $true; break }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $ready2) { throw 'Second PrivacyLink API did not become ready against PostgreSQL.' }

    $httpClient = [System.Net.Http.HttpClient]::new()
    try {
        $openTasks = [System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]]::new()
        for ($index = 0; $index -lt 8; $index++) {
            $port = if ($index % 2 -eq 0) { 5089 } else { 5090 }
            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "http://127.0.0.1:$port/api/v1/secrets/$($created.id)/open")
            $request.Headers.Add('X-PrivacyLink-Proof', (Get-OpenProof "http://127.0.0.1:$port" $created.id))
            $openTasks.Add($httpClient.SendAsync($request))
        }
        $openResponses = $openTasks.ToArray()
        [System.Threading.Tasks.Task]::WaitAll($openResponses)
        $successes = @($openResponses | Where-Object { $_.Result.StatusCode -eq [System.Net.HttpStatusCode]::OK })
        $notFound = @($openResponses | Where-Object { $_.Result.StatusCode -eq [System.Net.HttpStatusCode]::NotFound })
        if ($successes.Count -ne 1 -or $notFound.Count -ne 7) {
            $codes = ($openResponses | ForEach-Object { [int]$_.Result.StatusCode }) -join ', '
            throw "Expected exactly one successful open across two API instances; got HTTP statuses: $codes."
        }
        $openedPayload = $successes[0].Result.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
        if ($openedPayload.protocolVersion -ne 1 -or $openedPayload.message.ciphertext -ne 'AAAAAAAAAAAAAAAAAAAAAAA') {
            throw 'The one-time open did not return the complete persisted message payload.'
        }

        $successfulMetadataStatus = $null
        try { Invoke-RestMethod "http://127.0.0.1:5090/api/v1/secrets/$($created.id)" -Method Get | Out-Null }
        catch { $successfulMetadataStatus = [int]$_.Exception.Response.StatusCode }
        if ($successfulMetadataStatus -ne 404) { throw 'Successfully delivered one-time content was not removed from the server.' }
        $markFixtureConsumed = & docker exec $container psql -U privacylink -d privacylink -tAc "UPDATE secrets SET opened_at = now() WHERE id = '$($consumedFixture.id)' AND one_time_open RETURNING id"
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($markFixtureConsumed)) { throw 'Could not mark the separate persistence fixture as consumed.' }
        Stop-ApiProcessTree $apiProcess
        Stop-ApiProcessTree $apiProcess2
        $apiProcess = $null
        $apiProcess2 = $null

        $restartLog = Join-Path $runRoot 'api-restart.log'
        $restartErrorLog = Join-Path $runRoot 'api-restart-error.log'
        $apiProcess = Start-Process dotnet -ArgumentList 'run --project src/PrivacyLink.Api/PrivacyLink.Api.csproj --no-launch-profile --urls http://127.0.0.1:5089' -WorkingDirectory $repoRoot -RedirectStandardOutput $restartLog -RedirectStandardError $restartErrorLog -WindowStyle Hidden -PassThru
        $restarted = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            try {
                $response = Invoke-WebRequest 'http://127.0.0.1:5089/health/ready' -UseBasicParsing
                if ($response.StatusCode -eq 200) { $restarted = $true; break }
            } catch { }
            Start-Sleep -Seconds 1
        }
        if (-not $restarted) { throw 'PrivacyLink API did not restart against the persisted PostgreSQL database.' }
        $restartedMetadata = Invoke-RestMethod "http://127.0.0.1:5089/api/v1/secrets/$($consumedFixture.id)" -Method Get
        if (-not $restartedMetadata.oneTimeOpened) { throw 'The one-time-open claim was lost after restarting the API.' }
        $restartedOpenRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, "http://127.0.0.1:5089/api/v1/secrets/$($consumedFixture.id)/open")
        $restartedOpenRequest.Headers.Add('X-PrivacyLink-Proof', (Get-OpenProof 'http://127.0.0.1:5089' $consumedFixture.id))
        $restartedOpenResponse = $httpClient.SendAsync($restartedOpenRequest).GetAwaiter().GetResult()
        if ($restartedOpenResponse.StatusCode -ne [System.Net.HttpStatusCode]::NotFound) {
            throw "The restarted API allowed a second open after the durable claim; got HTTP $([int]$restartedOpenResponse.StatusCode)."
        }
        $restartedOpenResponse.Dispose()
        $restartedOpenRequest.Dispose()
    }
    finally {
        $httpClient.Dispose()
    }

    $legacyStatsTables = (& docker exec $container psql -U privacylink -d privacylink -tAc "SELECT (to_regclass('public.stats_daily') IS NULL AND to_regclass('public.stats_visitors_daily') IS NULL)").Trim()
    if ($legacyStatsTables -ne 't') { throw 'Legacy statistics tables still exist after startup migrations.' }

    Invoke-Docker @('exec', $container, 'sh', '-c', 'pg_dump -U privacylink -Fc privacylink > /tmp/metadata.dump')
    Invoke-Docker @('cp', "${container}:/tmp/metadata.dump", $dumpPath)
    Compress-Archive -Path (Join-Path $blobPath '*') -DestinationPath $blobArchive -Force

    Invoke-Docker @('exec', $container, 'createdb', '-U', 'privacylink', 'restored')
    Invoke-Docker @('cp', $dumpPath, "${container}:/tmp/restore.dump")
    Invoke-Docker @('exec', $container, 'pg_restore', '-U', 'privacylink', '-d', 'restored', '/tmp/restore.dump')
    $restoredRows = (& docker exec $container psql -U privacylink -d restored -tAc 'SELECT COUNT(*) FROM secrets').Trim()
    if ($restoredRows -ne '1') { throw "Expected only the separate consumed fixture to remain after successful-delivery cleanup, got '$restoredRows' restored secrets." }
    $restoredClaims = (& docker exec $container psql -U privacylink -d restored -tAc 'SELECT COUNT(*) FROM secrets WHERE one_time_open AND opened_at IS NOT NULL').Trim()
    if ($restoredClaims -ne '1') { throw 'The consumed one-time-open state was not preserved in the PostgreSQL backup.' }

    Expand-Archive -Path $blobArchive -DestinationPath $restoredBlobPath -Force
    $originalHash = (Get-ChildItem $blobPath -Recurse -File | Get-FileHash -Algorithm SHA256 | Sort-Object Path | ForEach-Object Hash) -join ','
    $restoredHash = (Get-ChildItem $restoredBlobPath -Recurse -File | Get-FileHash -Algorithm SHA256 | Sort-Object Path | ForEach-Object Hash) -join ','
    if ($originalHash -ne $restoredHash) { throw 'Blob restore hash does not match the source blob set.' }

    Write-Host "PostgreSQL one-time-open concurrency, successful-delivery cleanup, restart, and backup/restore verification passed: successful delivery removed its secret; a separate consumed fixture remained unavailable after restart; $restoredRows metadata row and matching blob hash restored."
}
finally {
    Stop-ApiProcessTree $apiProcess
    Stop-ApiProcessTree $apiProcess2
    & docker rm -f $container *> $null
    $env:ConnectionStrings__PrivacyLink = $oldConnection
    $env:Storage__BlobPath = $oldBlobPath
    $env:ASPNETCORE_ENVIRONMENT = $oldEnvironment
    $env:Security__CreateProofHmacKey = $oldCreateProofKey
    $env:Security__CreateProofDifficultyBits = $oldCreateProofDifficulty
    $env:Security__OpenProofDifficultyBits = $oldOpenProofDifficulty
    if (Test-Path $runRoot) { Remove-Item -LiteralPath $runRoot -Recurse -Force }
}
