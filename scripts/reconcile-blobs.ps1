[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)][string]$ConnectionString,
    [Parameter(Mandatory = $true)][string]$BlobPath,
    [switch]$DeleteOrphans
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $BlobPath -PathType Container)) { throw "Blob path does not exist: $BlobPath" }
$rows = & psql $ConnectionString -At -F '|' -c "SELECT id, COALESCE(blob_id, '') FROM secrets"
if ($LASTEXITCODE -ne 0) { throw 'Could not read PostgreSQL blob references.' }
$references = [Collections.Generic.List[object]]::new()
foreach ($row in $rows) {
    $parts = $row -split '\|', 2
    if ($parts.Length -eq 2 -and $parts[1]) { $references.Add([pscustomobject]@{ SecretId = $parts[0]; BlobId = $parts[1] }) }
}
$fileRows = & psql $ConnectionString -At -F '|' -c "SELECT id, files_json FROM secrets"
if ($LASTEXITCODE -ne 0) { throw 'Could not read PostgreSQL file references.' }
foreach ($row in $fileRows) {
    $parts = $row -split '\|', 2
    if ($parts.Length -ne 2 -or -not $parts[1]) { continue }
    foreach ($file in ($parts[1] | ConvertFrom-Json)) {
        if ($file.blobId) { $references.Add([pscustomobject]@{ SecretId = $parts[0]; BlobId = $file.blobId }) }
    }
}
$relative = Get-ChildItem -LiteralPath $BlobPath -Recurse -File |
    Where-Object { $_.Name -notlike '*.tmp-*' } |
    ForEach-Object { $_.FullName.Substring($BlobPath.TrimEnd('\').Length + 1).Replace('\', '/') }
$referenced = $references | ForEach-Object { "$($_.SecretId)/$($_.BlobId)" }
$orphans = $relative | Where-Object { $referenced -notcontains $_ } | Sort-Object
Write-Host "Referenced blobs: $($referenced.Count); candidate orphans: $($orphans.Count)"
foreach ($orphan in $orphans) {
    $fullPath = Join-Path $BlobPath ($orphan -replace '/', [IO.Path]::DirectorySeparatorChar)
    if ($DeleteOrphans) {
        if ($PSCmdlet.ShouldProcess($fullPath, 'Delete orphan blob')) { Remove-Item -LiteralPath $fullPath -Force }
    } else { Write-Host "DRY-RUN orphan: $orphan" }
}
