$ErrorActionPreference = 'Stop'
$headersPath = Join-Path $PSScriptRoot '..\src\PrivacyLink.Web\public\_headers'
$headers = Get-Content -LiteralPath $headersPath -Raw
foreach ($required in @('strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'cache-control')) {
    if ($headers -notmatch "(?im)^\s*$([regex]::Escape($required))\s*:") { throw "Missing static hosting header: $required" }
}
if ($headers -notmatch '(?im)^\s*/\*\s*$') { throw 'Static hosting profile has no global rule.' }
Write-Host 'Static hosting header profile passed.'
