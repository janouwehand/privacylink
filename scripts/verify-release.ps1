$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repoRoot
try {
    dotnet restore PrivacyLink.slnx
    dotnet build PrivacyLink.slnx --no-restore
    dotnet test PrivacyLink.slnx --no-restore
    dotnet publish src/PrivacyLink.Api/PrivacyLink.Api.csproj -c Release -r win-x64 --self-contained true -p:PublishAot=true -p:PublishAotUsingRuntimePack=true --no-restore
    & (Join-Path $PSScriptRoot 'validate-hosting.ps1')
    Push-Location (Join-Path $repoRoot 'src\PrivacyLink.Web')
    try {
        npm ci --ignore-scripts --no-audit --no-fund
        npm test -- --no-watch --no-progress
        npm run build:container
    } finally { Pop-Location }
    & (Join-Path $PSScriptRoot 'verify-linux-container.ps1')
    Write-Host 'PrivacyLink release gates passed. No deployment was performed.'
} finally { Pop-Location }
