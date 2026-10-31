$ErrorActionPreference = 'Stop'

$webRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\src\PrivacyLink.Web')).Path
$clientRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\src\PrivacyLink.Client')).Path
$outputPath = Join-Path $webRoot '.container-dist'

docker run --rm `
  -v "${webRoot}:/workspace/src/PrivacyLink.Web" `
  -v "${clientRoot}:/workspace/src/PrivacyLink.Client:ro" `
  -w /workspace/src/PrivacyLink.Web `
  node:24.18-bookworm `
  bash -lc 'rm -rf /tmp/privacy-link && mkdir -p /tmp/privacy-link/src/PrivacyLink.Web /tmp/privacy-link/src/PrivacyLink.Client && cp package.json package-lock.json angular.json tsconfig*.json /tmp/privacy-link/src/PrivacyLink.Web/ && cp -R src public /tmp/privacy-link/src/PrivacyLink.Web/ && cp -R /workspace/src/PrivacyLink.Client/src /tmp/privacy-link/src/PrivacyLink.Client/ && cd /tmp/privacy-link/src/PrivacyLink.Web && npm ci --ignore-scripts --no-audit --no-fund && npx ng build --configuration production --output-path=/workspace/src/PrivacyLink.Web/.container-dist'

if ($LASTEXITCODE -ne 0) {
    throw "Containerized Angular production build failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path (Join-Path $outputPath 'index.html')) -and -not (Test-Path (Join-Path $outputPath 'browser\index.html'))) {
    throw "Containerized Angular production build did not produce index.html."
}

Write-Host "Angular production bundle written to $outputPath"
