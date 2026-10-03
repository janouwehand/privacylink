$ErrorActionPreference = 'Stop'

$webRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\src\PrivacyLink.Web')).Path
$outputPath = Join-Path $webRoot '.container-dist'

docker run --rm `
  -v "${webRoot}:/workspace" `
  -w /workspace `
  node:24.18-bookworm `
  bash -lc 'rm -rf /tmp/privacy-link-web && mkdir /tmp/privacy-link-web && cp package.json package-lock.json angular.json tsconfig*.json /tmp/privacy-link-web/ && cp -R src public /tmp/privacy-link-web/ && cd /tmp/privacy-link-web && npm ci --ignore-scripts --no-audit --no-fund && npx ng build --configuration production --output-path=/workspace/.container-dist'

if ($LASTEXITCODE -ne 0) {
    throw "Containerized Angular production build failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path (Join-Path $outputPath 'index.html')) -and -not (Test-Path (Join-Path $outputPath 'browser\index.html'))) {
    throw "Containerized Angular production build did not produce index.html."
}

Write-Host "Angular production bundle written to $outputPath"
