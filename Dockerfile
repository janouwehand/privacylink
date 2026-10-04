FROM node:24.18-bookworm AS web-build
WORKDIR /src

COPY src/PrivacyLink.Web/package.json src/PrivacyLink.Web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY src/PrivacyLink.Web/ ./
RUN npm run build -- --configuration production

FROM mcr.microsoft.com/dotnet/sdk:10.0-aot AS api-build
WORKDIR /src

COPY global.json PrivacyLink.slnx ./
COPY src/PrivacyLink.Contracts/ src/PrivacyLink.Contracts/
COPY src/PrivacyLink.Api/ src/PrivacyLink.Api/
RUN dotnet restore src/PrivacyLink.Api/PrivacyLink.Api.csproj
RUN dotnet publish src/PrivacyLink.Api/PrivacyLink.Api.csproj \
    --configuration Release \
    --framework net10.0 \
    --runtime linux-x64 \
    --self-contained true \
    -p:PublishAot=true \
    -p:PublishAotUsingRuntimePack=true \
    -p:StripSymbols=true \
    --output /out
RUN mkdir -p /out/data/blobs

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled AS runtime
WORKDIR /app

LABEL org.opencontainers.image.source="https://github.com/janouwehand/privacylink"

COPY --from=api-build --chown=1654:1654 /out/ ./
COPY --from=web-build --chown=1654:1654 /src/dist/privacy-link-web/browser/ ./wwwroot/

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER 1654
ENTRYPOINT ["/app/PrivacyLink.Api"]

