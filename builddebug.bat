$env:ASPNETCORE_ENVIRONMENT = "Development"

docker compose up --build -d
docker compose ps
docker compose logs -f app
