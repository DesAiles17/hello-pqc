#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$PWD")}"
POSTGRES_VOLUME="${PROJECT_NAME}_postgres-data"

echo "Resetting PostgreSQL volume for project: ${PROJECT_NAME}"
echo "Target volume: ${POSTGRES_VOLUME}"
echo ""

docker compose down

if docker volume inspect "${POSTGRES_VOLUME}" >/dev/null 2>&1; then
  docker volume rm "${POSTGRES_VOLUME}"
else
  echo "⚠️  Volume ${POSTGRES_VOLUME} not found; skipping removal"
fi

docker compose up -d --force-recreate

echo ""
echo "✅ Database reset complete"
docker compose ps
