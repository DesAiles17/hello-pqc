#!/bin/bash
# Build all PQC Rust service images with shared Docker cache.

set -euo pipefail

export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

echo "Building API, hasher, and manifest service images..."
docker compose build api-gateway hasher-service manifest-builder-service

echo "Build complete."
