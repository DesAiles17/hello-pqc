#!/bin/bash
# Optimized Docker build script for PQC Honours Project
# This script enables BuildKit and uses the build profile for fast, cache-friendly builds.

set -e

# Enable Docker BuildKit for better caching
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

echo "🚀 Building Docker image with optimized caching..."
echo "   Using cargo-chef + BuildKit cache"
echo ""

# Build only the build-profile image (don't run it)
docker compose --profile build build pqc-build

echo ""
echo "✅ Build complete!"
echo ""
