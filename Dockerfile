# syntax=docker/dockerfile:1.4

############################
# Chef stage (cargo-chef)  #
############################
FROM rust:bookworm AS chef
WORKDIR /app

# Cache the cargo-chef install itself so cold builds are less painful.
# --locked keeps it reproducible (uses Cargo.lock inside the crate).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef --locked --version 0.1.67


############################
# Planner stage            #
############################
FROM chef AS planner
# Keep this minimal: it improves cache stability.
COPY Cargo.toml Cargo.lock ./
COPY src/main.rs ./src/main.rs
COPY src/lib.rs ./src/lib.rs
COPY src/bin ./src/bin
RUN cargo chef prepare --recipe-path recipe.json


############################
# Builder stage            #
############################
FROM chef AS builder

# System deps required by aws-lc-sys / ring / etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

# 1) Build deps only (cached unless Cargo.toml/Cargo.lock/recipe changes)
COPY --from=planner /app/recipe.json /app/recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path /app/recipe.json

# 2) Build the actual binaries (cached per-target and per-registry)
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release \
    --bin api-gateway \
    --bin hasher-service \
    --bin manifest-builder-service && \
    mkdir -p /app/bin && \
    cp /app/target/release/api-gateway /app/bin/api-gateway && \
    cp /app/target/release/hasher-service /app/bin/hasher-service && \
    cp /app/target/release/manifest-builder-service /app/bin/manifest-builder-service


############################
# Runtime stage            #
############################
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Runtime deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# SECURITY: Create non-root user with fixed UID/GID (matches your compose user: 1000:1000)
RUN groupadd -r -g 1000 pqcuser && \
    useradd  -r -u 1000 -g pqcuser -m -s /sbin/nologin pqcuser && \
    mkdir -p /app /data/uploads /tmp/pqc && \
    chown -R pqcuser:pqcuser /app /data /tmp/pqc

# Copy binaries explicitly to their final paths (less brittle than COPY ... ./)
COPY --from=builder /app/bin/api-gateway /app/api-gateway
COPY --from=builder /app/bin/hasher-service /app/hasher-service
COPY --from=builder /app/bin/manifest-builder-service /app/manifest-builder-service

# Ensure executability (normally preserved, but explicit is safer across environments)
RUN chmod 0755 /app/api-gateway /app/hasher-service /app/manifest-builder-service

USER pqcuser

EXPOSE 3000 3001 3002

# Default command (docker-compose overrides this per service)
CMD ["./api-gateway"]
