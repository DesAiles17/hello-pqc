# syntax=docker/dockerfile:1.4

############################
# Chef stage (cargo-chef)  #
############################
FROM rust:bookworm AS chef
WORKDIR /app

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef --locked --version 0.1.67


############################
# Planner stage            #
############################
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src/main.rs ./src/main.rs
COPY src/lib.rs ./src/lib.rs
COPY src/bin ./src/bin
RUN cargo chef prepare --recipe-path recipe.json


############################
# Builder stage            #
############################
FROM chef AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

COPY --from=planner /app/recipe.json /app/recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo chef cook --release --recipe-path /app/recipe.json

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    --bin api-gateway \
    --bin hasher-service \
    --bin manifest-builder-service && \
    mkdir -p /app/bin && \
    cp /app/target/release/api-gateway /app/bin/api-gateway && \
    cp /app/target/release/hasher-service /app/bin/hasher-service && \
    cp /app/target/release/manifest-builder-service /app/bin/manifest-builder-service


############################
# Runtime base stage       #
############################
FROM debian:bookworm-slim AS runtime-base
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 pqcuser && \
    useradd  -r -u 1000 -g pqcuser -m -s /sbin/nologin pqcuser && \
    mkdir -p /app /data/uploads /tmp/pqc && \
    chown -R pqcuser:pqcuser /app /data /tmp/pqc

USER pqcuser


############################
# Runtime targets          #
############################
FROM runtime-base AS runtime-api-gateway
COPY --from=builder --chmod=0755 /app/bin/api-gateway /app/api-gateway
EXPOSE 3000
CMD ["./api-gateway"]

FROM runtime-base AS runtime-hasher-service
COPY --from=builder --chmod=0755 /app/bin/hasher-service /app/hasher-service
EXPOSE 3001
CMD ["./hasher-service"]

FROM runtime-base AS runtime-manifest-builder-service
COPY --from=builder --chmod=0755 /app/bin/manifest-builder-service /app/manifest-builder-service
EXPOSE 3002
CMD ["./manifest-builder-service"]
