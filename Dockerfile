FROM rust:1.93-slim AS builder

WORKDIR /usr/src/stamp-suite

# Install build dependencies for nix crate
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main to cache dependency builds
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    cargo build --release --features ttl-nix && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Touch main.rs so cargo rebuilds it (not the cached dummy)
RUN touch src/main.rs && \
    cargo build --release --features ttl-nix

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/stamp-suite/target/release/stamp-suite /usr/local/bin/stamp-suite

RUN setcap cap_net_bind_service=+ep /usr/local/bin/stamp-suite && \
    useradd --system --no-create-home --shell /usr/sbin/nologin stamp

USER stamp

EXPOSE 862/udp

ENTRYPOINT ["stamp-suite"]
CMD ["-i", "--stateful-reflector"]
