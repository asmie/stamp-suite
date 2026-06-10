# Builder and runtime MUST share the same Debian release (glibc
# compatibility) — pin the distro suffix explicitly so a moving `slim`
# tag can't silently desynchronize them again.
FROM rust:1.93-slim-trixie AS builder

WORKDIR /usr/src/stamp-suite

# Install build dependencies for nix crate
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Production feature set for the container image: nix backend (real TTL
# capture, no privileges needed), Prometheus metrics, SNMP AgentX,
# kernel/hardware timestamping, and the runtime control-plane REST API.
ARG FEATURES="ttl-nix,metrics,snmp,hwtstamp,control"

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create stub targets to cache dependency builds. The manifest declares a
# lib, a bin, and the reflector_hotpath bench, so all three files must
# exist for cargo to parse it (benches are never compiled by
# `cargo build`, the stub just satisfies the manifest).
RUN mkdir -p src benches && \
    echo "fn main() {}" > src/main.rs && \
    echo "// stub for the dependency-caching stage" > src/lib.rs && \
    echo "fn main() {}" > benches/reflector_hotpath.rs && \
    cargo build --release --features "$FEATURES" && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Touch the entry points so cargo rebuilds the real code (not the cached stubs)
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --features "$FEATURES"

# Runtime stage — same Debian release as the builder (see note above).
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/stamp-suite/target/release/stamp-suite /usr/local/bin/stamp-suite

RUN setcap cap_net_bind_service=+ep /usr/local/bin/stamp-suite && \
    useradd --system --no-create-home --shell /usr/sbin/nologin stamp

USER stamp

# STAMP test packets (RFC 8762 / RFC 8545).
EXPOSE 862/udp
# Prometheus metrics endpoint (--metrics; bind --metrics-addr 0.0.0.0:9090
# to expose outside the container).
EXPOSE 9090/tcp
# Runtime control-plane REST API (--control). SECURITY: it manages HMAC
# keys and shutdown — keep it on the loopback default unless you publish
# it behind network-level access control and --control-token-file.
EXPOSE 9091/tcp

ENTRYPOINT ["stamp-suite"]
CMD ["-i", "--stateful-reflector"]
