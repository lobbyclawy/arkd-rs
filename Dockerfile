# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM rust:slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy full workspace for build
COPY . .

# Build the release binary
RUN cargo build --release --bin arkd

# =============================================================================
# Stage 2: Runtime — distroless for minimal CVE surface
# =============================================================================
FROM gcr.io/distroless/cc-debian12 AS runtime

# Copy TLS certificates for HTTPS support
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the release binary
COPY --from=builder /build/target/release/arkd /usr/local/bin/arkd

# Default configuration
ENV RUST_LOG=info
ENV ARKD_CONFIG=/etc/arkd/config.toml

# Expose ports
EXPOSE 7070 7071 8080 9090

ENTRYPOINT ["/usr/local/bin/arkd"]
