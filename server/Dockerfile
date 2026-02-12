# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY server/Cargo.toml ./

# Copy proto files
COPY proto /proto

# Copy build script
COPY server/build.rs ./

# Create dummy src for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY server/src ./src
COPY server/migrations ./migrations

# Build application
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (including curl for healthcheck)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/orafinite-api /app/orafinite-api

# Copy migrations
COPY --from=builder /app/migrations /app/migrations

# Set environment
ENV RUST_LOG=orafinite_api=info,tower_http=info

EXPOSE 8080

CMD ["/app/orafinite-api"]
