# Build stage
FROM rust:1.91-bookworm AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source (including .git so build.rs can stamp the commit hash)
COPY Cargo.toml ./
COPY build.rs ./
COPY .git ./.git
COPY miuturn.toml.example ./miuturn.toml
COPY src ./src
COPY static ./static

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/miuturn /usr/local/bin/miuturn

# Copy static files
COPY --from=builder /app/static ./static
COPY --from=builder /app/miuturn.toml ./miuturn.toml

ENV CONFIG=/app/miuturn.toml

ENTRYPOINT ["miuturn"]
