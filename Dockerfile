# Build stage
FROM rust:1.91-bookworm AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY Cargo.toml Cargo.lock ./
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

# Create default config
RUN echo '[server]\nrealm = "miuturn"\nexternal_ip = "0.0.0.0"\nstart_port = 49152\nend_port = 65535\n\n[[server.listening]]\nprotocol = "udp"\naddress = "0.0.0.0:3478"\n\n[[server.listening]]\nprotocol = "tcp"\naddress = "0.0.0.0:3478"\n\n[http]\naddress = "0.0.0.0:8080"\n\n[[auth.users]]\nusername = "admin"\npassword = "changeme"\nuser_type = "Fixed"\nmax_allocations = 10\n\n[[auth.acl_rules]]\nip_range = "0.0.0.0/0"\naction = "Allow"\npriority = 0' > /app/miuturn.toml

# Expose ports
# TURN UDP/TCP
EXPOSE 3478/tcp 3478/udp
# Admin HTTP
EXPOSE 8080/tcp
# TURN relay port range
EXPOSE 49152-65535/tcp 49152-65535/udp

ENV CONFIG=/app/miuturn.toml

ENTRYPOINT ["miuturn"]
