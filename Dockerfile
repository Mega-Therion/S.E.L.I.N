FROM rust:1.88-slim AS builder

# bundled-sqlcipher-vendored-openssl vendors its own OpenSSL build, which needs
# a full C toolchain + perl (FindBin) to run Configure. rust:*-slim ships neither.
RUN apt-get update && apt-get install -y \
    build-essential \
    perl \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN cargo build --release -p selin

# ── runtime image ──────────────────────────────────────────────────────────────
# Pin to a specific digest so the image is reproducible and supply-chain attacks
# via a mutable `bookworm-slim` tag are blocked.  Update by running:
#   docker pull debian:bookworm-slim
#   docker inspect debian:bookworm-slim --format '{{index .RepoDigests 0}}'
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user: selin runs as uid 10001.
RUN groupadd --gid 10001 selin && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /sbin/nologin selin

WORKDIR /app
COPY --from=builder /app/target/release/selin /app/selin

# Data directory owned by the selin user; mounted as a volume in docker-compose.
RUN mkdir -p /data/selin && chown selin:selin /data/selin
ENV HOME=/data/selin

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -fsS http://localhost:8080/health || exit 1

USER selin

ENTRYPOINT ["/app/selin"]
# Containers must bind 0.0.0.0; an ARCHON_API_KEY must be set in docker-compose.
CMD ["serve", "--bind", "0.0.0.0", "--port", "8080"]
