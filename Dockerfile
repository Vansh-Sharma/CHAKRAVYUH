# Build stage
FROM rust:1.75-slim AS builder

RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true && rm -rf src

COPY . .
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y tini ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd -r chakravyuh -g 10001 && useradd -r -g chakravyuh -u 10001 chakravyuh

COPY --from=builder /app/target/release/chakravyuh /usr/local/bin/
COPY --from=builder /app/configs/config.example.yaml /etc/chakravyuh/config.yaml

RUN mkdir -p /etc/chakravyuh/tls /var/lib/chakravyuh
RUN chown -R chakravyuh:chakravyuh /etc/chakravyuh /var/lib/chakravyuh

EXPOSE 8443
USER chakravyuh

ENTRYPOINT ["tini", "--"]
CMD ["chakravyuh", "serve", "--config", "/etc/chakravyuh/config.yaml"]
