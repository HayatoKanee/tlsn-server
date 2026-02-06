FROM rust:1.83 AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/tlsn-server /usr/local/bin/
COPY config.yaml /etc/tlsn-server/
EXPOSE 7047
CMD ["tlsn-server", "--config", "/etc/tlsn-server/config.yaml"]
