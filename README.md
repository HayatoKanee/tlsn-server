# tlsn-server

A standalone [TLSNotary](https://tlsnotary.org/) Notary Server for **alpha 14**.

Built on [tlsnotary/tlsn](https://github.com/tlsnotary/tlsn) `v0.1.0-alpha.14`.

TLSNotary removed the `notary-server` crate in alpha 13 and archived `tlsn-js`. This project provides a lightweight notary server that implements the MPC-TLS co-computation and attestation signing protocol.

## What it does

1. **MPC-TLS co-computation** — participates in the TLS handshake as the verifier (MPC counterparty)
2. **Attestation signing** — signs transcript commitments with a secp256k1 key, producing a portable `Attestation`
3. The prover then builds a `Presentation` from `Attestation + Secrets` — this is the serializable proof

## Protocol Flow

```
Prover (WASM/Extension)              Notary Server
─────────────────────                ────────────────
1. POST /session                   → Create session, return sessionId
2. WS /notarize?sessionId=xxx      → WebSocket upgrade
3. MPC-TLS protocol                ←→ Verifier protocol (commit → accept → run → verify)
4. Send AttestationRequest         → Receive over reclaimed socket
5. Receive signed Attestation      ← Sign with secp256k1 key, send back
```

## Quick Start

```bash
# Build
cargo build --release

# Run with default config (ephemeral signing key)
./target/release/tlsn-server

# Run with custom config
./target/release/tlsn-server --config config.yaml
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (returns "ok") |
| GET | `/info` | Server version + notary public key |
| POST | `/session` | Create a notarization session |
| GET | `/notarize?sessionId=xxx` | WebSocket for notarization |
| GET | `/proxy?token=host:port` | WebSocket-to-TCP proxy (for browser clients) |

### POST /session

Request:
```json
{
  "maxSentData": 4096,
  "maxRecvData": 16384
}
```

Response:
```json
{
  "sessionId": "uuid-v4"
}
```

### GET /info

Response:
```json
{
  "version": "0.1.0",
  "publicKey": "hex-encoded-secp256k1-pubkey",
  "gitHash": "dev"
}
```

## Configuration

See `config.yaml`:

```yaml
host: "0.0.0.0"
port: 7047

notarization:
  max_sent_data: 4096
  max_recv_data: 16384
  timeout: 120
  private_key_pem_path: null  # null = ephemeral key

tls:
  enabled: false
```

## Docker

### Pre-built image (Docker Hub)

```bash
docker pull lumio1/tlsn-server:v0.1.0-alpha.14
docker run -p 7047:7047 lumio1/tlsn-server:v0.1.0-alpha.14
```

With a custom config:

```bash
docker run -p 7047:7047 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  lumio1/tlsn-server:v0.1.0-alpha.14 \
  --config /app/config.yaml
```

With a persistent signing key:

```bash
docker run -p 7047:7047 \
  -v $(pwd)/notary.pem:/app/notary.pem \
  -v $(pwd)/config.yaml:/app/config.yaml \
  lumio1/tlsn-server:v0.1.0-alpha.14 \
  --config /app/config.yaml
```

### Build from source

```bash
docker build -t tlsn-server .
docker run -p 7047:7047 tlsn-server
```

## Signing Key

By default, an ephemeral secp256k1 key is generated on startup. For production, provide a persistent key:

1. Generate a key: `openssl ecparam -name secp256k1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out notary.pem`
2. Set `notarization.private_key_pem_path: "/path/to/notary.pem"` in config
3. The public key is exposed via `/info` for provers to verify attestations

## Testing

```bash
cargo test -- --nocapture
```

The integration test runs a full MPC-TLS notarization round-trip using the official `tlsn-server-fixture` (self-signed TLS server from the tlsn repo). It validates that the notary correctly participates in the protocol, signs attestations, and produces output that the prover can verify.

## Architecture

```
src/
├── main.rs      # Axum server, routes, session management
├── notary.rs    # Core notarization (MPC-TLS + attestation signing)
├── signing.rs   # secp256k1 key management
├── proxy.rs     # WebSocket-to-TCP proxy for browser clients
├── config.rs    # YAML configuration
└── lib.rs       # Library exports for integration tests
tests/
└── notarize_integration.rs  # Full round-trip integration test
```

## License

MIT OR Apache-2.0
