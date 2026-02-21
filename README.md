# jjskin-oracle

TDX oracle for the [JJSKIN](https://jjskin.com) CS2 skin marketplace. Runs MPC-TLS verification and settlement decisions inside an Intel TDX confidential VM, so neither the operator nor the hosting provider can tamper with trade outcomes.

Built on [TLSNotary](https://github.com/tlsnotary/tlsn) `v0.1.0-alpha.14` and deployed via [dstack](https://github.com/aspect-build/dstack) (Phala Network).

## How it works

1. **MPC-TLS** — The oracle co-computes the TLS session with the prover (browser extension). Neither party sees the other's share of the key material.
2. **Settlement** — After the TLS session, the oracle parses the authenticated Steam API response and decides Release or Refund based on trade state.
3. **EIP-712 signing** — The decision is signed with the oracle's Ethereum key. Anyone can submit it on-chain.
4. **TDX attestation** — The entire binary runs inside Intel TDX. A DCAP quote proves the exact code (MRTD) and Docker image (RTMR[3]) that produced the signature.

## Modules

```
src/
  main.rs                  Axum server, routes, session lifecycle
  config.rs                YAML + env configuration
  verifier.rs              MPC-TLS protocol + post-protocol settlement
  attestation.rs           TDX DCAP quote generation via dstack
  proxy.rs                 WebSocket-to-TCP proxy for browser clients
  settlement/
    oracle.rs              Core decision engine (3 proof paths)
    parsing.rs             HTTP/JSON/HTML parsing for Steam responses
    types.rs               EscrowSnapshot, Decision, RefundReason, Settlement
    decision.rs            Fault attribution (expired, canceled, declined)
    signer.rs              EIP-712 typed-data signing
    chain_reader.rs        On-chain escrow reads (Arbitrum)
  inspect/
    bot_pool.rs            Steam bot pool with proxy rotation
    gc_client.rs           CS2 Game Coordinator protocol client
    cache.rs               In-memory inspect result cache
    link_parser.rs         Steam inspect link parser (S/M/A/D params)
    item_detail.rs         Protobuf encoding for item details
    types.rs               Inspect request/response types
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (`"ok"`) |
| GET | `/info` | Version, oracle address, TDX status |
| GET | `/attestation` | Fresh TDX DCAP quote (binary) |
| POST | `/session` | Create MPC-TLS session (requires `assetId` query param) |
| GET | `/notarize` | WebSocket MPC-TLS session |
| GET | `/proxy` | WebSocket-to-TCP proxy for browser provers |
| GET | `/inspect` | CS2 item inspection (float, paint seed, stickers) |
| POST | `/inspect/bulk` | Bulk inspection (up to 100 items) |

## Settlement decision logic

Three proof paths, each targeting a different Steam endpoint:

| Proof source | Endpoint verified | Can Release? | Can Refund? |
|---|---|---|---|
| `GetTradeOffer` | `api.steampowered.com/IEconService/GetTradeOffer` | No | Yes (expired, canceled, declined) |
| `GetTradeStatus` | `api.steampowered.com/IEconService/GetTradeStatus` | Yes (status 3 + escrow passed) | Yes (status 4-12 rollback) |
| `Community HTML` | `steamcommunity.com/tradeoffer/<id>` | No | Yes (trade abandonment, 24h wait) |

## Docker image

The production image is published to Docker Hub:

```
lumio1/jjskin-oracle
```

The `docker-compose.yaml` in this repo pins the image by SHA256 digest. dstack hashes this file into RTMR[3], binding the exact image to the TDX attestation.

### Build from source

```bash
docker build -t jjskin-oracle .
```

### Run locally (no TDX)

```bash
docker run -p 7047:7047 jjskin-oracle
```

The `/attestation` endpoint returns 503 outside TDX. All other endpoints work normally.

## Verify the oracle

Anyone can verify that the oracle is running the expected code inside TDX:

### 1. Get the attestation quote

```bash
curl -s https://<oracle-host>:7047/attestation -o quote.bin
```

### 2. Extract measurements

```python
with open('quote.bin', 'rb') as f:
    data = f.read()

# TDX Quote v4, TD Report Body v1.5
mrtd = data[184:232]           # 48 bytes — hash of the TD (binary measurement)
rtmr3 = data[520:568]          # 48 bytes — dstack compose-hash extension
oracle_addr = data[568:588]    # 20 bytes — oracle's Ethereum address

print(f'MRTD:    {mrtd.hex()}')
print(f'RTMR[3]: {rtmr3.hex()}')
print(f'Oracle:  0x{oracle_addr.hex()}')
```

### 3. Verify RTMR[3] matches docker-compose.yaml

```bash
# The compose-hash is SHA256(docker-compose.yaml)
sha256sum docker-compose.yaml

# dstack extends RTMR[3] with this hash at boot.
# The on-chain verifier checks: keccak256(RTMR3_48_bytes)
```

### 4. Verify on-chain

The JJSKIN smart contract verifies the DCAP quote via Automata's on-chain verifier and checks:

- **MRTD** matches the registered measurement (`keccak256(mrtd_48_bytes)`)
- **RTMR[3]** matches the registered compose-hash (`keccak256(rtmr3_48_bytes)`)
- **reportData[0:20]** is the oracle's Ethereum address (registered as authorized signer)

```bash
# Check if an oracle is registered
cast call <JJSKIN_ADDRESS> "oracles(address)(bool)" <ORACLE_ADDRESS> --rpc-url <RPC>
```

## Configuration

```yaml
host: "0.0.0.0"
port: 7047

notarization:
  max_sent_data: 4096
  max_recv_data: 16384
  timeout: 120

oracle:
  contract_address: "0x..."
  chain_id: 421614
  rpc_url: "https://sepolia-rollup.arbitrum.io/rpc"

inspect:
  bots_config_path: "bots.json"
  cache_ttl_secs: 300
```

The oracle signing key is derived deterministically inside dstack using `TappdClient::derive_key()`, so no private key is stored or configured.

## Build & test

```bash
cargo build --release
cargo test
```

## License

MIT OR Apache-2.0
