//! TDX attestation support for TEE oracle registration.
//!
//! At startup, stores the oracle's Ethereum address. On each `GET /attestation`
//! request, generates a fresh TDX DCAP quote with the address in `reportData`.
//!
//! Uses **dstack** (`/var/run/dstack.sock`) — Phala's Docker-native TDX framework.
//! dstack extends RTMR[3] with the compose-hash (SHA256 of docker-compose.yaml),
//! binding the exact application image to the attestation.
//!
//! Returns 503 if not running inside dstack (dev mode).

use std::path::Path;
use std::sync::OnceLock;

use alloy::primitives::Address;
use axum::{http::StatusCode, response::IntoResponse};
use dstack_sdk::tappd_client::TappdClient;
use tracing::{error, info, warn};

/// Oracle address bound at startup, embedded in every generated quote.
static ORACLE_ADDRESS: OnceLock<Address> = OnceLock::new();

/// dstack socket paths (present inside dstack CVMs).
const DSTACK_SOCKET: &str = "/var/run/dstack.sock";
const TAPPD_SOCKET: &str = "/var/run/tappd.sock";

/// Check if running inside a dstack CVM.
pub fn is_tdx_available() -> bool {
    Path::new(DSTACK_SOCKET).exists() || Path::new(TAPPD_SOCKET).exists()
}

/// Store the oracle's Ethereum address for attestation quote generation.
///
/// dstack embeds report_data at quote generation time. This just stores the address.
///
/// No-op if not running inside dstack (dev mode).
pub fn bind_oracle_address(oracle_address: Address) {
    if !is_tdx_available() {
        warn!(
            "dstack not available — skipping attestation binding (address={})",
            oracle_address
        );
    }

    ORACLE_ADDRESS.set(oracle_address).unwrap_or_else(|_| {
        warn!("Oracle address already bound (ignoring duplicate call)");
    });

    info!(
        "TDX: bound oracle address {} (dstack={})",
        oracle_address,
        is_tdx_available()
    );
}

/// GET /attestation — generate and return a fresh TDX DCAP quote.
///
/// The quote contains the VM's identity (MRTD + RTMR[3]) and the oracle address
/// in reportData. Callers submit this quote to `JJSKIN.registerOracle()` for
/// on-chain verification.
///
/// Returns 503 if not running inside dstack.
pub async fn attestation_handler() -> impl IntoResponse {
    let address = match ORACLE_ADDRESS.get() {
        Some(addr) => *addr,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Oracle address not bound",
            )
                .into_response();
        }
    };

    match generate_tdx_quote(&address).await {
        Ok(quote_bytes) => {
            info!("TDX: serving DCAP quote ({} bytes)", quote_bytes.len());
            (
                StatusCode::OK,
                [("content-type", "application/octet-stream")],
                quote_bytes,
            )
                .into_response()
        }
        Err(e) => {
            error!("TDX: failed to generate quote: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate TDX quote: {e}"),
            )
                .into_response()
        }
    }
}

/// Generate a TDX DCAP quote via dstack with the oracle address in reportData.
async fn generate_tdx_quote(address: &Address) -> eyre::Result<Vec<u8>> {
    if !is_tdx_available() {
        return Err(eyre::eyre!(
            "dstack not available (no {DSTACK_SOCKET} — not running in dstack CVM)"
        ));
    }

    let mut report_data = vec![0u8; 64];
    report_data[..20].copy_from_slice(address.as_ref());

    let client = TappdClient::new(None);
    let resp = client
        .get_quote(report_data)
        .await
        .map_err(|e| eyre::eyre!("dstack get_quote failed: {e}"))?;

    let quote = resp
        .decode_quote()
        .map_err(|e| eyre::eyre!("Failed to decode quote hex: {e}"))?;

    info!("TDX: generated quote via dstack ({} bytes)", quote.len());
    Ok(quote)
}
