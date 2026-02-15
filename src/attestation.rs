//! TDX attestation support for TEE oracle registration.
//!
//! At startup, stores the oracle's Ethereum address. On each `GET /attestation`
//! request, generates a fresh TDX DCAP quote with the address in `reportData`.
//!
//! Supports two backends (auto-detected at runtime):
//! 1. **Linux TSM configfs** (`/sys/kernel/config/tsm/report/`) — kernel 6.7+
//! 2. **Azure IMDS** (`/dev/tdx_guest` ioctl + IMDS quote signing) — Azure DCesv5
//!
//! Returns 503 if not running inside a TDX VM (dev mode).

use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::OnceLock;

use alloy::primitives::Address;
use axum::{http::StatusCode, response::IntoResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use tracing::{error, info, warn};

/// Oracle address bound at startup, embedded in every generated quote.
static ORACLE_ADDRESS: OnceLock<Address> = OnceLock::new();

/// Linux TSM configfs path (kernel 6.7+).
const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

/// TDX guest device (available on all TDX VMs).
const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";

/// Azure IMDS endpoint that signs a TD report into a DCAP quote.
const AZURE_IMDS_QUOTE_URL: &str = "http://169.254.169.254/acc/tdquote";

/// TDX_CMD_GET_REPORT0 ioctl number for x86_64 Linux.
/// `_IOWR('T', 1, struct tdx_report_req)` where struct is 1088 bytes (64 + 1024).
const TDX_CMD_GET_REPORT0: libc::c_ulong = 0xC4405401;

/// TDX attestation backend.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TdxBackend {
    /// Linux TSM configfs — write inblob, read outblob (kernel 6.7+).
    Configfs,
    /// Azure: get TD report via /dev/tdx_guest ioctl, sign via IMDS.
    AzureImds,
    /// Not running in TDX (dev mode).
    None,
}

/// Detect which TDX attestation backend is available.
pub fn detect_tdx_backend() -> TdxBackend {
    if Path::new(TSM_REPORT_PATH).exists() {
        TdxBackend::Configfs
    } else if Path::new(TDX_GUEST_DEVICE).exists() {
        TdxBackend::AzureImds
    } else {
        TdxBackend::None
    }
}

/// Check if running inside a TDX VM.
pub fn is_tdx_available() -> bool {
    !matches!(detect_tdx_backend(), TdxBackend::None)
}

/// Store the oracle's Ethereum address for attestation quote generation.
///
/// Unlike SGX (which binds report_data once at startup via Gramine pseudo-fs),
/// TDX embeds report_data at quote generation time. This just stores the address.
///
/// No-op if not running inside TDX (dev mode).
pub fn bind_oracle_address(oracle_address: Address) {
    let backend = detect_tdx_backend();
    if matches!(backend, TdxBackend::None) {
        warn!(
            "TDX not available — skipping attestation binding (address={})",
            oracle_address
        );
    }

    ORACLE_ADDRESS.set(oracle_address).unwrap_or_else(|_| {
        warn!("Oracle address already bound (ignoring duplicate call)");
    });

    info!(
        "TDX: bound oracle address {} (backend={:?})",
        oracle_address, backend
    );
}

/// GET /attestation — generate and return a fresh TDX DCAP quote.
///
/// The quote contains the VM's identity (MRTD) and the oracle address in
/// reportData. Callers submit this quote to `JJSKIN.registerOracle()` for
/// on-chain verification.
///
/// Returns 503 if not running inside TDX.
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

/// Generate a TDX DCAP quote with the oracle address in reportData.
async fn generate_tdx_quote(address: &Address) -> eyre::Result<Vec<u8>> {
    let mut report_data = [0u8; 64];
    report_data[..20].copy_from_slice(address.as_ref());

    match detect_tdx_backend() {
        TdxBackend::Configfs => generate_quote_configfs(&report_data),
        TdxBackend::AzureImds => generate_quote_azure_imds(&report_data).await,
        TdxBackend::None => Err(eyre::eyre!(
            "TDX attestation not available (not running in TDX VM)"
        )),
    }
}

// =============================================================================
// Backend: Linux TSM configfs (kernel 6.7+)
// =============================================================================

/// Generate a quote via the Linux TSM configfs interface.
///
/// 1. Create entry directory under `/sys/kernel/config/tsm/report/`
/// 2. Write 64-byte report_data to `inblob`
/// 3. Read the full DCAP quote from `outblob`
/// 4. Clean up the entry directory
fn generate_quote_configfs(report_data: &[u8; 64]) -> eyre::Result<Vec<u8>> {
    let entry_name = format!("oracle-{}", std::process::id());
    let entry_path = format!("{TSM_REPORT_PATH}/{entry_name}");

    // Clean up any stale entry from a previous crash
    let _ = std::fs::remove_dir(&entry_path);

    std::fs::create_dir(&entry_path)
        .map_err(|e| eyre::eyre!("Failed to create TSM report entry '{entry_path}': {e}"))?;

    // Write report_data → triggers quote generation on outblob read
    let inblob_path = format!("{entry_path}/inblob");
    if let Err(e) = std::fs::write(&inblob_path, report_data) {
        let _ = std::fs::remove_dir(&entry_path);
        return Err(eyre::eyre!("Failed to write inblob: {e}"));
    }

    // Read the full DCAP quote
    let outblob_path = format!("{entry_path}/outblob");
    let quote = match std::fs::read(&outblob_path) {
        Ok(q) => q,
        Err(e) => {
            let _ = std::fs::remove_dir(&entry_path);
            return Err(eyre::eyre!("Failed to read outblob: {e}"));
        }
    };

    // Clean up
    let _ = std::fs::remove_dir(&entry_path);

    info!(
        "TDX: generated quote via configfs ({} bytes)",
        quote.len()
    );
    Ok(quote)
}

// =============================================================================
// Backend: Azure IMDS (/dev/tdx_guest + IMDS)
// =============================================================================

/// Azure IMDS quote response.
#[derive(Deserialize)]
struct ImdsQuoteResponse {
    quote: String,
}

/// Generate a quote via Azure IMDS.
///
/// 1. Get a TD report with custom report_data via `/dev/tdx_guest` ioctl
/// 2. Send the TD report to Azure IMDS to get a signed DCAP quote
async fn generate_quote_azure_imds(report_data: &[u8; 64]) -> eyre::Result<Vec<u8>> {
    // Step 1: Get TD report from hardware with our report_data
    let td_report = get_td_report(report_data)?;

    // Step 2: Send TD report to Azure IMDS for signing
    let client = reqwest::Client::new();
    let response = client
        .post(AZURE_IMDS_QUOTE_URL)
        .json(&serde_json::json!({
            "report": URL_SAFE_NO_PAD.encode(&td_report)
        }))
        .send()
        .await
        .map_err(|e| eyre::eyre!("Azure IMDS request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(eyre::eyre!(
            "Azure IMDS returned {status}: {body}"
        ));
    }

    let resp: ImdsQuoteResponse = response
        .json()
        .await
        .map_err(|e| eyre::eyre!("Failed to parse IMDS response: {e}"))?;

    let quote = URL_SAFE_NO_PAD
        .decode(&resp.quote)
        .map_err(|e| eyre::eyre!("Failed to decode IMDS quote: {e}"))?;

    info!(
        "TDX: generated quote via Azure IMDS ({} bytes)",
        quote.len()
    );
    Ok(quote)
}

/// Request layout for TDX_CMD_GET_REPORT0 ioctl.
#[repr(C)]
struct TdxReportReq {
    /// Input: 64 bytes of custom data embedded in the TD report.
    report_data: [u8; 64],
    /// Output: 1024-byte TD report.
    td_report: [u8; 1024],
}

/// Get a TD report with custom report_data via `/dev/tdx_guest` ioctl.
fn get_td_report(report_data: &[u8; 64]) -> eyre::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_GUEST_DEVICE)
        .map_err(|e| eyre::eyre!("Failed to open {TDX_GUEST_DEVICE}: {e}"))?;

    let mut req = TdxReportReq {
        report_data: *report_data,
        td_report: [0u8; 1024],
    };

    let ret =
        unsafe { libc::ioctl(file.as_raw_fd(), TDX_CMD_GET_REPORT0, &mut req as *mut _) };
    if ret != 0 {
        return Err(eyre::eyre!(
            "TDX_CMD_GET_REPORT0 ioctl failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(req.td_report.to_vec())
}
