use eyre::{Result, eyre};
use futures_util::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tracing::info;

use tlsn::{
    config::verifier::VerifierConfig,
    connection::ServerName,
    transcript::ContentType,
    verifier::VerifierOutput,
    Session,
};

use crate::settlement::{oracle, EscrowSnapshot, OracleSigner, SettlementResult};

// ============================================================================
// MPC-TLS Result
// ============================================================================

/// Bundles MPC-TLS output needed by settlement.
pub struct MpcTlsResult {
    pub server_name: Option<ServerName>,
    pub sent_bytes: Vec<u8>,
    pub recv_bytes: Vec<u8>,
}

// ============================================================================
// Step 1: Run MPC-TLS Protocol
// ============================================================================

/// Run MPC-TLS, extract plaintext, return result + reclaimed socket.
pub async fn run_mpc_tls<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: S,
    verifier_config: VerifierConfig,
) -> Result<(MpcTlsResult, S)> {
    info!("Starting MPC-TLS session");

    let session = Session::new(socket);
    let (driver, mut handle) = session.split();

    let driver_task = tokio::spawn(driver);

    info!("Running MPC-TLS verifier protocol");

    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(|e| eyre!("Failed to create verifier: {}", e))?
        .commit()
        .await
        .map_err(|e| eyre!("Commitment failed: {}", e))?;

    let verifier = verifier
        .accept()
        .await
        .map_err(|e| eyre!("Accept failed: {}", e))?;

    let verifier = verifier
        .run()
        .await
        .map_err(|e| eyre!("MPC-TLS run failed: {}", e))?;

    info!("MPC-TLS protocol complete, verifying transcript");

    let verifier = verifier
        .verify()
        .await
        .map_err(|e| eyre!("Verification failed: {}", e))?;

    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier
        .accept()
        .await
        .map_err(|e| eyre!("Accept verification failed: {}", e))?;

    let tls_transcript = verifier.tls_transcript();

    // Extract plaintext from MPC-verified transcript
    let (sent_bytes, recv_bytes) = match transcript {
        Some(ref t) => (t.sent_unsafe().to_vec(), t.received_unsafe().to_vec()),
        None => (Vec::new(), Vec::new()),
    };

    // Log transcript lengths
    let sent_len: usize = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| match record.typ {
            ContentType::ApplicationData => Some(record.ciphertext.len()),
            _ => None,
        })
        .sum();

    let recv_len: usize = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| match record.typ {
            ContentType::ApplicationData => Some(record.ciphertext.len()),
            _ => None,
        })
        .sum();

    info!(
        "Transcript: sent={} bytes, recv={} bytes, plaintext_sent={}, plaintext_recv={}",
        sent_len,
        recv_len,
        sent_bytes.len(),
        recv_bytes.len()
    );

    if let Some(ref name) = server_name {
        info!("Server name: {}", name);
    }

    // Close verifier
    verifier
        .close()
        .await
        .map_err(|e| eyre!("Failed to close verifier: {}", e))?;

    // Close session and reclaim socket
    handle.close();
    let socket = driver_task
        .await
        .map_err(|e| eyre!("Driver task failed: {}", e))?
        .map_err(|e| eyre!("Session driver error: {}", e))?;

    let result = MpcTlsResult {
        server_name,
        sent_bytes,
        recv_bytes,
    };

    Ok((result, socket))
}

// ============================================================================
// Step 2: Post-MPC Settlement (single verifier path)
// ============================================================================

/// Handle post-MPC settlement: decide using MPC-verified plaintext, sign EIP-712.
///
/// Wire protocol (server → prover only):
///   result_len(u64) | bincode(SettlementResult)
///
/// The prover sends nothing — the server already has MPC-verified plaintext.
pub async fn handle_post_protocol<S: AsyncRead + AsyncWrite + Unpin>(
    mpc: &MpcTlsResult,
    socket: &mut S,
    escrow: &EscrowSnapshot,
    signer: &OracleSigner,
) -> Result<()> {
    // Use MPC-verified plaintext directly (NOT prover-sent data)
    let server_name_str = mpc
        .server_name
        .as_ref()
        .map(|sn| sn.to_string())
        .unwrap_or_default();

    info!(
        "Settlement: server={}, sent={} bytes, recv={} bytes",
        server_name_str,
        mpc.sent_bytes.len(),
        mpc.recv_bytes.len()
    );

    let settlement = oracle::decide(&server_name_str, &mpc.sent_bytes, &mpc.recv_bytes, escrow)
        .map_err(|e| eyre!("Settlement decision failed: {e}"))?;

    info!(
        "Decision: asset_id={}, decision={:?}, refund_reason={:?}",
        settlement.asset_id, settlement.decision, settlement.refund_reason
    );

    let signature = signer
        .sign_settlement(&settlement)
        .await
        .map_err(|e| eyre!("EIP-712 signing failed: {e}"))?;

    info!(
        "Signed settlement: sig=0x{}",
        hex::encode(&signature)
    );

    let wire_result = SettlementResult {
        signature,
        asset_id: settlement.asset_id,
        decision: settlement.decision as u8,
        refund_reason: settlement.refund_reason as u8,
    };

    let result_bytes =
        bincode::serialize(&wire_result).map_err(|e| eyre!("Failed to serialize result: {e}"))?;

    // Send: result_len(u64) | result_bytes
    socket
        .write_all(&(result_bytes.len() as u64).to_le_bytes())
        .await
        .map_err(|e| eyre!("Failed to send result length: {e}"))?;
    socket
        .write_all(&result_bytes)
        .await
        .map_err(|e| eyre!("Failed to send result: {e}"))?;
    socket
        .flush()
        .await
        .map_err(|e| eyre!("Failed to flush: {e}"))?;

    info!(
        "Settlement result sent ({} bytes): asset_id={}, decision={:?}",
        result_bytes.len(),
        settlement.asset_id,
        settlement.decision
    );

    Ok(())
}
