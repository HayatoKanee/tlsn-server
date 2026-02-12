use eyre::{Result, eyre};
use futures_util::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::info;

use tlsn::{
    attestation::{
        request::Request as AttestationRequest, Attestation, AttestationConfig, CryptoProvider,
    },
    config::verifier::VerifierConfig,
    connection::{ConnectionInfo, ServerName, TranscriptLength},
    transcript::{ContentType, TranscriptCommitment, TlsTranscript},
    verifier::VerifierOutput,
    Session,
};

use crate::settlement::{batch, oracle, EscrowSnapshot, OracleWallet, SettlementResult};

/// Maximum allowed message size for length-prefixed reads from the prover (16 MiB).
/// Prevents a malicious prover from claiming a multi-GB length and causing OOM.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ============================================================================
// MPC-TLS Result
// ============================================================================

/// Bundles MPC-TLS output needed by both attestation and settlement.
pub struct MpcTlsResult {
    pub server_name: Option<ServerName>,
    pub sent_bytes: Vec<u8>,
    pub recv_bytes: Vec<u8>,
    pub transcript_commitments: Vec<TranscriptCommitment>,
    pub tls_transcript: TlsTranscript,
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
            transcript_commitments,
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier
        .accept()
        .await
        .map_err(|e| eyre!("Accept verification failed: {}", e))?;

    let tls_transcript = verifier.tls_transcript().clone();

    // Extract plaintext from transcript (for settlement)
    let (sent_bytes, recv_bytes) = match transcript {
        Some(ref t) => (t.sent_unsafe().to_vec(), t.received_unsafe().to_vec()),
        None => (Vec::new(), Vec::new()),
    };

    // Log transcript lengths
    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    info!(
        "Transcript: sent={} bytes, recv={} bytes, plaintext_sent={}, plaintext_recv={}",
        sent_len, recv_len, sent_bytes.len(), recv_bytes.len()
    );

    if let Some(ref name) = server_name {
        info!("Server name: {:?}", name);
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
        transcript_commitments,
        tls_transcript,
    };

    Ok((result, socket))
}

// ============================================================================
// Step 2: Attestation Exchange (always runs, unchanged logic)
// ============================================================================

/// Exchange attestation request/response with the prover.
pub async fn handle_attestation<S: AsyncRead + AsyncWrite + Unpin>(
    mpc: &MpcTlsResult,
    socket: &mut S,
    crypto_provider: &CryptoProvider,
) -> Result<()> {
    info!("Waiting for AttestationRequest from prover");

    // Receive AttestationRequest (length-prefixed)
    let mut len_buf = [0u8; 8];
    socket
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| eyre!("Failed to read request length: {}", e))?;
    let req_len = u64::from_le_bytes(len_buf) as usize;

    if req_len > MAX_MESSAGE_SIZE {
        return Err(eyre!(
            "AttestationRequest too large: {} bytes (max {})",
            req_len,
            MAX_MESSAGE_SIZE
        ));
    }

    info!("Reading AttestationRequest ({} bytes)", req_len);

    let mut request_bytes = vec![0u8; req_len];
    socket
        .read_exact(&mut request_bytes)
        .await
        .map_err(|e| eyre!("Failed to read attestation request: {}", e))?;

    let request: AttestationRequest = bincode::deserialize(&request_bytes)
        .map_err(|e| eyre!("Failed to deserialize attestation request: {}", e))?;

    info!("Received AttestationRequest, building Attestation");

    // Build attestation
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder
        .supported_signature_algs(Vec::from_iter(crypto_provider.signer.supported_algs()));
    let att_config = att_config_builder
        .build()
        .map_err(|e| eyre!("Failed to build attestation config: {}", e))?;

    // Compute transcript lengths
    let sent_len = mpc
        .tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = mpc
        .tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let mut builder = Attestation::builder(&att_config)
        .accept_request(request)
        .map_err(|e| eyre!("Failed to accept attestation request: {}", e))?;

    builder
        .connection_info(ConnectionInfo {
            time: mpc.tls_transcript.time(),
            version: *mpc.tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(mpc.tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(mpc.transcript_commitments.clone());

    let attestation = builder
        .build(crypto_provider)
        .map_err(|e| eyre!("Failed to build attestation: {}", e))?;

    info!("Attestation built and signed, sending to prover");

    // Send attestation (length-prefixed)
    let attestation_bytes = bincode::serialize(&attestation)
        .map_err(|e| eyre!("Failed to serialize attestation: {}", e))?;

    info!("Sending attestation ({} bytes)", attestation_bytes.len());

    let len_bytes = (attestation_bytes.len() as u64).to_le_bytes();
    socket
        .write_all(&len_bytes)
        .await
        .map_err(|e| eyre!("Failed to send attestation length: {}", e))?;
    socket
        .write_all(&attestation_bytes)
        .await
        .map_err(|e| eyre!("Failed to send attestation: {}", e))?;

    info!("Attestation sent successfully");

    Ok(())
}

// ============================================================================
// Step 3: Settlement (decide + on-chain + send result to prover)
// ============================================================================

/// Settle on-chain and send result to prover.
pub async fn handle_settlement<S: AsyncRead + AsyncWrite + Unpin>(
    mpc: &MpcTlsResult,
    socket: &mut S,
    escrow: &EscrowSnapshot,
    wallet: &OracleWallet,
) -> Result<()> {
    let server_name_str = mpc
        .server_name
        .as_ref()
        .map(|n| n.to_string())
        .unwrap_or_default();

    info!("Starting settlement for asset_id={}", escrow.asset_id);

    // 1. Decide: parse plaintext + validate against escrow
    let settlement_result = oracle::decide(
        &server_name_str,
        &mpc.sent_bytes,
        &mpc.recv_bytes,
        escrow,
    )
    .map_err(|e| eyre!("Settlement decision failed: {e}"))?;

    info!(
        "Settlement decision: asset_id={}, decision={:?}, refund_reason={:?}",
        settlement_result.asset_id, settlement_result.decision, settlement_result.refund_reason
    );

    // 2. Compute batch_hash (single settlement: batch_hash = commitment)
    let commitment = escrow.commitment();
    let batch_hash = batch::compute_batch_hash(&[commitment]);

    // 3. Submit on-chain
    let tx_hash = wallet
        .settle_on_chain(batch_hash, &[settlement_result.clone()])
        .await
        .map_err(|e| eyre!("On-chain settlement failed: {e}"))?;

    info!("Settlement tx confirmed: {tx_hash}");

    // 4. Build wire result and send to prover
    let wire_result = SettlementResult {
        tx_hash: tx_hash.0,
        asset_id: settlement_result.asset_id,
        decision: settlement_result.decision as u8,
        refund_reason: settlement_result.refund_reason as u8,
    };

    let result_bytes = bincode::serialize(&wire_result)
        .map_err(|e| eyre!("Failed to serialize settlement result: {e}"))?;

    info!("Sending settlement result ({} bytes)", result_bytes.len());

    // Send length-prefixed result
    let len_bytes = (result_bytes.len() as u64).to_le_bytes();
    socket
        .write_all(&len_bytes)
        .await
        .map_err(|e| eyre!("Failed to send settlement result length: {e}"))?;
    socket
        .write_all(&result_bytes)
        .await
        .map_err(|e| eyre!("Failed to send settlement result: {e}"))?;

    info!("Settlement complete: asset_id={}, tx={tx_hash}", escrow.asset_id);

    Ok(())
}
