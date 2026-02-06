use eyre::{Result, eyre};
use futures_util::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::info;

use tlsn::{
    attestation::{
        request::Request as AttestationRequest, Attestation, AttestationConfig, CryptoProvider,
    },
    config::verifier::VerifierConfig,
    connection::{ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::VerifierOutput,
    Session,
};

/// Run the notarization protocol on the given socket.
///
/// This function acts as the notary (verifier) side of the MPC-TLS protocol:
/// 1. Creates a session with the prover
/// 2. Runs the verifier protocol (MPC-TLS co-computation)
/// 3. Receives an AttestationRequest from the prover
/// 4. Signs and returns an Attestation
pub async fn notarize<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: S,
    crypto_provider: &CryptoProvider,
    verifier_config: VerifierConfig,
) -> Result<()> {
    info!("Starting notarization session");

    // Create a session with the prover.
    // Session::new takes futures::io::AsyncRead + AsyncWrite.
    let session = Session::new(socket);
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    info!("Running MPC-TLS verifier protocol");

    // Create verifier and run the commitment protocol.
    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(|e| eyre!("Failed to create verifier: {}", e))?
        .commit()
        .await
        .map_err(|e| eyre!("Commitment failed: {}", e))?;

    // Accept the prover's commitment request.
    let verifier = verifier
        .accept()
        .await
        .map_err(|e| eyre!("Accept failed: {}", e))?;

    // Run the MPC-TLS protocol.
    let verifier = verifier
        .run()
        .await
        .map_err(|e| eyre!("MPC-TLS run failed: {}", e))?;

    info!("MPC-TLS protocol complete, verifying transcript");

    // Verify the proof.
    let verifier = verifier
        .verify()
        .await
        .map_err(|e| eyre!("Verification failed: {}", e))?;

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier
        .accept()
        .await
        .map_err(|e| eyre!("Accept verification failed: {}", e))?;

    let tls_transcript = verifier.tls_transcript().clone();

    // Close the verifier.
    verifier
        .close()
        .await
        .map_err(|e| eyre!("Failed to close verifier: {}", e))?;

    // Compute transcript lengths (application data only).
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
        "Transcript: sent={} bytes, recv={} bytes",
        sent_len, recv_len
    );

    // Close the session and reclaim the socket.
    handle.close();
    let mut socket = driver_task
        .await
        .map_err(|e| eyre!("Driver task failed: {}", e))?
        .map_err(|e| eyre!("Session driver error: {}", e))?;

    info!("Waiting for AttestationRequest from prover");

    // Receive AttestationRequest from the prover (length-prefixed).
    // The prover sends [8 bytes: u64 LE length][payload] because WebSocket
    // close is bidirectional — we can't rely on EOF to delimit the request.
    let mut len_buf = [0u8; 8];
    socket
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| eyre!("Failed to read request length: {}", e))?;
    let req_len = u64::from_le_bytes(len_buf) as usize;

    info!("Reading AttestationRequest ({} bytes)", req_len);

    let mut request_bytes = vec![0u8; req_len];
    socket
        .read_exact(&mut request_bytes)
        .await
        .map_err(|e| eyre!("Failed to read attestation request: {}", e))?;

    let request: AttestationRequest = bincode::deserialize(&request_bytes)
        .map_err(|e| eyre!("Failed to deserialize attestation request: {}", e))?;

    info!("Received AttestationRequest, building Attestation");

    // Build attestation config.
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder
        .supported_signature_algs(Vec::from_iter(crypto_provider.signer.supported_algs()));
    let att_config = att_config_builder
        .build()
        .map_err(|e| eyre!("Failed to build attestation config: {}", e))?;

    // Build the attestation.
    let mut builder = Attestation::builder(&att_config)
        .accept_request(request)
        .map_err(|e| eyre!("Failed to accept attestation request: {}", e))?;

    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: *tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder
        .build(crypto_provider)
        .map_err(|e| eyre!("Failed to build attestation: {}", e))?;

    info!("Attestation built and signed, sending to prover");

    // Send the attestation back to the prover (length-prefixed).
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

    socket
        .close()
        .await
        .map_err(|e| eyre!("Failed to close socket: {}", e))?;

    info!("Notarization session completed successfully");

    Ok(())
}
