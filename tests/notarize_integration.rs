use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    attestation::{
        request::{Request as AttestationRequest, RequestConfig},
        Attestation, CryptoProvider,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
        verifier::VerifierConfig,
    },
    connection::{HandshakeData, ServerName},
    prover::ProverOutput,
    transcript::TranscriptCommitConfig,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
    Session,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_server_fixture_certs::{CA_CERT_DER, CLIENT_CERT_DER, CLIENT_KEY_DER, SERVER_DOMAIN};

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 14;

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

#[tokio::test]
async fn test_full_notarization_round_trip() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init()
        .ok();

    // 1. Start test HTTP server fixture on a random TCP port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                tlsn_server_fixture::bind(tcp_stream.compat()).await.unwrap();
            });
        }
    });

    // 2. Create notary signing key (ephemeral).
    let notary_key = tlsn_server::signing::create_notary_key(None).unwrap();

    // 3. Build VerifierConfig with the test CA cert.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()
        .unwrap();

    // 4. Create duplex pair for prover <-> notary communication.
    let (prover_socket, notary_socket) = tokio::io::duplex(1 << 23);

    // 5. Spawn notary task using our server's notarize function.
    let crypto_provider = notary_key.provider;
    tokio::spawn(async move {
        tlsn_server::notary::notarize(notary_socket.compat(), &crypto_provider, verifier_config)
            .await
            .unwrap();
    });

    // 6. Run prover side.
    let session = Session::new(prover_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap()
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_recv_data(MAX_RECV_DATA)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    // Connect to the test HTTP server via TLS.
    let client_socket = tokio::net::TcpStream::connect(("127.0.0.1", server_port))
        .await
        .unwrap();

    let (tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .client_auth((
                    vec![CertificateDer(CLIENT_CERT_DER.to_vec())],
                    PrivateKeyDer(CLIENT_KEY_DER.to_vec()),
                ))
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .await
        .unwrap();
    let tls_connection = TokioIo::new(tls_connection.compat());

    let prover_task = tokio::spawn(prover_fut);

    // Send HTTP request via hyper.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection)
            .await
            .unwrap();
    tokio::spawn(connection);

    let request = Request::builder()
        .uri("/formats/json")
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "HTTP request failed");

    // Wait for prover to finish MPC-TLS.
    let mut prover = prover_task.await.unwrap().unwrap();

    // Parse HTTP transcript and commit.
    let transcript = HttpTranscript::parse(prover.transcript()).unwrap();
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    DefaultHttpCommitter::default()
        .commit_transcript(&mut builder, &transcript)
        .unwrap();
    let transcript_commit = builder.build().unwrap();

    // Build attestation request config.
    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);
    let request_config = builder.build().unwrap();

    // Build prove config and prove.
    let mut builder = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        builder.transcript_commit(config.clone());
    }
    let disclosure_config = builder.build().unwrap();

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await.unwrap();

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await.unwrap();

    // Build AttestationRequest.
    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, _secrets) = builder.build(&CryptoProvider::default()).unwrap();

    // Close session, reclaim socket, send request to notary.
    handle.close();
    let mut socket = driver_task.await.unwrap().unwrap();

    let request_bytes = bincode::serialize(&request).unwrap();
    socket.write_all(&request_bytes).await.unwrap();
    socket.close().await.unwrap();

    // Receive attestation from notary.
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await.unwrap();
    let attestation: Attestation = bincode::deserialize(&attestation_bytes).unwrap();

    // 7. Validate attestation against prover's view.
    //    This checks that the attestation is consistent with the prover's
    //    transcript commitments and server identity.
    let provider = CryptoProvider::default();
    request.validate(&attestation, &provider).unwrap();

    // 8. Verify the notary's verifying key is present in the attestation.
    let _verifying_key = attestation.body.verifying_key();

    println!("Full notarization round-trip completed successfully!");
}
