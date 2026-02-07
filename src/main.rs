mod axum_websocket;
mod config;
mod notary;
mod proxy;
mod signing;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use axum_websocket::{WebSocket, WebSocketUpgrade};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tower_http::cors::CorsLayer;
use tracing::{error, info};
use uuid::Uuid;
use ws_stream_tungstenite::WsStream;

use tlsn::{config::verifier::VerifierConfig, webpki::RootCertStore};

use config::Config;
use signing::NotaryKey;

// ============================================================================
// Application State
// ============================================================================

/// Stored session data.
#[allow(dead_code)]
struct SessionData {
    max_sent_data: usize,
    max_recv_data: usize,
}

/// Shared application state.
struct AppState {
    sessions: Mutex<HashMap<String, SessionData>>,
    config: Config,
    notary_key: NotaryKey,
}

// ============================================================================
// CLI Args
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "tlsn-server", version, about = "TLSNotary Notary Server")]
struct Args {
    /// Path to the configuration YAML file.
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct SessionRequest {
    #[serde(rename = "maxSentData")]
    max_sent_data: Option<usize>,
    #[serde(rename = "maxRecvData")]
    max_recv_data: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
}

#[derive(Debug, Serialize)]
struct InfoResponse {
    version: &'static str,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "gitHash")]
    git_hash: String,
}

#[derive(Debug, Deserialize)]
struct NotarizeQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(true)
        .with_line_number(true)
        .init();

    let args = Args::parse();
    let config = Config::load(Path::new(&args.config));

    info!("Configuration loaded:");
    info!("  host: {}", config.host);
    info!("  port: {}", config.port);
    info!("  max_sent_data: {}", config.notarization.max_sent_data);
    info!("  max_recv_data: {}", config.notarization.max_recv_data);
    info!("  timeout: {}s", config.notarization.timeout);

    // Initialize signing key.
    let notary_key =
        signing::create_notary_key(config.notarization.private_key_pem_path.as_deref())?;

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid host:port");

    let app_state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        config,
        notary_key,
    });

    let tls_config = app_state.config.tls.clone();

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/info", get(info_handler))
        .route("/session", post(session_handler))
        .route("/notarize", get(notarize_ws_handler))
        .route("/proxy", get(proxy::proxy_ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let tls_enabled = tls_config.enabled;
    info!(
        "TLSNotary Notary Server starting on {} (TLS: {})",
        addr,
        if tls_enabled { "enabled" } else { "disabled" }
    );
    info!("  GET  /health              - Health check");
    info!("  GET  /info                - Server info + public key");
    info!("  POST /session             - Create notarization session");
    info!("  GET  /notarize?sessionId= - WebSocket notarization");
    info!("  GET  /proxy?token=        - WebSocket-to-TCP proxy");

    if tls_enabled {
        let cert_path = tls_config
            .certificate_path
            .as_ref()
            .expect("tls.certificate_path is required when tls.enabled = true");
        let key_path = tls_config
            .private_key_path
            .as_ref()
            .expect("tls.private_key_path is required when tls.enabled = true");

        let rustls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).tcp_nodelay(true).await?;
    }

    Ok(())
}

// ============================================================================
// Route Handlers
// ============================================================================

/// GET /health
async fn health_handler() -> impl IntoResponse {
    "ok"
}

/// GET /info — server version and notary public key.
async fn info_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let git_hash = std::env::var("GIT_HASH").unwrap_or_else(|_| "dev".to_string());

    Json(InfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        public_key: hex::encode(&state.notary_key.public_key),
        git_hash,
    })
}

/// POST /session — create a new notarization session.
async fn session_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = Uuid::new_v4().to_string();
    let max_sent_data = body
        .max_sent_data
        .unwrap_or(state.config.notarization.max_sent_data);
    let max_recv_data = body
        .max_recv_data
        .unwrap_or(state.config.notarization.max_recv_data);

    // Enforce server limits.
    if max_sent_data > state.config.notarization.max_sent_data {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "maxSentData {} exceeds server limit {}",
                max_sent_data, state.config.notarization.max_sent_data
            ),
        ));
    }
    if max_recv_data > state.config.notarization.max_recv_data {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "maxRecvData {} exceeds server limit {}",
                max_recv_data, state.config.notarization.max_recv_data
            ),
        ));
    }

    {
        let mut sessions = state.sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            SessionData {
                max_sent_data,
                max_recv_data,
            },
        );
    }

    info!(
        "[{}] Session created: maxSentData={}, maxRecvData={}",
        session_id, max_sent_data, max_recv_data
    );

    // Spawn a timeout task to clean up stale sessions.
    let state_clone = state.clone();
    let session_id_clone = session_id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let mut sessions = state_clone.sessions.lock().await;
        if sessions.remove(&session_id_clone).is_some() {
            info!(
                "[{}] Session expired (no WebSocket connection within 30s)",
                session_id_clone
            );
        }
    });

    Ok(Json(SessionResponse { session_id }))
}

/// GET /notarize?sessionId=xxx — WebSocket upgrade for notarization.
async fn notarize_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotarizeQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = query.session_id;

    // Look up and remove the session.
    let session_data = {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&session_id)
    };

    match session_data {
        Some(_session_data) => {
            info!("[{}] WebSocket upgrade for notarization", session_id);
            Ok(ws.on_upgrade(move |socket| {
                handle_notarize_websocket(socket, session_id, state)
            }))
        }
        None => {
            error!("[{}] Session not found or already used", session_id);
            Err((
                StatusCode::NOT_FOUND,
                format!("Session not found: {}", session_id),
            ))
        }
    }
}

/// Handle the WebSocket notarization connection.
async fn handle_notarize_websocket(
    socket: WebSocket,
    session_id: String,
    state: Arc<AppState>,
) {
    info!("[{}] WebSocket connected, starting notarization", session_id);

    // Convert the custom axum WebSocket (backed by async-tungstenite) to WsStream
    // which implements futures::io::AsyncRead + AsyncWrite.
    let ws_stream = WsStream::new(socket.into_inner());

    // Build verifier config with Mozilla root certificates for production.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .expect("Failed to build verifier config");

    // Run notarization with timeout.
    let timeout_duration = Duration::from_secs(state.config.notarization.timeout);

    match timeout(
        timeout_duration,
        notary::notarize(ws_stream, &state.notary_key.provider, verifier_config),
    )
    .await
    {
        Ok(Ok(())) => {
            info!("[{}] Notarization completed successfully", session_id);
        }
        Ok(Err(e)) => {
            error!("[{}] Notarization failed: {}", session_id, e);
        }
        Err(_) => {
            error!(
                "[{}] Notarization timed out after {:?}",
                session_id, timeout_duration
            );
        }
    }
}
