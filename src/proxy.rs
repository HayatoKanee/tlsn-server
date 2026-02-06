use axum::{
    extract::{Query, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};
use uuid::Uuid;

/// Query parameters for proxy WebSocket connection.
/// Supports both `token` (notary.pse.dev compatible) and `host` (legacy).
#[derive(Debug, Deserialize)]
pub struct ProxyQuery {
    #[serde(alias = "host")]
    pub token: String,
}

/// WebSocket proxy handler — bridges WebSocket to TCP for browser clients.
pub async fn proxy_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<ProxyQuery>,
) -> impl IntoResponse {
    let host = query.token;
    info!("[Proxy] New proxy request for host: {}", host);
    ws.on_upgrade(move |socket| handle_proxy_connection(socket, host))
}

/// Handle the proxy WebSocket connection by bridging to TCP.
async fn handle_proxy_connection(ws: WebSocket, host: String) {
    let proxy_id = Uuid::new_v4().to_string();
    info!("[{}] Proxy WebSocket connected for host: {}", proxy_id, host);

    // Parse host and port (default to 443 for HTTPS).
    let (hostname, port) = if host.contains(':') {
        let parts: Vec<&str> = host.split(':').collect();
        (
            parts[0].to_string(),
            parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443u16),
        )
    } else {
        (host.clone(), 443)
    };

    info!("[{}] Connecting to {}:{}", proxy_id, hostname, port);

    // Connect to the remote TCP host.
    let tcp_stream = match tokio::net::TcpStream::connect((hostname.as_str(), port)).await {
        Ok(stream) => {
            info!(
                "[{}] TCP connection established to {}:{}",
                proxy_id, hostname, port
            );
            stream
        }
        Err(e) => {
            error!(
                "[{}] Failed to connect to {}:{} - {}",
                proxy_id, hostname, port, e
            );
            return;
        }
    };

    // Split WebSocket and TCP streams.
    let (mut ws_sink, mut ws_stream) = ws.split();
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp_stream);

    // Forward WebSocket -> TCP.
    let proxy_id_clone = proxy_id.clone();
    let ws_to_tcp = tokio::spawn(async move {
        let mut total_bytes = 0u64;

        loop {
            match ws_stream.next().await {
                Some(Ok(msg)) => match msg {
                    Message::Binary(data) => {
                        total_bytes += data.len() as u64;
                        if let Err(e) = tcp_write.write_all(&data).await {
                            error!("[{}] Failed to write to TCP: {}", proxy_id_clone, e);
                            break;
                        }
                    }
                    Message::Close(_) => {
                        info!(
                            "[{}] WebSocket close received, forwarded {} bytes total",
                            proxy_id_clone, total_bytes
                        );
                        break;
                    }
                    _ => {}
                },
                Some(Err(e)) => {
                    error!("[{}] WebSocket read error: {}", proxy_id_clone, e);
                    break;
                }
                None => {
                    info!(
                        "[{}] WebSocket stream ended, forwarded {} bytes total",
                        proxy_id_clone, total_bytes
                    );
                    break;
                }
            }
        }

        total_bytes
    });

    // Forward TCP -> WebSocket.
    let proxy_id_clone = proxy_id.clone();
    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        let mut total_bytes = 0u64;

        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    info!(
                        "[{}] TCP EOF, forwarded {} bytes to WebSocket",
                        proxy_id_clone, total_bytes
                    );
                    let _ = ws_sink.send(Message::Close(None)).await;
                    break;
                }
                Ok(n) => {
                    total_bytes += n as u64;
                    if let Err(e) = ws_sink.send(Message::Binary(buf[..n].to_vec())).await {
                        error!("[{}] Failed to send to WebSocket: {}", proxy_id_clone, e);
                        break;
                    }
                }
                Err(e) => {
                    error!("[{}] TCP read error: {}", proxy_id_clone, e);
                    let _ = ws_sink.send(Message::Close(None)).await;
                    break;
                }
            }
        }

        total_bytes
    });

    // Wait for both tasks.
    let (ws_result, tcp_result) = tokio::join!(ws_to_tcp, tcp_to_ws);
    let ws_total = ws_result.unwrap_or(0);
    let tcp_total = tcp_result.unwrap_or(0);

    info!(
        "[{}] Proxy closed: WS->TCP {} bytes, TCP->WS {} bytes",
        proxy_id, ws_total, tcp_total
    );
}
