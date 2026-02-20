use axum::{
    extract::{Query, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Allowed proxy target hosts (Steam servers only).
/// The proxy exists so browser extensions can reach Steam CM servers
/// via WebSocket (browsers can't open raw TCP).
const ALLOWED_HOSTS: &[&str] = &[
    "api.steampowered.com",
    "steamcommunity.com",
    "community.steam-api.com",
    "login.steampowered.com",
    "store.steampowered.com",
];

/// Maximum allowed port range.
const ALLOWED_PORT_RANGE: std::ops::RangeInclusive<u16> = 80..=65535;

/// Query parameters for proxy WebSocket connection.
/// Supports both `token` (notary.pse.dev compatible) and `host` (legacy).
#[derive(Debug, Deserialize)]
pub struct ProxyQuery {
    #[serde(alias = "host")]
    pub token: String,
}

/// WebSocket proxy handler — bridges WebSocket to TCP for browser clients.
///
/// Security: Only allows connections to allowlisted Steam servers.
pub async fn proxy_ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<ProxyQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let host = &query.token;

    // Parse host:port
    let (hostname, port) = parse_host_port(host);

    // Validate against allowlist
    if !is_allowed_host(&hostname) {
        warn!(host = %host, "Proxy request rejected: host not in allowlist");
        return Err((
            StatusCode::FORBIDDEN,
            format!("Host not allowed: {hostname}. Only Steam servers are permitted."),
        ));
    }

    if !ALLOWED_PORT_RANGE.contains(&port) {
        warn!(host = %host, port, "Proxy request rejected: port out of range");
        return Err((
            StatusCode::FORBIDDEN,
            format!("Port {port} not allowed"),
        ));
    }

    info!("[Proxy] Approved proxy request for {}:{}", hostname, port);
    let hostname_owned = hostname.to_string();
    Ok(ws.on_upgrade(move |socket| handle_proxy_connection(socket, hostname_owned, port)))
}

/// Parse host:port string, defaulting to port 443.
fn parse_host_port(host: &str) -> (String, u16) {
    if let Some(colon_pos) = host.rfind(':') {
        let hostname = host[..colon_pos].to_string();
        let port = host[colon_pos + 1..].parse().unwrap_or(443);
        (hostname, port)
    } else {
        (host.to_string(), 443)
    }
}

/// Check if hostname is in the Steam allowlist.
fn is_allowed_host(hostname: &str) -> bool {
    let hostname_lower = hostname.to_lowercase();
    ALLOWED_HOSTS
        .iter()
        .any(|allowed| hostname_lower == *allowed)
}

/// Handle the proxy WebSocket connection by bridging to TCP.
async fn handle_proxy_connection(ws: WebSocket, hostname: String, port: u16) {
    let proxy_id = Uuid::new_v4().to_string();
    info!("[{}] Proxy WebSocket connected for {}:{}", proxy_id, hostname, port);

    // Connect to the remote TCP host with timeout.
    let tcp_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect((hostname.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => {
            info!(
                "[{}] TCP connection established to {}:{}",
                proxy_id, hostname, port
            );
            stream
        }
        Ok(Err(e)) => {
            error!(
                "[{}] Failed to connect to {}:{} - {}",
                proxy_id, hostname, port, e
            );
            return;
        }
        Err(_) => {
            error!(
                "[{}] TCP connect timeout to {}:{} (10s)",
                proxy_id, hostname, port
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_hosts() {
        assert!(is_allowed_host("api.steampowered.com"));
        assert!(is_allowed_host("steamcommunity.com"));
        assert!(is_allowed_host("API.STEAMPOWERED.COM"));
        assert!(!is_allowed_host("evil.com"));
        assert!(!is_allowed_host("169.254.169.254"));
        assert!(!is_allowed_host("localhost"));
        assert!(!is_allowed_host("10.0.0.1"));
    }

    #[test]
    fn test_parse_host_port() {
        let (h, p) = parse_host_port("api.steampowered.com:443");
        assert_eq!(h, "api.steampowered.com");
        assert_eq!(p, 443);

        let (h, p) = parse_host_port("steamcommunity.com");
        assert_eq!(h, "steamcommunity.com");
        assert_eq!(p, 443);

        let (h, p) = parse_host_port("example.com:8080");
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
    }
}
