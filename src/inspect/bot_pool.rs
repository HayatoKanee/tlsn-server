use std::future::ready;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{Connector, client_async_tls_with_config};
use tracing::{error, info, warn};

use steam_vent::auth::{FileGuardDataStore, SharedSecretAuthConfirmationHandler};
use steam_vent::connection::UnAuthenticatedConnection;
use steam_vent::proto::steammessages_clientserver_2::CMsgClientRequestFreeLicense;
use steam_vent::{Connection, ConnectionTrait, GameCoordinator, NetworkError, ServerList};
use steam_vent_proto_csgo::gcsdk_gcmessages::CMsgClientHello as CsgoClientHello;
use steam_vent_proto_csgo::GCHandshake as CsgoHandshake;

use super::gc_client::{self, InspectError};
use super::link_parser::InspectParams;
use super::types::InspectData;
use crate::config::InspectConfig;

/// CS2 GC protocol version (from node-globaloffensive). Rarely changes.
const CS2_GC_VERSION: u32 = 2000244;

/// CS2 app ID on Steam.
const CS2_APP_ID: u32 = 730;

/// Max retries when connecting a bot (handles LoggedInElsewhere kick).
const BOT_CONNECT_MAX_RETRIES: u32 = 3;

/// Delay between bot connection retries.
/// Must be >30s to guarantee a fresh TOTP window (avoids TwoFactorCodeMismatch).
const BOT_CONNECT_RETRY_DELAY: Duration = Duration::from_secs(35);

/// Timeout for GC welcome handshake.
const GC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval for periodic bot relog (CSFloat uses 30 min).
/// GC inspect calls can silently stop working; periodic relog prevents this.
/// Only applies to direct bots — proxied bots connect on-demand instead.
const RELOG_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Max variance added to relog interval (prevents all bots relogging at once).
const RELOG_VARIANCE_SECS: u64 = 4 * 60;

/// Consecutive timeouts before marking a bot as unhealthy.
const MAX_CONSECUTIVE_TIMEOUTS: u32 = 3;

/// Timeout for eager warmup connections at startup.
/// Must be long enough for connect_session_with_retry (handles LoggedInElsewhere):
/// ~5s connect + 35s retry delay + ~5s reconnect + 30s GC handshake = ~75s, so 90s is safe.
const WARMUP_CONNECT_TIMEOUT: Duration = Duration::from_secs(90);

/// TTL for cached ServerList (avoid re-discovering CM servers on every connect).
const SERVER_LIST_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Batch size for parallel warmup connections.
const WARMUP_BATCH_SIZE: usize = 20;

/// Delay between inspect retries to avoid instant retry storms.
const RETRY_DELAY: Duration = Duration::from_millis(200);

// ============================================================================
// Bot pool — manages authenticated Steam bots for CS2 GC inspect requests.
// ============================================================================

pub struct BotPool {
    bots: Vec<Arc<Bot>>,
    next: AtomicUsize,
    config: InspectConfig,
    bots_config: BotsConfig,
    /// Cached CM server list to avoid re-discovering on every connect.
    server_list_cache: Arc<tokio::sync::RwLock<Option<(Arc<ServerList>, Instant)>>>,
}

struct Bot {
    /// Single mutex protects all mutable bot state.
    /// `try_lock()` in inspect path skips busy bots (natural serialization).
    inner: Mutex<BotInner>,
    username: String,
    /// Bot index in the config (for credential lookup).
    index: usize,
    /// Whether this bot connects directly or through a proxy.
    kind: BotKind,
}

struct BotInner {
    /// None = disconnected (relog will reconnect).
    session: Option<BotSession>,
    /// Rate limiting: when was the last GC request sent.
    last_request: Instant,
    /// Health tracking: consecutive GC timeouts.
    consecutive_timeouts: u32,
}

enum BotKind {
    /// Connects directly to Steam CM servers.
    Direct,
    /// Connects through a SOCKS5/HTTP proxy.
    Proxied(ProxyInfo),
}

struct BotSession {
    #[allow(dead_code)]
    connection: Connection,
    gc: GameCoordinator,
}

// ============================================================================
// Bot credentials + proxy config loaded from JSON file
// ============================================================================

#[derive(Debug, Clone, serde::Deserialize)]
pub struct BotsConfig {
    pub bots: Vec<BotCredentials>,
    #[serde(default)]
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct BotCredentials {
    pub username: String,
    pub password: String,
    pub shared_secret: String,
}

// ============================================================================
// Proxy parsing — supports socks5://, http://, https://
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum ProxyProtocol {
    Socks5,
    Http,
}

#[derive(Clone)]
struct ProxyInfo {
    protocol: ProxyProtocol,
    host: String,
    port: u16,
    username: String,
    password: String,
}

/// Parse proxy URL into components. Supports:
/// - `socks5://user:pass@host:port` → SOCKS5 tunnel
/// - `http://user:pass@host:port`   → HTTP CONNECT tunnel
/// - `https://user:pass@host:port`  → HTTP CONNECT tunnel (same behavior)
///
/// Uses rsplit to handle passwords containing `@` or `:`.
fn parse_proxy_url(url: &str) -> Option<ProxyInfo> {
    let (protocol, rest) = if let Some(r) = url.strip_prefix("socks5://") {
        (ProxyProtocol::Socks5, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (ProxyProtocol::Http, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        (ProxyProtocol::Http, r)
    } else {
        return None;
    };
    // Split on LAST '@' so passwords with '@' work
    let (auth, host_port) = rest.rsplit_once('@')?;
    // Split auth on FIRST ':' (username can't contain ':')
    let (username, password) = auth.split_once(':')?;
    let (host, port_str) = host_port.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some(ProxyInfo {
        protocol,
        host: host.to_string(),
        port,
        username: username.to_string(),
        password: password.to_string(),
    })
}

/// Extract hostname and port from a WSS URL.
/// e.g., `wss://ext2-par1.steamserver.net:27025/cmsocket/` → ("ext2-par1.steamserver.net", 27025)
/// e.g., `wss://cm2-mt1.steampowered.com/cmsocket/` → ("cm2-mt1.steampowered.com", 443)
fn parse_wss_host_port(wss_url: &str) -> Option<(&str, u16)> {
    let rest = wss_url.strip_prefix("wss://")?;
    let authority = rest.split('/').next()?;
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host, port))
    } else {
        Some((authority, 443)) // default WSS port
    }
}

/// Find the end of HTTP headers (\r\n\r\n) in a byte buffer.
/// Returns the position just after the \r\n\r\n sequence.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

// ============================================================================
// BotPool implementation
// ============================================================================

impl BotPool {
    /// Initialize the bot pool: load credentials, register all bots cold, then warm them up.
    /// All bots (direct and proxied) are eagerly connected at startup and relogged periodically.
    pub async fn new(config: &InspectConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bots_json = std::fs::read_to_string(&config.bots_config_path)
            .map_err(|e| format!("Failed to read bots config at {}: {}", config.bots_config_path, e))?;
        let bots_config: BotsConfig = serde_json::from_str(&bots_json)
            .map_err(|e| format!("Failed to parse bots config: {}", e))?;

        if bots_config.bots.is_empty() {
            return Err("No bots configured in bots config file".into());
        }

        // Parse proxy list
        let proxies: Vec<ProxyInfo> = bots_config
            .proxies
            .iter()
            .filter_map(|url| {
                let info = parse_proxy_url(url);
                if info.is_none() {
                    warn!(url, "Failed to parse proxy URL, skipping");
                }
                info
            })
            .collect();

        if !proxies.is_empty() {
            info!(
                count = proxies.len(),
                "Proxies loaded for round-robin rotation"
            );
        }

        // Register all bots cold (session: None) — warmup connects them in parallel
        let mut bots = Vec::new();
        let total = bots_config.bots.len();

        for (i, creds) in bots_config.bots.iter().enumerate() {
            let kind = if proxies.is_empty() {
                BotKind::Direct
            } else {
                let proxy = proxies[i % proxies.len()].clone();
                let proto = match proxy.protocol {
                    ProxyProtocol::Socks5 => "socks5",
                    ProxyProtocol::Http => "http",
                };
                info!(
                    "Bot {}/{}: {} assigned proxy {} {}:{}",
                    i + 1, total, creds.username, proto, proxy.host, proxy.port,
                );
                BotKind::Proxied(proxy)
            };

            bots.push(Arc::new(Bot {
                inner: Mutex::new(BotInner {
                    session: None,
                    last_request: Instant::now() - Duration::from_secs(10),
                    consecutive_timeouts: 0,
                }),
                username: creds.username.clone(),
                index: i,
                kind,
            }));
        }

        let pool = Self {
            bots,
            next: AtomicUsize::new(0),
            config: config.clone(),
            bots_config: bots_config.clone(),
            server_list_cache: Arc::new(tokio::sync::RwLock::new(None)),
        };

        // Eagerly warm up ALL bots (parallel batches)
        pool.warmup_all_bots().await;

        if pool.ready_count() == 0 {
            return Err("All bots failed to connect — inspect disabled".into());
        }

        // Spawn periodic relog tasks for ALL bots
        pool.spawn_relog_tasks();

        Ok(pool)
    }

    /// Get cached CM server list, refreshing if stale (>5 min).
    async fn get_or_refresh_server_list(
        cache: &tokio::sync::RwLock<Option<(Arc<ServerList>, Instant)>>,
    ) -> Result<Arc<ServerList>, Box<dyn std::error::Error + Send + Sync>> {
        // Fast path: read lock
        {
            let cached = cache.read().await;
            if let Some((ref list, ref fetched_at)) = *cached {
                if fetched_at.elapsed() < SERVER_LIST_CACHE_TTL {
                    return Ok(Arc::clone(list));
                }
            }
        }
        // Slow path: write lock + discover
        let mut cached = cache.write().await;
        // Double-check (another task may have refreshed while we waited)
        if let Some((ref list, ref fetched_at)) = *cached {
            if fetched_at.elapsed() < SERVER_LIST_CACHE_TTL {
                return Ok(Arc::clone(list));
            }
        }
        info!("Discovering Steam CM servers...");
        let server_list = Arc::new(ServerList::discover().await?);
        *cached = Some((Arc::clone(&server_list), Instant::now()));
        Ok(server_list)
    }

    /// Warm up all bots in parallel batches at startup.
    async fn warmup_all_bots(&self) {
        let server_list = match Self::get_or_refresh_server_list(&self.server_list_cache).await {
            Ok(sl) => sl,
            Err(e) => {
                error!("Failed to discover CM servers for warmup: {}", e);
                return;
            }
        };

        let total = self.bots.len();
        let mut connected = 0usize;
        let mut failed = 0usize;

        for batch in self.bots.chunks(WARMUP_BATCH_SIZE) {
            let mut handles = Vec::new();

            for bot in batch {
                let bot = Arc::clone(bot);
                let server_list = Arc::clone(&server_list);
                let creds = self.bots_config.bots[bot.index].clone();
                let proxy = match &bot.kind {
                    BotKind::Proxied(p) => Some(p.clone()),
                    BotKind::Direct => None,
                };

                handles.push(tokio::spawn(async move {
                    let result = tokio::time::timeout(
                        WARMUP_CONNECT_TIMEOUT,
                        BotPool::connect_session_with_retry(&server_list, &creds, proxy.as_ref()),
                    )
                    .await;

                    match result {
                        Ok(Ok(session)) => {
                            let mut inner = bot.inner.lock().await;
                            inner.session = Some(session);
                            info!(bot = %bot.username, "Warmup: connected to CS2 GC");
                            true
                        }
                        Ok(Err(e)) => {
                            error!(bot = %bot.username, error = %e, "Warmup: connection failed");
                            false
                        }
                        Err(_) => {
                            error!(
                                bot = %bot.username,
                                "Warmup: timed out after {}s",
                                WARMUP_CONNECT_TIMEOUT.as_secs(),
                            );
                            false
                        }
                    }
                }));
            }

            for handle in handles {
                match handle.await {
                    Ok(true) => connected += 1,
                    Ok(false) => failed += 1,
                    Err(e) => {
                        error!("Warmup task panicked: {}", e);
                        failed += 1;
                    }
                }
            }
        }

        info!(
            connected,
            failed,
            total,
            "Warmup complete: {}/{} bots connected",
            connected,
            total,
        );
    }

    /// Connect a bot session with retry logic. First attempt may kick an existing session
    /// (LoggedInElsewhere), so we retry after a delay to let Steam clean up.
    async fn connect_session_with_retry(
        server_list: &ServerList,
        creds: &BotCredentials,
        proxy: Option<&ProxyInfo>,
    ) -> Result<BotSession, Box<dyn std::error::Error + Send + Sync>> {
        let mut last_error = None;

        for attempt in 0..BOT_CONNECT_MAX_RETRIES {
            match Self::connect_session(server_list, creds, proxy).await {
                Ok(session) => return Ok(session),
                Err(e) => {
                    let is_last = attempt + 1 >= BOT_CONNECT_MAX_RETRIES;
                    if is_last {
                        last_error = Some(e);
                    } else {
                        warn!(
                            bot = %creds.username,
                            attempt = attempt + 1,
                            error = %e,
                            "Bot connection failed, retrying in {}s (may be LoggedInElsewhere)",
                            BOT_CONNECT_RETRY_DELAY.as_secs(),
                        );
                        last_error = Some(e);
                        tokio::time::sleep(BOT_CONNECT_RETRY_DELAY).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Authenticate a single bot, request free CS2 license, and connect to CS2 GC.
    /// Returns a BotSession (connection + gc) that can be placed into a Bot.
    async fn connect_session(
        server_list: &ServerList,
        creds: &BotCredentials,
        proxy: Option<&ProxyInfo>,
    ) -> Result<BotSession, Box<dyn std::error::Error + Send + Sync>> {
        let connection = match proxy {
            Some(proxy) => {
                Self::connect_bot_via_proxy(server_list, creds, proxy).await?
            }
            None => {
                Connection::login(
                    server_list,
                    &creds.username,
                    &creds.password,
                    FileGuardDataStore::user_cache(),
                    SharedSecretAuthConfirmationHandler::new(&creds.shared_secret),
                )
                .await?
            }
        };

        // Request free CS2 license (like CSFloat's requestFreeLicense([730])).
        // Idempotent — does nothing if already owned.
        Self::request_free_cs2_license(&connection).await;

        // Connect to CS2 GC with correct version
        let handshake = CsgoHandshake {
            hello: CsgoClientHello {
                version: Some(CS2_GC_VERSION),
                ..Default::default()
            },
        };
        let (gc, welcome) = tokio::time::timeout(
            GC_HANDSHAKE_TIMEOUT,
            GameCoordinator::with_handshake(&connection, &handshake),
        )
        .await
        .map_err(|_| format!("CS2 GC welcome timed out after {}s", GC_HANDSHAKE_TIMEOUT.as_secs()))?
        .map_err(|e| format!("CS2 GC connection failed: {}", e))?;

        if let Some(gc_version) = welcome.version {
            info!(gc_version, "CS2 GC welcome received");
        }

        Ok(BotSession { connection, gc })
    }

    /// Request the free CS2 license for a bot account.
    /// CS2 is free-to-play but bots may not have it in their library.
    /// Fire-and-forget — we don't wait for the response.
    async fn request_free_cs2_license(connection: &Connection) {
        let mut req = CMsgClientRequestFreeLicense::default();
        req.appids = vec![CS2_APP_ID];
        match connection.send(req).await {
            Ok(_) => {
                // Small delay to let Steam process the license grant
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                warn!(error = %e, "Failed to request free CS2 license (may already own it)");
            }
        }
    }

    /// Connect a bot through a proxy using steam-vent's custom transport API.
    /// Dispatches to SOCKS5 or HTTP CONNECT based on proxy protocol.
    async fn connect_bot_via_proxy(
        server_list: &ServerList,
        creds: &BotCredentials,
        proxy: &ProxyInfo,
    ) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
        let wss_url = server_list.pick_ws();
        let (target_host, target_port) = parse_wss_host_port(&wss_url)
            .ok_or("Failed to parse Steam CM WebSocket URL")?;

        info!(
            wss_url = %wss_url,
            target_host = %target_host,
            target_port = %target_port,
            "Tunneling to Steam CM server via proxy"
        );

        // 1. Establish TCP tunnel through proxy (protocol-specific)
        let tunnel: TcpStream = match proxy.protocol {
            ProxyProtocol::Socks5 => {
                let socks_stream = Socks5Stream::connect_with_password(
                    (proxy.host.as_str(), proxy.port),
                    (target_host, target_port),
                    &proxy.username,
                    &proxy.password,
                )
                .await
                .map_err(|e| {
                    format!("SOCKS5 connect to {}:{} failed: {}", proxy.host, proxy.port, e)
                })?;
                socks_stream.into_inner()
            }
            ProxyProtocol::Http => {
                Self::http_connect_tunnel(proxy, target_host, target_port).await?
            }
        };

        // 2. WebSocket + TLS handshake over the tunnel
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = Connector::Rustls(Arc::new(tls_config));

        let (ws_stream, _) = client_async_tls_with_config(
            &wss_url,
            tunnel,
            None,
            Some(connector),
        )
        .await
        .map_err(|e| format!("WebSocket handshake via proxy failed: {}", e))?;

        // 3. Split into sink/stream, filtering out 0-byte messages.
        //    Steam sends empty WS frames when kicking a session (LoggedInElsewhere).
        //    These crash steam-vent's message parser which expects at least 8 bytes.
        let (raw_write, raw_read) = ws_stream.split();
        let sender = raw_write.with(|msg: BytesMut| ready(Ok(WsMessage::binary(msg))));
        let receiver = raw_read
            .map_err(NetworkError::from)
            .map_ok(|msg| BytesMut::from(&msg.into_data()[..]))
            .try_filter(|data| ready(!data.is_empty()));

        // 4. Create unauthenticated connection with custom transport, then authenticate
        let unauth = UnAuthenticatedConnection::from_sender_receiver(sender, receiver).await?;
        let connection = unauth
            .login(
                &creds.username,
                &creds.password,
                FileGuardDataStore::user_cache(),
                SharedSecretAuthConfirmationHandler::new(&creds.shared_secret),
            )
            .await?;

        Ok(connection)
    }

    /// HTTP CONNECT tunnel: opens a raw TCP connection through an HTTP proxy.
    ///
    /// Sends `CONNECT target:port HTTP/1.1` with Basic auth, waits for `200`,
    /// then returns the raw TcpStream for TLS + WebSocket to layer on top.
    async fn http_connect_tunnel(
        proxy: &ProxyInfo,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await
            .map_err(|e| format!("TCP connect to proxy {}:{} failed: {}", proxy.host, proxy.port, e))?;

        // Build HTTP CONNECT request with Basic auth
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", proxy.username, proxy.password));
        let request = format!(
            "CONNECT {target_host}:{target_port} HTTP/1.1\r\n\
             Host: {target_host}:{target_port}\r\n\
             Proxy-Authorization: Basic {auth}\r\n\
             \r\n"
        );

        stream.write_all(request.as_bytes()).await
            .map_err(|e| format!("Failed to send CONNECT to proxy: {}", e))?;

        // Read response (looking for "HTTP/1.x 200")
        let mut buf = [0u8; 4096];
        let mut total = 0;
        loop {
            let n = stream.read(&mut buf[total..]).await
                .map_err(|e| format!("Failed to read CONNECT response: {}", e))?;
            if n == 0 {
                return Err("Proxy closed connection during CONNECT handshake".into());
            }
            total += n;

            // Check if we've received the full HTTP header (ends with \r\n\r\n)
            if let Some(header_end) = find_header_end(&buf[..total]) {
                let header = std::str::from_utf8(&buf[..header_end])
                    .map_err(|_| "Proxy returned non-UTF8 CONNECT response")?;

                // Verify we got 200
                if !header.starts_with("HTTP/1.1 200") && !header.starts_with("HTTP/1.0 200") {
                    return Err(format!(
                        "Proxy CONNECT failed: {}",
                        header.lines().next().unwrap_or("unknown")
                    ).into());
                }

                return Ok(stream);
            }

            if total >= buf.len() {
                return Err("Proxy CONNECT response too large".into());
            }
        }
    }

    /// Spawn periodic relog tasks for ALL bots (direct and proxied).
    /// Every ~30 min (+ random variance), reconnect the bot to prevent stale GC sessions.
    fn spawn_relog_tasks(&self) {
        let cache = Arc::clone(&self.server_list_cache);

        for bot in &self.bots {
            let bot = Arc::clone(bot);
            let creds = self.bots_config.bots[bot.index].clone();
            let cache = Arc::clone(&cache);
            let proxy = match &bot.kind {
                BotKind::Proxied(p) => Some(p.clone()),
                BotKind::Direct => None,
            };

            tokio::spawn(async move {
                // Stagger relog times (CSFloat uses 0-4 min variance)
                let variance = rand_u64() % RELOG_VARIANCE_SECS;
                let interval = RELOG_INTERVAL + Duration::from_secs(variance);

                loop {
                    tokio::time::sleep(interval).await;

                    info!(
                        bot = %bot.username,
                        "Periodic relog: reconnecting (interval={}min)",
                        interval.as_secs() / 60,
                    );

                    // Clear session to prevent inspects from using stale connection during relog.
                    {
                        let mut inner = bot.inner.lock().await;
                        inner.session = None;
                    }

                    let server_list = match BotPool::get_or_refresh_server_list(&cache).await {
                        Ok(sl) => sl,
                        Err(e) => {
                            error!(bot = %bot.username, error = %e, "Relog failed: CM discovery error");
                            continue;
                        }
                    };

                    match BotPool::connect_session_with_retry(
                        &server_list,
                        &creds,
                        proxy.as_ref(),
                    )
                    .await
                    {
                        Ok(new_session) => {
                            let mut inner = bot.inner.lock().await;
                            inner.session = Some(new_session);
                            inner.consecutive_timeouts = 0;
                            info!(bot = %bot.username, "Relog successful");
                        }
                        Err(e) => {
                            error!(bot = %bot.username, error = %e, "Relog failed — bot stays offline");
                        }
                    }
                }
            });
        }
    }

    /// Inspect an item with automatic retry across different bots.
    pub async fn inspect(&self, params: &InspectParams) -> Result<InspectData, InspectError> {
        let mut last_error = None;

        for attempt in 0..self.config.max_retries {
            match self.inspect_with_next_bot(params).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        "Inspect attempt failed, retrying with next bot"
                    );
                    last_error = Some(e);
                    if attempt + 1 < self.config.max_retries {
                        tokio::time::sleep(RETRY_DELAY).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(InspectError::NoBots))
    }

    /// Send inspect request to the next available bot in round-robin order.
    /// Uses try_lock() to skip busy bots — naturally serializes per-bot GC access.
    async fn inspect_with_next_bot(
        &self,
        params: &InspectParams,
    ) -> Result<InspectData, InspectError> {
        if self.bots.is_empty() {
            return Err(InspectError::NoBots);
        }

        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let len = self.bots.len();

        for offset in 0..len {
            let idx = (start + offset) % len;
            let bot = &self.bots[idx];

            // try_lock: skip busy bots (locked = doing an inspect or connecting)
            let mut inner = match bot.inner.try_lock() {
                Ok(guard) => guard,
                Err(_) => continue,
            };

            // No session = disconnected (relog will reconnect), skip
            if inner.session.is_none() {
                continue;
            }

            // Rate limit (Steam enforces ~1100ms between requests)
            let elapsed = inner.last_request.elapsed();
            let delay = Duration::from_millis(self.config.request_delay_ms);
            if elapsed < delay {
                tokio::time::sleep(delay - elapsed).await;
            }

            // Do inspect
            let session = inner.session.as_ref().unwrap();
            let result =
                gc_client::inspect_item(&session.gc, params, self.config.request_timeout_s).await;
            inner.last_request = Instant::now();

            match &result {
                Ok(_) => {
                    inner.consecutive_timeouts = 0;
                }
                Err(InspectError::Timeout) => {
                    if matches!(bot.kind, BotKind::Proxied(_)) {
                        // Proxied: single timeout = dead proxy session, drop immediately
                        inner.session = None;
                        inner.consecutive_timeouts = 0;
                        warn!(bot = %bot.username, "Proxied bot session dropped on first GC timeout");
                    } else {
                        // Direct: existing 3-consecutive-timeout logic
                        inner.consecutive_timeouts += 1;
                        if inner.consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                            error!(
                                bot = %bot.username,
                                consecutive = inner.consecutive_timeouts,
                                "Direct bot marked unhealthy after {} consecutive timeouts",
                                MAX_CONSECUTIVE_TIMEOUTS,
                            );
                        } else {
                            warn!(
                                bot = %bot.username,
                                consecutive = inner.consecutive_timeouts,
                                "GC inspect timed out"
                            );
                        }
                    }
                }
                Err(InspectError::SendFailed(_) | InspectError::ReceiveFailed(_)) => {
                    // Connection is dead, drop session (relog will reconnect)
                    inner.session = None;
                    inner.consecutive_timeouts = 0;
                    warn!(
                        bot = %bot.username,
                        error = %result.as_ref().unwrap_err(),
                        "Bot session dropped after send/receive failure"
                    );
                }
                _ => {}
            }

            return result;
        }

        Err(InspectError::NoBots)
    }

    pub fn bot_count(&self) -> usize {
        self.bots.len()
    }

    pub fn ready_count(&self) -> usize {
        self.bots
            .iter()
            .filter(|b| {
                match b.inner.try_lock() {
                    Ok(inner) => inner.session.is_some(),
                    Err(_) => true, // Locked = in use = effectively ready
                }
            })
            .count()
    }
}

/// Simple pseudo-random u64 using current time (no external crate needed).
fn rand_u64() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Mix nanoseconds for some entropy
    now.as_nanos() as u64 ^ (now.as_secs().wrapping_mul(6364136223846793005))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socks5_proxy() {
        let info = parse_proxy_url("socks5://user:pass@1.2.3.4:50100").unwrap();
        assert_eq!(info.protocol, ProxyProtocol::Socks5);
        assert_eq!(info.host, "1.2.3.4");
        assert_eq!(info.port, 50100);
        assert_eq!(info.username, "user");
        assert_eq!(info.password, "pass");
    }

    #[test]
    fn parse_http_proxy() {
        let info = parse_proxy_url("http://user:pass@1.2.3.4:8080").unwrap();
        assert_eq!(info.protocol, ProxyProtocol::Http);
        assert_eq!(info.host, "1.2.3.4");
        assert_eq!(info.port, 8080);
        assert_eq!(info.username, "user");
        assert_eq!(info.password, "pass");
    }

    #[test]
    fn parse_https_proxy() {
        let info = parse_proxy_url("https://user:pass@1.2.3.4:8443").unwrap();
        assert_eq!(info.protocol, ProxyProtocol::Http); // https:// maps to Http CONNECT
        assert_eq!(info.host, "1.2.3.4");
        assert_eq!(info.port, 8443);
    }

    #[test]
    fn parse_proxy_with_complex_password() {
        let info = parse_proxy_url("socks5://myuser:p@ss:word@10.0.0.1:1080").unwrap();
        assert_eq!(info.host, "10.0.0.1");
        assert_eq!(info.port, 1080);
        assert_eq!(info.username, "myuser");
        assert_eq!(info.password, "p@ss:word");
    }

    #[test]
    fn parse_proxy_invalid() {
        assert!(parse_proxy_url("ftp://1.2.3.4:8080").is_none());
        assert!(parse_proxy_url("socks5://noauth@1.2.3.4:8080").is_none());
        assert!(parse_proxy_url("garbage").is_none());
    }

    #[test]
    fn find_header_end_works() {
        assert_eq!(find_header_end(b"HTTP/1.1 200\r\n\r\n"), Some(16));
        assert_eq!(find_header_end(b"HTTP/1.1 200\r\nFoo: bar\r\n\r\n"), Some(26));
        assert_eq!(find_header_end(b"no end yet"), None);
    }

    #[test]
    fn parse_wss_host_port_with_port() {
        assert_eq!(
            parse_wss_host_port("wss://ext2-par1.steamserver.net:27025/cmsocket/"),
            Some(("ext2-par1.steamserver.net", 27025))
        );
    }

    #[test]
    fn parse_wss_host_port_default() {
        assert_eq!(
            parse_wss_host_port("wss://cm2-mt1.steampowered.com/cmsocket/"),
            Some(("cm2-mt1.steampowered.com", 443))
        );
    }

    #[test]
    fn parse_wss_host_port_invalid() {
        assert!(parse_wss_host_port("http://example.com").is_none());
    }

    #[test]
    fn proxy_round_robin_assignment() {
        // 5 bots, 3 proxies → assignment: [0, 1, 2, 0, 1]
        let proxies = vec![0, 1, 2];
        let num_bots = 5;
        let assignments: Vec<usize> = (0..num_bots).map(|i| i % proxies.len()).collect();
        assert_eq!(assignments, vec![0, 1, 2, 0, 1]);
    }

    #[test]
    fn bots_config_deserialize_with_proxies() {
        let json = r#"{
            "bots": [
                { "username": "bot1", "password": "pass1", "shared_secret": "secret1" }
            ],
            "proxies": [
                "socks5://user:pass@1.2.3.4:50100"
            ]
        }"#;
        let config: BotsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.bots.len(), 1);
        assert_eq!(config.proxies.len(), 1);
    }

    #[test]
    fn bots_config_deserialize_without_proxies() {
        let json = r#"{
            "bots": [
                { "username": "bot1", "password": "pass1", "shared_secret": "secret1" }
            ]
        }"#;
        let config: BotsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.bots.len(), 1);
        assert!(config.proxies.is_empty());
    }
}
