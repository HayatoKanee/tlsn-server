use std::path::Path;

use serde::Deserialize;
use tracing::{info, warn};

/// Server configuration loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub notarization: NotarizationConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub oracle: OracleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotarizationConfig {
    /// Maximum bytes the prover can send through TLS.
    #[serde(default = "default_max_sent_data")]
    pub max_sent_data: usize,
    /// Maximum bytes the prover can receive through TLS.
    #[serde(default = "default_max_recv_data")]
    pub max_recv_data: usize,
    /// Timeout for the notarization session in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Path to secp256k1 private key in PEM (PKCS8) format.
    /// If null/missing, an ephemeral key is generated on startup.
    pub private_key_pem_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub private_key_path: Option<String>,
    pub certificate_path: Option<String>,
}

/// Oracle settlement configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct OracleConfig {
    /// Enable oracle settlement mode.
    #[serde(default)]
    pub enabled: bool,
    /// Path to oracle Ethereum private key (hex format).
    pub signing_key_path: Option<String>,
    /// Ethereum RPC URL (e.g. Arbitrum).
    pub rpc_url: Option<String>,
    /// JJSKIN contract address.
    pub contract_address: Option<String>,
    /// Chain ID (default: 42161 for Arbitrum One).
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            notarization: NotarizationConfig::default(),
            tls: TlsConfig::default(),
            oracle: OracleConfig::default(),
        }
    }
}

impl Default for NotarizationConfig {
    fn default() -> Self {
        Self {
            max_sent_data: default_max_sent_data(),
            max_recv_data: default_max_recv_data(),
            timeout: default_timeout(),
            private_key_pem_path: None,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            private_key_path: None,
            certificate_path: None,
        }
    }
}

impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            signing_key_path: None,
            rpc_url: None,
            contract_address: None,
            chain_id: default_chain_id(),
        }
    }
}

impl Config {
    /// Load configuration from a YAML file.
    /// Returns default config if the file doesn't exist or can't be parsed.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => match serde_yaml::from_str(&contents) {
                Ok(config) => {
                    info!("Loaded config from {:?}", path);
                    config
                }
                Err(e) => {
                    warn!("Failed to parse config file {:?}: {}", path, e);
                    Self::default()
                }
            },
            Err(_) => {
                info!("No config file found at {:?}, using defaults", path);
                Self::default()
            }
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    7047
}

fn default_max_sent_data() -> usize {
    4096
}

fn default_max_recv_data() -> usize {
    16384
}

fn default_timeout() -> u64 {
    120
}

fn default_chain_id() -> u64 {
    42161 // Arbitrum One
}
