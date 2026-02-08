use eyre::{Result, eyre};
use k256::ecdsa::SigningKey;
use tlsn::attestation::{signing::Secp256k1Signer, CryptoProvider};
use tracing::info;

/// Holds the notary's signing key material.
pub struct NotaryKey {
    pub provider: CryptoProvider,
    pub public_key: Vec<u8>,
}

/// Create a NotaryKey with crypto provider and extracted public key.
///
/// Key resolution order:
/// 1. `NOTARY_SIGNING_KEY` env var (raw 64-char hex private key)
/// 2. `pem_path` config (file path to PEM or hex key file)
/// 3. Ephemeral random key (development only)
pub fn create_notary_key(pem_path: Option<&str>) -> Result<NotaryKey> {
    let signing_key = if let Ok(hex_key) = std::env::var("NOTARY_SIGNING_KEY") {
        let hex_key = hex_key.trim();
        let key_bytes =
            hex::decode(hex_key).map_err(|e| eyre!("NOTARY_SIGNING_KEY invalid hex: {}", e))?;
        info!("Using signing key from NOTARY_SIGNING_KEY env var");
        SigningKey::from_slice(&key_bytes)
            .map_err(|e| eyre!("NOTARY_SIGNING_KEY invalid secp256k1 key: {}", e))?
    } else if let Some(path) = pem_path {
        load_signing_key(path)?
    } else {
        info!("No signing key configured, generating ephemeral key");
        SigningKey::random(&mut rand::thread_rng())
    };

    let public_key = signing_key.verifying_key().to_sec1_bytes().to_vec();
    info!(
        "Notary public key (secp256k1): {}",
        hex::encode(&public_key)
    );

    let signer = Box::new(
        Secp256k1Signer::new(&signing_key.to_bytes())
            .map_err(|e| eyre!("Failed to create signer: {}", e))?,
    );

    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    Ok(NotaryKey {
        provider,
        public_key,
    })
}

/// Load a secp256k1 signing key from file.
///
/// Supports:
/// - Raw 32-byte hex string (64 hex chars)
/// - PKCS8 PEM format
fn load_signing_key(path: &str) -> Result<SigningKey> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| eyre!("Failed to read key file '{}': {}", path, e))?;

    let data = data.trim();

    // Try raw hex key first (simplest format).
    if data.len() == 64 && data.chars().all(|c| c.is_ascii_hexdigit()) {
        let key_bytes =
            hex::decode(data).map_err(|e| eyre!("Failed to decode hex key: {}", e))?;
        return SigningKey::from_slice(&key_bytes)
            .map_err(|e| eyre!("Invalid secp256k1 key: {}", e));
    }

    // Try PKCS8 PEM format.
    let base64_content: String = data
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    use base64::Engine;
    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(&base64_content)
        .map_err(|e| eyre!("Failed to decode PEM base64: {}", e))?;

    // Try SEC1 DER first, then PKCS8 DER.
    use k256::pkcs8::DecodePrivateKey;
    k256::SecretKey::from_sec1_der(&der_bytes)
        .or_else(|_| k256::SecretKey::from_pkcs8_der(&der_bytes))
        .map(|sk| SigningKey::from(&sk))
        .map_err(|e| eyre!("Failed to parse key file (tried SEC1 and PKCS8): {}", e))
}
