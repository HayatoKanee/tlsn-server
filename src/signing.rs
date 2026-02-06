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
/// If `pem_path` is Some, loads a secp256k1 key from a PEM or hex file.
/// If None, generates a random ephemeral key (suitable for development).
pub fn create_notary_key(pem_path: Option<&str>) -> Result<NotaryKey> {
    let signing_key = match pem_path {
        Some(path) => load_signing_key(path)?,
        None => {
            info!("No signing key configured, generating ephemeral key");
            SigningKey::random(&mut rand::thread_rng())
        }
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

    // Try SEC1 DER, then try extracting raw key bytes from PKCS8.
    k256::SecretKey::from_sec1_der(&der_bytes)
        .or_else(|_| {
            if der_bytes.len() >= 32 {
                let key_bytes = &der_bytes[der_bytes.len() - 32..];
                k256::SecretKey::from_slice(key_bytes)
            } else {
                Err(k256::elliptic_curve::Error)
            }
        })
        .map(|sk| SigningKey::from(&sk))
        .map_err(|e| eyre!("Failed to parse key file: {}", e))
}
