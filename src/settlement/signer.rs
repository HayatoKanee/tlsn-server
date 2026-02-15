use std::sync::LazyLock;

use alloy::primitives::{keccak256, Address, FixedBytes, B256};
use alloy::signers::{local::PrivateKeySigner, Signer};
use eyre::{Result, eyre};
use tracing::info;

use super::types::Settlement;
use crate::config::OracleConfig;

/// EIP-712 type hash: keccak256("Settlement(uint64 assetId,uint8 decision,uint8 refundReason)")
static SETTLEMENT_TYPEHASH: LazyLock<B256> =
    LazyLock::new(|| keccak256(b"Settlement(uint64 assetId,uint8 decision,uint8 refundReason)"));

/// EIP-712 domain separator type hash
static EIP712_DOMAIN_TYPEHASH: LazyLock<B256> = LazyLock::new(|| {
    keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
});

/// Oracle signer for EIP-712 settlement signatures.
///
/// Replaces OracleWallet — no on-chain calls, just signing.
/// The signed message is submitted to the contract by a relayer.
pub struct OracleSigner {
    signer: PrivateKeySigner,
    domain_separator: B256,
}

impl OracleSigner {
    /// Create from OracleConfig.
    ///
    /// Key resolution order:
    /// 1. `ORACLE_SIGNING_KEY` env var (raw 64-char hex private key)
    /// 2. `signing_key_path` config (file path to hex key)
    /// 3. Error (no ephemeral key for oracle — too dangerous)
    pub fn from_config(config: &OracleConfig) -> Result<Self> {
        let signer = if let Ok(hex_key) = std::env::var("ORACLE_SIGNING_KEY") {
            let hex_key = hex_key.trim();
            hex_key
                .parse::<PrivateKeySigner>()
                .map_err(|e| eyre!("ORACLE_SIGNING_KEY invalid: {e}"))?
        } else if let Some(path) = &config.signing_key_path {
            let data = std::fs::read_to_string(path)
                .map_err(|e| eyre!("Failed to read oracle key file '{path}': {e}"))?;
            let data = data.trim();
            data.parse::<PrivateKeySigner>()
                .map_err(|e| eyre!("Invalid oracle key in '{path}': {e}"))?
        } else {
            return Err(eyre!(
                "Oracle signing key required: set ORACLE_SIGNING_KEY env or oracle.signing_key_path config"
            ));
        };

        let contract_address: Address = config
            .contract_address
            .parse()
            .map_err(|e| eyre!("Invalid contract address: {e}"))?;

        let domain_separator = compute_domain_separator(config.chain_id, contract_address);

        info!(
            "Oracle signer initialized: address={}, contract={}, chain_id={}",
            signer.address(),
            contract_address,
            config.chain_id
        );

        Ok(Self {
            signer,
            domain_separator,
        })
    }

    /// Get the oracle's Ethereum address.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a settlement decision using EIP-712.
    ///
    /// Returns 65 bytes: r (32) || s (32) || v (1).
    /// Matches Solidity: `ECDSA.recover(_hashTypedDataV4(structHash), oracleSignature)`
    pub async fn sign_settlement(&self, settlement: &Settlement) -> Result<Vec<u8>> {
        let struct_hash = compute_struct_hash(settlement);
        let digest = compute_eip712_digest(self.domain_separator, struct_hash);

        let signature = self
            .signer
            .sign_hash(&digest)
            .await
            .map_err(|e| eyre!("Failed to sign settlement: {e}"))?;

        // as_bytes() returns [u8; 65]: r (32) || s (32) || v (1, 27 or 28)
        Ok(signature.as_bytes().to_vec())
    }
}

/// Compute EIP-712 domain separator.
///
/// Matches OpenZeppelin's EIP712("JJSKIN", "1"):
/// ```text
/// keccak256(abi.encode(
///     EIP712_DOMAIN_TYPEHASH,
///     keccak256("JJSKIN"),
///     keccak256("1"),
///     chainId,
///     verifyingContract
/// ))
/// ```
fn compute_domain_separator(chain_id: u64, contract_address: Address) -> B256 {
    let name_hash = keccak256(b"JJSKIN");
    let version_hash = keccak256(b"1");

    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice((*EIP712_DOMAIN_TYPEHASH).as_ref());
    encoded.extend_from_slice(name_hash.as_ref());
    encoded.extend_from_slice(version_hash.as_ref());
    // chainId as uint256 (left-padded to 32 bytes)
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(&chain_id.to_be_bytes()).0);
    // address as bytes32 (left-padded to 32 bytes)
    encoded.extend_from_slice(&FixedBytes::<32>::left_padding_from(contract_address.as_ref()).0);

    keccak256(&encoded)
}

/// Compute struct hash for Settlement.
///
/// Matches Solidity:
/// ```text
/// keccak256(abi.encode(SETTLEMENT_TYPEHASH, assetId, decision, refundReason))
/// ```
///
/// abi.encode pads each value to 32 bytes.
fn compute_struct_hash(settlement: &Settlement) -> B256 {
    let mut encoded = Vec::with_capacity(4 * 32);
    encoded.extend_from_slice((*SETTLEMENT_TYPEHASH).as_ref());
    // uint64 assetId → uint256 (left-padded to 32 bytes)
    encoded
        .extend_from_slice(&FixedBytes::<32>::left_padding_from(&settlement.asset_id.to_be_bytes()).0);
    // uint8 decision → uint256 (left-padded to 32 bytes)
    encoded
        .extend_from_slice(&FixedBytes::<32>::left_padding_from(&[settlement.decision as u8]).0);
    // uint8 refundReason → uint256 (left-padded to 32 bytes)
    encoded.extend_from_slice(
        &FixedBytes::<32>::left_padding_from(&[settlement.refund_reason as u8]).0,
    );

    keccak256(&encoded)
}

/// Compute EIP-712 digest: keccak256("\x19\x01" || domainSeparator || structHash)
fn compute_eip712_digest(domain_separator: B256, struct_hash: B256) -> B256 {
    let mut data = Vec::with_capacity(2 + 32 + 32);
    data.extend_from_slice(&[0x19, 0x01]);
    data.extend_from_slice(domain_separator.as_ref());
    data.extend_from_slice(struct_hash.as_ref());
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::types::{Decision, RefundReason};

    /// Test that EIP-712 signing produces a valid 65-byte signature
    /// and ecrecover yields the expected signer address.
    #[tokio::test]
    async fn test_sign_and_recover() {
        // Known private key for deterministic testing
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer: PrivateKeySigner = key_hex.parse().unwrap();
        let expected_address = signer.address();

        // Use Arbitrum chain ID and a dummy contract address
        let chain_id = 42161u64;
        let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();

        let domain_separator = compute_domain_separator(chain_id, contract_address);

        let oracle_signer = OracleSigner {
            signer,
            domain_separator,
        };

        let settlement = Settlement {
            asset_id: 12345,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        };

        let sig_bytes = oracle_signer.sign_settlement(&settlement).await.unwrap();
        assert_eq!(sig_bytes.len(), 65, "signature must be 65 bytes");

        // Verify ecrecover matches expected address
        let struct_hash = compute_struct_hash(&settlement);
        let digest = compute_eip712_digest(domain_separator, struct_hash);

        let v = sig_bytes[64];
        let sig = alloy::primitives::Signature::from_bytes_and_parity(&sig_bytes[..64], v != 27);
        let recovered = sig.recover_address_from_prehash(&digest).unwrap();
        assert_eq!(recovered, expected_address, "ecrecover must match signer address");
    }

    /// Test domain separator matches expected value for known inputs.
    #[test]
    fn test_domain_separator_deterministic() {
        let chain_id = 42161u64;
        let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            .parse()
            .unwrap();

        let sep1 = compute_domain_separator(chain_id, contract_address);
        let sep2 = compute_domain_separator(chain_id, contract_address);
        assert_eq!(sep1, sep2);

        // Different chain ID → different separator
        let sep3 = compute_domain_separator(1, contract_address);
        assert_ne!(sep1, sep3);
    }

    /// Test struct hash matches expected encoding.
    #[test]
    fn test_struct_hash_deterministic() {
        let s1 = Settlement {
            asset_id: 12345,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        };
        let s2 = Settlement {
            asset_id: 12345,
            decision: Decision::Refund,
            refund_reason: RefundReason::BuyerExpired,
        };

        let h1 = compute_struct_hash(&s1);
        let h2 = compute_struct_hash(&s2);
        assert_ne!(h1, h2, "different settlements must produce different hashes");

        // Same input → same hash
        let h3 = compute_struct_hash(&s1);
        assert_eq!(h1, h3);
    }
}
