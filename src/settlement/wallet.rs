//! Oracle on-chain submission via alloy.
//!
//! Uses alloy `sol!` for the function selector + packed `bytes calldata`
//! (10B per settlement) for gas-efficient L2 submission.

use alloy::{
    network::EthereumWallet,
    primitives::{Address, FixedBytes, TxHash},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use eyre::{Result, eyre};
use tracing::info;

use super::types::Settlement;
use crate::config::OracleConfig;

sol! {
    /// Contract function: accepts packed bytes, not ABI-encoded structs.
    /// Each settlement is 10 bytes: [u64 assetId BE | u8 decision | u8 refundReason]
    #[sol(rpc)]
    contract JJSKINSettlement {
        function settleByOracle(
            bytes32 batchHash,
            bytes calldata settlements
        ) external;
    }
}

/// Pack settlements into bytes: 10 bytes each.
/// Layout: [u64 assetId big-endian | u8 decision | u8 refundReason] x N
fn pack_settlements(settlements: &[Settlement]) -> Vec<u8> {
    let mut data = Vec::with_capacity(settlements.len() * 10);
    for s in settlements {
        data.extend_from_slice(&s.asset_id.to_be_bytes()); // 8 bytes
        data.push(s.decision as u8);                        // 1 byte
        data.push(s.refund_reason as u8);                   // 1 byte
    }
    data
}

/// Oracle wallet for on-chain settlement submission.
pub struct OracleWallet {
    signer: PrivateKeySigner,
    rpc_url: String,
    contract_address: Address,
}

impl OracleWallet {
    /// Create from OracleConfig.
    ///
    /// Key resolution order:
    /// 1. `ORACLE_SIGNING_KEY` env var (raw 64-char hex private key)
    /// 2. `signing_key_path` config (file path to hex key)
    /// 3. Error (no ephemeral key for oracle — too dangerous)
    pub fn from_config(config: &OracleConfig) -> Result<Self> {
        let signer = if let Ok(hex_key) = std::env::var("ORACLE_SIGNING_KEY") {
            let hex_key = hex_key.trim();
            hex_key.parse::<PrivateKeySigner>()
                .map_err(|e| eyre!("ORACLE_SIGNING_KEY invalid: {e}"))?
        } else if let Some(path) = &config.signing_key_path {
            let data = std::fs::read_to_string(path)
                .map_err(|e| eyre!("Failed to read oracle key file '{path}': {e}"))?;
            let data = data.trim();
            data.parse::<PrivateKeySigner>()
                .map_err(|e| eyre!("Invalid oracle key in '{path}': {e}"))?
        } else {
            return Err(eyre!("Oracle signing key required: set ORACLE_SIGNING_KEY env or oracle.signing_key_path config"));
        };

        let rpc_url = config.rpc_url.clone()
            .ok_or_else(|| eyre!("oracle.rpc_url is required"))?;

        let contract_address: Address = config.contract_address.as_ref()
            .ok_or_else(|| eyre!("oracle.contract_address is required"))?
            .parse()
            .map_err(|e| eyre!("Invalid contract address: {e}"))?;

        info!(
            "Oracle wallet initialized: address={}, contract={}",
            signer.address(),
            contract_address
        );

        Ok(Self {
            signer,
            rpc_url,
            contract_address,
        })
    }

    /// Get the oracle's Ethereum address.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Submit settlement(s) on-chain.
    ///
    /// Builds a `settleByOracle(batchHash, packedSettlements)` transaction,
    /// signs it, and broadcasts.
    pub async fn settle_on_chain(
        &self,
        batch_hash: [u8; 32],
        settlements: &[Settlement],
    ) -> Result<TxHash> {
        let wallet = EthereumWallet::from(self.signer.clone());

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.rpc_url.parse()?);

        let contract = JJSKINSettlement::new(self.contract_address, &provider);

        let packed = pack_settlements(settlements);

        info!(
            "Submitting settlement: batch_hash={}, settlements={}, packed_bytes={}",
            hex::encode(batch_hash),
            settlements.len(),
            packed.len()
        );

        let tx = contract
            .settleByOracle(FixedBytes::from(batch_hash), packed.into())
            .send()
            .await
            .map_err(|e| eyre!("Failed to send settlement tx: {e}"))?;

        let tx_hash = *tx.tx_hash();

        info!("Settlement tx sent: {tx_hash}");

        Ok(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::types::{Decision, RefundReason};

    #[test]
    fn test_pack_single_release() {
        let settlements = vec![Settlement {
            asset_id: 12345,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        }];

        let packed = pack_settlements(&settlements);
        assert_eq!(packed.len(), 10);
        assert_eq!(&packed[0..8], &12345u64.to_be_bytes());
        assert_eq!(packed[8], 0); // Release
        assert_eq!(packed[9], 0); // None
    }

    #[test]
    fn test_pack_single_refund() {
        let settlements = vec![Settlement {
            asset_id: 99999,
            decision: Decision::Refund,
            refund_reason: RefundReason::BuyerExpired,
        }];

        let packed = pack_settlements(&settlements);
        assert_eq!(packed.len(), 10);
        assert_eq!(&packed[0..8], &99999u64.to_be_bytes());
        assert_eq!(packed[8], 1); // Refund
        assert_eq!(packed[9], 7); // BuyerExpired
    }

    #[test]
    fn test_pack_multiple() {
        let settlements = vec![
            Settlement {
                asset_id: 111,
                decision: Decision::Release,
                refund_reason: RefundReason::None,
            },
            Settlement {
                asset_id: 222,
                decision: Decision::Refund,
                refund_reason: RefundReason::SellerCanceled,
            },
        ];

        let packed = pack_settlements(&settlements);
        assert_eq!(packed.len(), 20);
        // First settlement
        assert_eq!(&packed[0..8], &111u64.to_be_bytes());
        assert_eq!(packed[8], 0);
        assert_eq!(packed[9], 0);
        // Second settlement
        assert_eq!(&packed[10..18], &222u64.to_be_bytes());
        assert_eq!(packed[18], 1);
        assert_eq!(packed[19], 10); // SellerCanceled
    }

    #[test]
    fn test_pack_empty() {
        let packed = pack_settlements(&[]);
        assert!(packed.is_empty());
    }
}
