/// Compute batch_hash for a single settlement by returning its commitment directly.
///
/// For single settlement: batch_hash = commitment (XOR identity).
/// For multiple settlements: XOR all commitments together.
///
/// Uses little-endian u64 chunks for cross-platform consistency.
pub fn compute_batch_hash(commitments: &[[u8; 32]]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for commitment in commitments {
        for chunk_idx in 0..4 {
            let start = chunk_idx * 8;
            let end = start + 8;
            let hash_chunk = u64::from_le_bytes(hash[start..end].try_into().unwrap());
            let commit_chunk = u64::from_le_bytes(commitment[start..end].try_into().unwrap());
            hash[start..end].copy_from_slice(&(hash_chunk ^ commit_chunk).to_le_bytes());
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_commitment_is_identity() {
        let commitment = [0xAB; 32];
        let hash = compute_batch_hash(&[commitment]);
        assert_eq!(hash, commitment);
    }

    #[test]
    fn test_xor_cancellation() {
        let commitment = [0xFF; 32];
        let hash = compute_batch_hash(&[commitment, commitment]);
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn test_xor_commutativity() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        let ab = compute_batch_hash(&[a, b]);
        let ba = compute_batch_hash(&[b, a]);
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_empty_is_zero() {
        let hash = compute_batch_hash(&[]);
        assert_eq!(hash, [0u8; 32]);
    }
}
