use super::types::RefundReason;

/// Determine fault for Expired state (state = 5)
///
/// Expired means the recipient didn't accept the trade in time.
/// - If seller created offer → recipient is buyer → BuyerExpired
/// - If buyer created offer → recipient is seller → SellerExpired
pub fn fault_for_expired(seller_created_offer: bool) -> RefundReason {
    if seller_created_offer {
        RefundReason::BuyerExpired
    } else {
        RefundReason::SellerExpired
    }
}

/// Determine fault for Canceled state (state = 6)
///
/// Canceled means the sender canceled their own offer.
/// - If seller created and canceled → SellerCanceled
/// - If buyer created and canceled → BuyerCanceled
pub fn fault_for_canceled(seller_created_offer: bool) -> RefundReason {
    if seller_created_offer {
        RefundReason::SellerCanceled
    } else {
        RefundReason::BuyerCanceled
    }
}

/// Determine fault for Declined state (state = 7)
///
/// Declined means the recipient declined the offer.
/// - If seller created offer → recipient is buyer → BuyerDeclined
/// - If buyer created offer → recipient is seller → SellerDeclined
pub fn fault_for_declined(seller_created_offer: bool) -> RefundReason {
    if seller_created_offer {
        RefundReason::BuyerDeclined
    } else {
        RefundReason::SellerDeclined
    }
}

/// Returns true for non-terminal states that should not be submitted as proofs.
pub fn is_non_terminal_state(state: u32) -> bool {
    !matches!(state, 5 | 6 | 7 | 8 | 10)
}

/// Determine who created the offer based on is_our_offer and capturer identity.
///
/// # Arguments
/// * `capturer_is_seller` - True if proof capturer is the seller
/// * `is_our_offer` - From Steam API, true if proof capturer created the offer
///
/// # Returns
/// True if seller created the offer
pub fn determine_seller_created_offer(capturer_is_seller: bool, is_our_offer: bool) -> bool {
    if capturer_is_seller {
        is_our_offer
    } else {
        !is_our_offer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expired_seller_created_offer() {
        assert_eq!(fault_for_expired(true), RefundReason::BuyerExpired);
    }

    #[test]
    fn test_expired_buyer_created_offer() {
        assert_eq!(fault_for_expired(false), RefundReason::SellerExpired);
    }

    #[test]
    fn test_canceled_seller_created_offer() {
        assert_eq!(fault_for_canceled(true), RefundReason::SellerCanceled);
    }

    #[test]
    fn test_canceled_buyer_created_offer() {
        assert_eq!(fault_for_canceled(false), RefundReason::BuyerCanceled);
    }

    #[test]
    fn test_declined_seller_created_offer() {
        assert_eq!(fault_for_declined(true), RefundReason::BuyerDeclined);
    }

    #[test]
    fn test_declined_buyer_created_offer() {
        assert_eq!(fault_for_declined(false), RefundReason::SellerDeclined);
    }

    #[test]
    fn test_seller_captures_seller_created_offer() {
        assert!(determine_seller_created_offer(true, true));
    }

    #[test]
    fn test_seller_captures_buyer_created_offer() {
        assert!(!determine_seller_created_offer(true, false));
    }

    #[test]
    fn test_buyer_captures_seller_created_offer() {
        assert!(determine_seller_created_offer(false, false));
    }

    #[test]
    fn test_buyer_captures_buyer_created_offer() {
        assert!(!determine_seller_created_offer(false, true));
    }

    #[test]
    fn test_terminal_states() {
        assert!(!is_non_terminal_state(5));
        assert!(!is_non_terminal_state(6));
        assert!(!is_non_terminal_state(7));
        assert!(!is_non_terminal_state(8));
        assert!(!is_non_terminal_state(10));
    }

    #[test]
    fn test_non_terminal_states_should_panic() {
        assert!(is_non_terminal_state(1));
        assert!(is_non_terminal_state(2));
        assert!(is_non_terminal_state(3));
        assert!(is_non_terminal_state(4));
        assert!(is_non_terminal_state(9));
        assert!(is_non_terminal_state(11));
    }

    #[test]
    fn test_refund_reason_values() {
        assert_eq!(RefundReason::None as u8, 0);
        assert_eq!(RefundReason::Timeout as u8, 1);
        assert_eq!(RefundReason::NotCS2Item as u8, 2);
        assert_eq!(RefundReason::WrongAsset as u8, 3);
        assert_eq!(RefundReason::WrongParties as u8, 4);
        assert_eq!(RefundReason::InvalidItems as u8, 5);
        assert_eq!(RefundReason::Canceled2FA as u8, 6);
        assert_eq!(RefundReason::BuyerExpired as u8, 7);
        assert_eq!(RefundReason::SellerExpired as u8, 8);
        assert_eq!(RefundReason::BuyerCanceled as u8, 9);
        assert_eq!(RefundReason::SellerCanceled as u8, 10);
        assert_eq!(RefundReason::BuyerDeclined as u8, 11);
        assert_eq!(RefundReason::SellerDeclined as u8, 12);
        assert_eq!(RefundReason::WrongRecipient as u8, 13);
        assert_eq!(RefundReason::TradeRollback as u8, 14);
        assert_eq!(RefundReason::DeprecatedRollback as u8, 15);
        assert_eq!(RefundReason::TradeNotExist as u8, 16);
    }
}
