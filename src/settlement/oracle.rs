//! Core settlement decision engine.
//!
//! Takes MPC-TLS plaintext (server_name, sent/recv bytes) + escrow snapshot,
//! validates the Steam response, and determines Release or Refund.

use super::decision;
use super::parsing::{
    self, ParseError, detect_proof_source, extract_http_body, extract_steam_id_from_cookie,
};
use super::types::{Decision, EscrowSnapshot, ProofSource, RefundReason, Settlement};

/// Steam API server hostname
const STEAM_API_HOST: &str = "api.steampowered.com";

/// Steam Community server hostname
const STEAM_COMMUNITY_HOST: &str = "steamcommunity.com";

#[derive(Debug)]
pub enum SettlementError {
    InvalidServer(String),
    UnknownProofSource,
    ParseFailed(ParseError),
    TradeOfferIdMismatch { expected: u64, got: u64 },
    AssetIdMismatch { expected: u64, got: Option<u64> },
    PartnerMismatch { expected: u64, got: u64 },
    NonTerminalState(u32),
    NoAssetInProof,
    /// Trade accepted — release, but asset validation on the claim path
    TradeAccepted,
}

impl std::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettlementError::InvalidServer(s) => write!(f, "Invalid server: {s}"),
            SettlementError::UnknownProofSource => write!(f, "Unknown proof source from request URL"),
            SettlementError::ParseFailed(e) => write!(f, "Parse error: {e}"),
            SettlementError::TradeOfferIdMismatch { expected, got } => {
                write!(f, "TradeOfferId mismatch: expected {expected}, got {got}")
            }
            SettlementError::AssetIdMismatch { expected, got } => {
                write!(f, "AssetId mismatch: expected {expected}, got {got:?}")
            }
            SettlementError::PartnerMismatch { expected, got } => {
                write!(f, "Partner SteamId mismatch: expected {expected}, got {got}")
            }
            SettlementError::NonTerminalState(s) => {
                write!(f, "Non-terminal trade state: {s}")
            }
            SettlementError::NoAssetInProof => write!(f, "No CS2 asset found in proof"),
            SettlementError::TradeAccepted => write!(f, "Trade accepted (claim path)"),
        }
    }
}

impl std::error::Error for SettlementError {}

/// Core decision function: parse MPC-TLS plaintext + validate against escrow.
///
/// # Arguments
/// * `server_name` - TLS server name from VerifierOutput (e.g. "api.steampowered.com")
/// * `sent_bytes` - Raw HTTP request bytes from MPC-TLS transcript
/// * `recv_bytes` - Raw HTTP response bytes from MPC-TLS transcript
/// * `escrow` - On-chain escrow snapshot from the extension
///
/// # Returns
/// * `Ok(Settlement)` - Decision to release or refund
/// * `Err(SettlementError)` - Validation failed
pub fn decide(
    server_name: &str,
    sent_bytes: &[u8],
    recv_bytes: &[u8],
    escrow: &EscrowSnapshot,
) -> Result<Settlement, SettlementError> {
    // 1. Validate server is a Steam server
    if server_name != STEAM_API_HOST && server_name != STEAM_COMMUNITY_HOST {
        return Err(SettlementError::InvalidServer(server_name.to_string()));
    }

    // 2. Detect proof source from request URL
    let proof_source = detect_proof_source(sent_bytes)
        .ok_or(SettlementError::UnknownProofSource)?;

    // 3. Extract HTTP body and parse
    let body = extract_http_body(recv_bytes)
        .map_err(SettlementError::ParseFailed)?;

    match proof_source {
        ProofSource::TradeOffer => decide_trade_offer(sent_bytes, &body, escrow),
        ProofSource::TradeStatus => decide_trade_status(&body, escrow),
        ProofSource::Community => decide_community(sent_bytes, recv_bytes, escrow),
    }
}

/// Decide based on GetTradeOffer response (refund path)
fn decide_trade_offer(
    sent_bytes: &[u8],
    json: &str,
    escrow: &EscrowSnapshot,
) -> Result<Settlement, SettlementError> {
    let data = parsing::parse_trade_offer(json)
        .map_err(SettlementError::ParseFailed)?;

    // Validate trade offer ID matches escrow
    if data.trade_offer_id != escrow.trade_offer_id {
        return Err(SettlementError::TradeOfferIdMismatch {
            expected: escrow.trade_offer_id,
            got: data.trade_offer_id,
        });
    }

    // Determine capturer identity:
    // 1. Try steamLoginSecure cookie (SteamCommunity / legacy path)
    // 2. Fall back to inferring from accountid_other + escrow (API access_token path)
    let (capturer_is_seller, _capturer_is_buyer) =
        if let Ok(capturer_steam_id) = extract_steam_id_from_cookie(sent_bytes) {
            let is_seller = capturer_steam_id == escrow.seller_steam_id;
            let is_buyer = capturer_steam_id == escrow.buyer_steam_id;
            if !is_seller && !is_buyer {
                return Err(SettlementError::PartnerMismatch {
                    expected: escrow.seller_steam_id,
                    got: capturer_steam_id,
                });
            }
            (is_seller, is_buyer)
        } else {
            // No cookie — infer capturer from accountid_other (the counterparty)
            // If partner == buyer, capturer must be seller, and vice versa
            if data.partner_steam_id == escrow.buyer_steam_id {
                (true, false) // capturer = seller
            } else if data.partner_steam_id == escrow.seller_steam_id {
                (false, true) // capturer = buyer
            } else {
                return Err(SettlementError::PartnerMismatch {
                    expected: escrow.buyer_steam_id,
                    got: data.partner_steam_id,
                });
            }
        };

    // Validate partner steam ID (accountid_other should be the counterparty)
    let expected_partner = if capturer_is_seller {
        escrow.buyer_steam_id
    } else {
        escrow.seller_steam_id
    };
    if data.partner_steam_id != expected_partner {
        return Err(SettlementError::PartnerMismatch {
            expected: expected_partner,
            got: data.partner_steam_id,
        });
    }

    // Validate CS2 asset
    let asset_in_proof = data.asset_to_give.or(data.asset_to_receive);
    if let Some(asset) = asset_in_proof {
        if asset != escrow.asset_id {
            return Err(SettlementError::AssetIdMismatch {
                expected: escrow.asset_id,
                got: Some(asset),
            });
        }
    }

    // State 3 = Accepted → claim path (release)
    if data.state == 3 {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        });
    }

    // Non-terminal states should not produce settlements
    if decision::is_non_terminal_state(data.state) {
        return Err(SettlementError::NonTerminalState(data.state));
    }

    // Determine fault attribution
    let refund_reason = match data.state {
        5 => {
            let seller_created = decision::determine_seller_created_offer(
                capturer_is_seller,
                data.is_our_offer,
            );
            decision::fault_for_expired(seller_created)
        }
        6 => {
            let seller_created = decision::determine_seller_created_offer(
                capturer_is_seller,
                data.is_our_offer,
            );
            decision::fault_for_canceled(seller_created)
        }
        7 => {
            let seller_created = decision::determine_seller_created_offer(
                capturer_is_seller,
                data.is_our_offer,
            );
            decision::fault_for_declined(seller_created)
        }
        8 => RefundReason::InvalidItems,
        10 => RefundReason::Canceled2FA,
        _ => return Err(SettlementError::NonTerminalState(data.state)),
    };

    Ok(Settlement {
        asset_id: escrow.asset_id,
        trade_offer_id: escrow.trade_offer_id,
        decision: Decision::Refund,
        refund_reason,
    })
}

/// Decide based on GetTradeStatus response (claim path)
fn decide_trade_status(
    json: &str,
    escrow: &EscrowSnapshot,
) -> Result<Settlement, SettlementError> {
    let data = parsing::parse_trade_status(json)
        .map_err(SettlementError::ParseFailed)?;

    // Validate partner
    if data.partner_steam_id != 0 {
        let is_buyer = data.partner_steam_id == escrow.buyer_steam_id;
        let is_seller = data.partner_steam_id == escrow.seller_steam_id;
        if !is_buyer && !is_seller {
            return Err(SettlementError::PartnerMismatch {
                expected: escrow.buyer_steam_id,
                got: data.partner_steam_id,
            });
        }
    }

    // Validate asset
    let asset_in_proof = data.asset_id_given.or(data.asset_id);
    if let Some(asset) = asset_in_proof {
        if asset != escrow.asset_id {
            return Err(SettlementError::AssetIdMismatch {
                expected: escrow.asset_id,
                got: Some(asset),
            });
        }
    }

    // Status 3 in GetTradeStatus = completed trade → release
    if data.status == 3 {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Release,
            refund_reason: RefundReason::None,
        });
    }

    // Status 1 = failed → refund with TradeRollback
    if data.status == 1 {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Refund,
            refund_reason: RefundReason::TradeRollback,
        });
    }

    Err(SettlementError::NonTerminalState(data.status))
}

/// Decide based on Community HTML page (trade-not-found proof → refund)
fn decide_community(
    sent_bytes: &[u8],
    recv_bytes: &[u8],
    escrow: &EscrowSnapshot,
) -> Result<Settlement, SettlementError> {
    let data = parsing::parse_community_html(sent_bytes, recv_bytes)
        .map_err(SettlementError::ParseFailed)?;

    // Validate trade offer ID
    if data.trade_offer_id != escrow.trade_offer_id {
        return Err(SettlementError::TradeOfferIdMismatch {
            expected: escrow.trade_offer_id,
            got: data.trade_offer_id,
        });
    }

    // Trade not found on community page → refund as TradeNotExist
    if data.trade_not_found {
        return Ok(Settlement {
            asset_id: escrow.asset_id,
            trade_offer_id: escrow.trade_offer_id,
            decision: Decision::Refund,
            refund_reason: RefundReason::TradeNotExist,
        });
    }

    Err(SettlementError::ParseFailed(ParseError::CommunityTradeExists))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_escrow() -> EscrowSnapshot {
        EscrowSnapshot {
            asset_id: 40964044588,
            trade_offer_id: 8653813160,
            seller_steam_id: 76561198366018280,
            buyer_steam_id: 76561198404282737,
            seller: [0; 20],
            buyer: [0; 20],
            amount: 1000000,
            purchase_time: 1700000000,
        }
    }

    fn make_http_response(json: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{json}").into_bytes()
    }

    fn make_trade_offer_request(capturer_steam_id: u64) -> Vec<u8> {
        format!(
            "GET /IEconService/GetTradeOffer/v1/?tradeofferid=8653813160 HTTP/1.1\r\n\
             Host: api.steampowered.com\r\n\
             Cookie: steamLoginSecure={capturer_steam_id}%7C%7CeyToken\r\n\r\n"
        ).into_bytes()
    }

    #[test]
    fn test_decide_trade_offer_accepted_release() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":3,"accountid_other":444017009,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow).unwrap();
        assert_eq!(result.decision, Decision::Release);
        assert_eq!(result.refund_reason, RefundReason::None);
    }

    #[test]
    fn test_decide_trade_offer_expired_seller_created() {
        let escrow = test_escrow();
        // Seller captures, is_our_offer=true → seller created → BuyerExpired
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":444017009,"is_our_offer":true,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::BuyerExpired);
    }

    #[test]
    fn test_decide_trade_offer_canceled_by_2fa() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":10,"accountid_other":444017009,"items_to_give":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::Canceled2FA);
    }

    #[test]
    fn test_decide_invalid_server() {
        let escrow = test_escrow();
        let result = decide("evil.com", b"GET /", b"HTTP/1.1 200\r\n\r\n{}", &escrow);
        assert!(matches!(result, Err(SettlementError::InvalidServer(_))));
    }

    #[test]
    fn test_decide_trade_offer_id_mismatch() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"999999","trade_offer_state":3,"accountid_other":444017009,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow);
        assert!(matches!(result, Err(SettlementError::TradeOfferIdMismatch { .. })));
    }

    /// Helper: API access token request (no steamLoginSecure cookie)
    fn make_trade_offer_request_api_token() -> Vec<u8> {
        b"GET /IEconService/GetTradeOffer/v1/?format=json&get_descriptions=false&tradeofferid=8653813160&access_token=SECRET HTTP/1.1\r\n\
          Host: api.steampowered.com\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n".to_vec()
    }

    #[test]
    fn test_decide_trade_offer_api_token_release() {
        let escrow = test_escrow();
        // No cookie — capturer inferred from accountid_other
        // accountid_other=444017009 → partner=76561198404282737 (buyer) → capturer=seller
        let sent = make_trade_offer_request_api_token();
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":3,"accountid_other":444017009,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow).unwrap();
        assert_eq!(result.decision, Decision::Release);
        assert_eq!(result.refund_reason, RefundReason::None);
    }

    #[test]
    fn test_decide_trade_offer_api_token_expired() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        // accountid_other=444017009 → partner=buyer → capturer=seller, is_our_offer=true → seller created → BuyerExpired
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":5,"accountid_other":444017009,"is_our_offer":true,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow).unwrap();
        assert_eq!(result.decision, Decision::Refund);
        assert_eq!(result.refund_reason, RefundReason::BuyerExpired);
    }

    #[test]
    fn test_decide_trade_offer_api_token_unknown_partner() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request_api_token();
        // accountid_other=999 → partner=76561198404265727 — neither buyer nor seller
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":3,"accountid_other":999,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow);
        assert!(matches!(result, Err(SettlementError::PartnerMismatch { .. })));
    }

    #[test]
    fn test_decide_non_terminal_state() {
        let escrow = test_escrow();
        let sent = make_trade_offer_request(escrow.seller_steam_id);
        let json = r#"{"response":{"offer":{"tradeofferid":"8653813160","trade_offer_state":2,"accountid_other":444017009,"items_to_receive":[{"appid":730,"assetid":"40964044588"}]}}}"#;
        let recv = make_http_response(json);

        let result = decide(STEAM_API_HOST, &sent, &recv, &escrow);
        assert!(matches!(result, Err(SettlementError::NonTerminalState(2))));
    }
}
