use std::time::Duration;

use tokio::time::timeout;
use tracing::debug;

use steam_vent::ConnectionTrait;
use steam_vent::GameCoordinator;
use steam_vent::proto::csgo::cstrike15_gcmessages::{
    CMsgGCCStrike15_v2_Client2GCEconPreviewDataBlockRequest,
    CMsgGCCStrike15_v2_Client2GCEconPreviewDataBlockResponse,
};

use super::link_parser::InspectParams;
use super::types::{InspectData, StickerData};

/// Send an inspect request to the CS2 Game Coordinator and parse the response.
pub async fn inspect_item(
    gc: &GameCoordinator,
    params: &InspectParams,
    timeout_secs: u64,
) -> Result<InspectData, InspectError> {
    // Build request
    let mut req = CMsgGCCStrike15_v2_Client2GCEconPreviewDataBlockRequest::default();
    req.param_a = Some(params.a);
    req.param_d = Some(params.d);
    match (params.s, params.m) {
        (Some(s), _) => {
            req.param_s = Some(s);
            req.param_m = Some(0);
        }
        (_, Some(m)) => {
            req.param_m = Some(m);
            req.param_s = Some(0);
        }
        _ => {
            req.param_s = Some(0);
            req.param_m = Some(0);
        }
    }

    debug!(
        a = params.a,
        d = params.d,
        s = params.s,
        m = params.m,
        "Sending GC inspect request (msg_id=9156)"
    );

    // Set up listener BEFORE sending (to not miss the response)
    let response_future =
        gc.one::<CMsgGCCStrike15_v2_Client2GCEconPreviewDataBlockResponse>();

    // Send request
    gc.send(req)
        .await
        .map_err(|e| InspectError::SendFailed(e.to_string()))?;
    debug!("GC inspect request sent, waiting for response (msg_id=9157)...");

    // Wait for response with timeout
    let resp = timeout(Duration::from_secs(timeout_secs), response_future)
        .await
        .map_err(|_| InspectError::Timeout)?
        .map_err(|e| InspectError::ReceiveFailed(e.to_string()))?;
    debug!("GC inspect response received");

    // Extract item data from response
    let item = resp
        .iteminfo
        .as_ref()
        .ok_or(InspectError::NoItemInfo)?;

    // Validate response matches requested asset (defense against stale/unsolicited GC messages)
    if let Some(returned_id) = item.itemid {
        if returned_id != params.a {
            return Err(InspectError::WrongAsset {
                expected: params.a,
                got: returned_id,
            });
        }
    }

    // paintwear (u32 IEEE 754 bit pattern) → f32
    let paintwear_raw = item.paintwear.unwrap_or(0);
    let floatvalue = f32::from_bits(paintwear_raw);

    // Map stickers
    let stickers: Vec<StickerData> = item
        .stickers
        .iter()
        .map(|s| StickerData {
            slot: s.slot.unwrap_or(0),
            sticker_id: s.sticker_id.unwrap_or(0),
            wear: s.wear,
            scale: s.scale,
            rotation: s.rotation,
            tint_id: s.tint_id,
        })
        .collect();

    Ok(InspectData {
        accountid: item.accountid.map(|id| id.to_string()),
        itemid: item.itemid.unwrap_or(0).to_string(),
        defindex: item.defindex.unwrap_or(0),
        paintindex: item.paintindex.unwrap_or(0),
        rarity: item.rarity.unwrap_or(0),
        quality: item.quality.unwrap_or(0),
        paintwear: item.paintwear,
        paintseed: item.paintseed.unwrap_or(0),
        killeaterscoretype: item.killeaterscoretype,
        killeatervalue: item.killeatervalue,
        customname: item.customname.clone(),
        stickers,
        inventory: item.inventory,
        origin: item.origin.unwrap_or(0),
        questid: item.questid,
        dropreason: item.dropreason,
        musicindex: item.musicindex,
        s: params.s.map(|v| v.to_string()),
        a: params.a.to_string(),
        d: params.d.to_string(),
        m: params.m.map(|v| v.to_string()),
        floatvalue,
    })
}

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug)]
pub enum InspectError {
    SendFailed(String),
    ReceiveFailed(String),
    Timeout,
    NoItemInfo,
    WrongAsset { expected: u64, got: u64 },
    NoBots,
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendFailed(e) => write!(f, "Failed to send GC request: {}", e),
            Self::ReceiveFailed(e) => write!(f, "Failed to receive GC response: {}", e),
            Self::Timeout => write!(f, "GC request timed out"),
            Self::NoItemInfo => write!(f, "No item info in GC response"),
            Self::WrongAsset { expected, got } => {
                write!(f, "GC response asset mismatch: expected {expected}, got {got}")
            }
            Self::NoBots => write!(f, "No bots available"),
        }
    }
}

impl std::error::Error for InspectError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #[test]
    fn paintwear_to_float() {
        // Known mapping: paintwear 1045220557 → ~0.2099 (Field-Tested)
        let paintwear: u32 = 1045220557;
        let float = f32::from_bits(paintwear);
        assert!(float > 0.0 && float < 1.0, "Float should be in [0, 1): {}", float);
    }

    #[test]
    fn paintwear_zero() {
        let float = f32::from_bits(0u32);
        assert_eq!(float, 0.0);
    }

    #[test]
    fn paintwear_factory_new() {
        // Factory New range: 0.00 - 0.07
        let paintwear: u32 = f32::to_bits(0.05);
        let float = f32::from_bits(paintwear);
        assert!(float < 0.07, "Factory New should be < 0.07: {}", float);
        assert!((float - 0.05).abs() < f32::EPSILON);
    }
}
