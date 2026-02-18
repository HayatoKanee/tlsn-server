use serde::Serialize;
use std::collections::HashMap;

// ============================================================================
// CSFloat-compatible response types
// ============================================================================

/// Item inspection data — matches CSFloat's JSON response shape exactly.
///
/// The dapp's `CSFloatInspectData` TypeScript interface expects these fields.
/// Enrichment fields (weapon_type, item_name, wear_name, etc.) are NOT provided
/// since the dapp's adapter handles item resolution from defindex/paintindex.
#[derive(Debug, Clone, Serialize)]
pub struct InspectData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accountid: Option<String>,
    pub itemid: String,
    pub defindex: u32,
    pub paintindex: u32,
    pub rarity: u32,
    pub quality: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paintwear: Option<u32>,
    pub paintseed: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub killeaterscoretype: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub killeatervalue: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customname: Option<String>,
    pub stickers: Vec<StickerData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory: Option<u32>,
    pub origin: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub questid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropreason: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub musicindex: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    pub a: String,
    pub d: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m: Option<String>,
    pub floatvalue: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct StickerData {
    pub slot: u32,
    pub sticker_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wear: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scale: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tint_id: Option<u32>,
}

// ============================================================================
// HTTP API types
// ============================================================================

/// GET /inspect response — matches CSFloat's single response format.
/// Extended with oracle attestation fields.
#[derive(Debug, Serialize)]
pub struct SingleResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteminfo: Option<InspectData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Packed uint64 item detail (decimal string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_detail: Option<String>,
    /// EIP-712 oracle signature ("0x" + 130 hex chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_signature: Option<String>,
}

/// POST /inspect/bulk response — keyed by asset ID.
pub type BulkResponse = HashMap<String, BulkItemResponse>;

/// Individual item in bulk response — either data or error.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum BulkItemResponse {
    Success {
        #[serde(flatten)]
        iteminfo: InspectData,
        #[serde(skip_serializing_if = "Option::is_none")]
        item_detail: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        oracle_signature: Option<String>,
    },
    Error {
        error: String,
    },
}

/// POST /inspect/bulk request body.
#[derive(Debug, serde::Deserialize)]
pub struct BulkRequest {
    pub links: Vec<BulkLink>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BulkLink {
    pub link: String,
}
