pub mod bot_pool;
pub mod gc_client;
pub mod item_detail;
pub mod link_parser;
pub mod types;

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::{debug, error, info};

use bot_pool::BotPool;
use item_detail::encode_item_detail;
use link_parser::parse_inspect_link;
use types::{BulkItemResponse, BulkRequest, BulkResponse, InspectData, SingleResponse};

use crate::settlement::OracleSigner;

// ============================================================================
// State
// ============================================================================

/// Shared state for inspect routes: bot pool + oracle signer.
pub struct InspectState {
    pub pool: BotPool,
    pub signer: Arc<OracleSigner>,
}

// ============================================================================
// Query types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct InspectQuery {
    pub url: String,
}

// ============================================================================
// Route handlers
// ============================================================================

/// Sign item attestation for inspect data, returning (item_detail, oracle_signature).
async fn sign_inspect_data(
    signer: &OracleSigner,
    asset_id: u64,
    data: &InspectData,
) -> (Option<String>, Option<String>) {
    let item_detail = encode_item_detail(
        data.paintindex,
        data.floatvalue,
        data.defindex,
        data.paintseed,
        data.quality,
        // tint_id: use first sticker's tint_id if present and no paint (graffiti),
        // otherwise 0
        if data.paintindex == 0 {
            data.stickers.first().and_then(|s| s.tint_id).unwrap_or(0)
        } else {
            0
        },
    );

    match signer.sign_item_attestation(asset_id, item_detail).await {
        Ok(sig_bytes) => {
            let sig_hex = format!("0x{}", hex::encode(&sig_bytes));
            (Some(item_detail.to_string()), Some(sig_hex))
        }
        Err(e) => {
            error!(a = asset_id, error = %e, "Failed to sign item attestation");
            (None, None)
        }
    }
}

/// GET /inspect?url={inspect_link}
///
/// Single item inspection — matches CSFloat's `GET /?url=` response format.
/// Includes `item_detail` and `oracle_signature` when signing succeeds.
pub async fn inspect_handler(
    State(state): State<Arc<InspectState>>,
    Query(params): Query<InspectQuery>,
) -> Result<Json<SingleResponse>, (StatusCode, Json<SingleResponse>)> {
    let link_params = parse_inspect_link(&params.url).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(SingleResponse {
                iteminfo: None,
                error: Some("Invalid inspect link".to_string()),
                item_detail: None,
                oracle_signature: None,
            }),
        )
    })?;

    debug!(a = link_params.a, "Inspecting item");

    match state.pool.inspect(&link_params).await {
        Ok(data) => {
            info!(a = link_params.a, float = data.floatvalue, "Inspect success");

            let (item_detail, oracle_signature) =
                sign_inspect_data(&state.signer, link_params.a, &data).await;

            Ok(Json(SingleResponse {
                iteminfo: Some(data),
                error: None,
                item_detail,
                oracle_signature,
            }))
        }
        Err(e) => {
            error!(a = link_params.a, error = %e, "Inspect failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SingleResponse {
                    iteminfo: None,
                    error: Some(e.to_string()),
                    item_detail: None,
                    oracle_signature: None,
                }),
            ))
        }
    }
}

/// POST /inspect/bulk
///
/// Batch item inspection — matches CSFloat's `POST /bulk` response format.
/// Response is keyed by asset ID (the `a` parameter from inspect links).
/// Each successful item includes `item_detail` and `oracle_signature`.
pub async fn bulk_handler(
    State(state): State<Arc<InspectState>>,
    Json(body): Json<BulkRequest>,
) -> Json<BulkResponse> {
    let count = body.links.len();
    info!(count, "Processing bulk inspect request");

    let futures: Vec<_> = body
        .links
        .iter()
        .map(|link_item| {
            let pool_ref = &state.pool;
            let signer_ref = &state.signer;
            let link = link_item.link.clone();
            async move {
                let params = match parse_inspect_link(&link) {
                    Some(p) => p,
                    None => return (link, Err("Invalid inspect link".to_string())),
                };
                let asset_id_num = params.a;
                let asset_id_key = params.a.to_string();
                match pool_ref.inspect(&params).await {
                    Ok(data) => {
                        let (item_detail, oracle_signature) =
                            sign_inspect_data(signer_ref, asset_id_num, &data).await;
                        (asset_id_key, Ok((data, item_detail, oracle_signature)))
                    }
                    Err(e) => (asset_id_key, Err(e.to_string())),
                }
            }
        })
        .collect();

    let results = futures_util::future::join_all(futures).await;

    let mut response = BulkResponse::new();
    let mut success_count = 0u32;
    let mut error_count = 0u32;

    for (key, result) in results {
        match result {
            Ok((data, item_detail, oracle_signature)) => {
                response.insert(
                    key,
                    BulkItemResponse::Success {
                        iteminfo: data,
                        item_detail,
                        oracle_signature,
                    },
                );
                success_count += 1;
            }
            Err(e) => {
                response.insert(key, BulkItemResponse::Error { error: e });
                error_count += 1;
            }
        }
    }

    info!(
        total = count,
        success = success_count,
        errors = error_count,
        "Bulk inspect complete"
    );

    Json(response)
}
