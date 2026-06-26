//! HTTP handlers + shared application state.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    Json,
};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::Config;
use crate::poison;
use crate::store::{ConsumeResult, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub config: Arc<Config>,
    pub view_html: String,
}

type JsonResp = (StatusCode, Json<Value>);

// --- Create --------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReq {
    ciphertext: String,
    iv: String,
    view_limit: i64,
    ttl_seconds: i64,
}

pub async fn create_secret(
    State(st): State<AppState>,
    Json(req): Json<CreateReq>,
) -> JsonResp {
    let cfg = &st.config;

    match decode_b64(&req.ciphertext) {
        Some(bytes) if bytes.len() <= cfg.max_ciphertext_bytes && !bytes.is_empty() => {}
        _ => return err(StatusCode::BAD_REQUEST, "invalid_ciphertext"),
    }
    match decode_b64(&req.iv) {
        Some(bytes) if bytes.len() <= 64 && !bytes.is_empty() => {}
        _ => return err(StatusCode::BAD_REQUEST, "invalid_iv"),
    }
    if req.view_limit < 1 || req.view_limit > cfg.max_view_limit {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_view_limit", "max": cfg.max_view_limit})),
        );
    }
    if req.ttl_seconds < cfg.min_ttl_seconds || req.ttl_seconds > cfg.max_ttl_seconds {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_ttl",
                "min": cfg.min_ttl_seconds,
                "max": cfg.max_ttl_seconds
            })),
        );
    }

    let id = random_b64url(16);
    let tokens: Vec<String> = (0..req.view_limit).map(|_| random_b64url(12)).collect();

    match st
        .store
        .create_secret(
            &id,
            req.ciphertext,
            req.iv,
            tokens,
            req.ttl_seconds as u64,
        )
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({
                "id": id,
                "viewLimit": req.view_limit,
                "ttlSeconds": req.ttl_seconds
            })),
        ),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

// --- Meta (non-destructive) ---------------------------------------------

pub async fn get_meta(State(st): State<AppState>, Path(id): Path<String>) -> JsonResp {
    if !valid_id(&id) {
        return err(StatusCode::NOT_FOUND, "not_found");
    }
    match st.store.get_meta(&id).await {
        Ok(Some(meta)) => (
            StatusCode::OK,
            Json(json!({
                "exists": true,
                "remaining": meta.remaining,
                "expiresAt": meta.expires_at
            })),
        ),
        Ok(None) => err(StatusCode::NOT_FOUND, "not_found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

// --- View (destructive) -------------------------------------------------

pub async fn view_secret(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> JsonResp {
    if !valid_id(&id) {
        return err(StatusCode::NOT_FOUND, "not_found");
    }

    // Server-side authority: reject a replayed poison token without burning a
    // view.
    if let Some(token) = bearer(&headers) {
        if poison::is_poisoned_for(&st.config, token, &id) {
            return err(StatusCode::FORBIDDEN, "already_viewed");
        }
    }

    match st.store.consume_view(&id).await {
        Ok(ConsumeResult::Gone) => err(StatusCode::GONE, "gone"),
        Ok(ConsumeResult::Ok {
            ciphertext,
            iv,
            remaining,
        }) => match poison::mint(&st.config, &id, st.config.max_ttl_seconds) {
            Ok(token) => (
                StatusCode::OK,
                Json(json!({
                    "ciphertext": ciphertext,
                    "iv": iv,
                    "remaining": remaining,
                    "poison": token
                })),
            ),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        },
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    }
}

// --- Misc routes ---------------------------------------------------------

pub async fn healthz() -> JsonResp {
    (StatusCode::OK, Json(json!({"ok": true})))
}

/// /view/:id is a single-page route served by view.html, which reads the id
/// from the path and the key from the URL hash.
pub async fn view_page(State(st): State<AppState>) -> Html<String> {
    Html(st.view_html.clone())
}

// --- helpers -------------------------------------------------------------

fn err(code: StatusCode, msg: &str) -> JsonResp {
    (code, Json(json!({ "error": msg })))
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn random_b64url(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Accepts ids matching `^[A-Za-z0-9_-]{10,64}$`.
fn valid_id(id: &str) -> bool {
    let len = id.len();
    (10..=64).contains(&len)
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let trimmed = value.trim();
    let rest = trimmed.strip_prefix("Bearer ").or_else(|| {
        // case-insensitive scheme match
        if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
            Some(&trimmed[7..])
        } else {
            None
        }
    })?;
    let rest = rest.trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}
