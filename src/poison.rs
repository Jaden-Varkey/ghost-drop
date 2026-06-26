//! Device "poison" tokens — server-signed JWTs (HS256) that mark a device as
//! having already viewed a given secret. The client persists these in
//! LocalStorage and IndexedDB and replays them on later attempts; the server
//! also verifies them as server-side authority, so a cleared-storage refresh
//! can't double-dip while a token survives.
//!
//! We hand-roll the compact JWT (header.payload.signature) over HMAC-SHA256
//! using pure-Rust crypto crates — no C/assembly build dependencies.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::Config;

type HmacSha256 = Hmac<Sha256>;

const ISSUER: &str = "ghostdrop";
const SUBJECT: &str = "poison";
// {"alg":"HS256","typ":"JWT"}
const HEADER_JSON: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;

#[derive(Serialize, Deserialize)]
struct PoisonClaims {
    sid: String, // secret id this poison belongs to
    sub: String,
    iss: String,
    exp: u64, // unix seconds
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign(secret: &[u8], signing_input: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Mint a signed poison token for `sid`, valid for at least `ttl_seconds`.
pub fn mint(cfg: &Config, sid: &str, ttl_seconds: i64) -> anyhow::Result<String> {
    let claims = PoisonClaims {
        sid: sid.to_string(),
        sub: SUBJECT.to_string(),
        iss: ISSUER.to_string(),
        exp: now_secs() + ttl_seconds.max(60) as u64,
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(HEADER_JSON);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_b64 = URL_SAFE_NO_PAD.encode(sign(cfg.jwt_secret.as_bytes(), &signing_input));
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify a poison token and confirm it belongs to `sid`.
pub fn is_poisoned_for(cfg: &Config, token: &str, sid: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    // Constant-time signature check.
    let provided_sig = match URL_SAFE_NO_PAD.decode(parts[2]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(cfg.jwt_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signing_input.as_bytes());
    if mac.verify_slice(&provided_sig).is_err() {
        return false;
    }

    // Signature valid — now check the claims.
    let payload = match URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let claims: PoisonClaims = match serde_json::from_slice(&payload) {
        Ok(c) => c,
        Err(_) => return false,
    };
    claims.iss == ISSUER
        && claims.sub == SUBJECT
        && claims.exp >= now_secs()
        && claims.sid == sid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            port: 0,
            host: "0".into(),
            store_driver: "memory".into(),
            redis_url: "".into(),
            jwt_secret: "test-secret".into(),
            max_ciphertext_bytes: 1024,
            max_view_limit: 100,
            min_ttl_seconds: 60,
            max_ttl_seconds: 3600,
        }
    }

    #[test]
    fn round_trip_matches_only_its_own_secret() {
        let c = cfg();
        let token = mint(&c, "abc123", 3600).unwrap();
        assert!(is_poisoned_for(&c, &token, "abc123"));
        assert!(!is_poisoned_for(&c, &token, "different"));
        assert!(!is_poisoned_for(&c, "garbage.token.value", "abc123"));
    }

    #[test]
    fn rejects_expired_token() {
        let c = cfg();
        // ttl floor is 60s, so force an already-expired token by signing directly.
        let claims = PoisonClaims {
            sid: "abc".into(),
            sub: SUBJECT.into(),
            iss: ISSUER.into(),
            exp: 1, // 1970
        };
        let header_b64 = URL_SAFE_NO_PAD.encode(HEADER_JSON);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = URL_SAFE_NO_PAD.encode(sign(c.jwt_secret.as_bytes(), &signing_input));
        let token = format!("{signing_input}.{sig}");
        assert!(!is_poisoned_for(&c, &token, "abc"));
    }
}
