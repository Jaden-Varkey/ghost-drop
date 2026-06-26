//! Runtime configuration, loaded from environment variables (and an optional
//! `.env` file).

use rand::RngCore;

pub struct Config {
    pub port: u16,
    pub host: String,

    /// "auto" | "redis" | "memory"
    pub store_driver: String,
    pub redis_url: String,

    /// Secret used to sign/verify device "poison" tokens.
    pub jwt_secret: String,

    pub max_ciphertext_bytes: usize,
    pub max_view_limit: i64,
    pub min_ttl_seconds: i64,
    pub max_ttl_seconds: i64,
}

impl Config {
    pub fn from_env() -> Self {
        // A JWT secret is required to mint/verify poison tokens. If the operator
        // doesn't supply one we generate an ephemeral secret so the app still
        // runs out-of-the-box, but warn because restarts then invalidate
        // previously issued poison tokens.
        let jwt_secret = std::env::var("JWT_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                eprintln!(
                    "[config] JWT_SECRET not set — generated an ephemeral one. \
                     Set JWT_SECRET in your environment for stable poison tokens."
                );
                random_hex(32)
            });

        Config {
            port: env_or("PORT", "3000").parse().unwrap_or(3000),
            host: env_or("HOST", "0.0.0.0"),
            store_driver: env_or("STORE_DRIVER", "auto").to_lowercase(),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            jwt_secret,
            max_ciphertext_bytes: env_int("MAX_CIPHERTEXT_BYTES", 64 * 1024) as usize,
            max_view_limit: env_int("MAX_VIEW_LIMIT", 100),
            min_ttl_seconds: env_int("MIN_TTL_SECONDS", 60),
            max_ttl_seconds: env_int("MAX_TTL_SECONDS", 30 * 24 * 60 * 60),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_int(key: &str, default: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(n * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
