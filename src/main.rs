//! GhostDrop — Rust backend.
//!
//! Frictionless, zero-knowledge multi-view secret sharing. The frontend
//! encrypts client-side (AES-256-GCM via WebCrypto); this server only ever
//! stores ciphertext, dispenses single-use view tokens (Redis List + TTL), and
//! signs per-device "poison" tokens to stop refresh-abuse.

mod config;
mod handlers;
mod poison;
mod store;

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use tower_http::services::{ServeDir, ServeFile};

use config::Config;
use handlers::AppState;
use store::{MemoryStore, RedisStore, Store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let config = Arc::new(Config::from_env());
    let store = build_store(&config).await;

    let public_dir =
        PathBuf::from(std::env::var("PUBLIC_DIR").unwrap_or_else(|_| "public".to_string()));
    let index_path = public_dir.join("index.html");
    let view_path = public_dir.join("view.html");
    let view_html = std::fs::read_to_string(&view_path).unwrap_or_else(|_| {
        eprintln!("[warn] could not read {}", view_path.display());
        String::from("<!doctype html><p>view.html missing</p>")
    });

    let state = AppState {
        store: store.clone(),
        config: config.clone(),
        view_html,
    };

    // Static files (js/css/index) with index.html as SPA fallback.
    let static_service = ServeDir::new(&public_dir).fallback(ServeFile::new(index_path));

    let app = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/api/secrets", post(handlers::create_secret))
        .route("/api/secrets/:id/meta", get(handlers::get_meta))
        .route("/api/secrets/:id/view", post(handlers::view_secret))
        .route("/view/:id", get(handlers::view_page))
        .fallback_service(static_service)
        .layer(middleware::from_fn(security_headers))
        .with_state(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!(
        "GhostDrop listening on http://{} (store: {})",
        addr,
        store.kind()
    );

    axum::serve(listener, app).await?;
    Ok(())
}

async fn build_store(config: &Config) -> Store {
    match config.store_driver.as_str() {
        "memory" => {
            println!("[store] using in-memory store (STORE_DRIVER=memory)");
            Store::Memory(MemoryStore::new())
        }
        "redis" => match RedisStore::connect(&config.redis_url).await {
            Ok(s) => {
                println!("[store] using Redis store at {}", config.redis_url);
                Store::Redis(s)
            }
            Err(e) => {
                eprintln!("[store] STORE_DRIVER=redis but Redis is unreachable: {e}");
                std::process::exit(1);
            }
        },
        _ => match RedisStore::connect(&config.redis_url).await {
            Ok(s) => {
                println!("[store] using Redis store at {}", config.redis_url);
                Store::Redis(s)
            }
            Err(e) => {
                eprintln!(
                    "[store] Redis unavailable ({e}); falling back to in-memory store. \
                     Data will not survive a restart or span instances. \
                     Set STORE_DRIVER=redis to require Redis."
                );
                Store::Memory(MemoryStore::new())
            }
        },
    }
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; base-uri 'none'; form-action 'self'",
        ),
    );
    res
}
