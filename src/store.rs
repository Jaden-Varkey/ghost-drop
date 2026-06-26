//! Storage layer. Two interchangeable implementations behind one enum:
//!   * `MemoryStore` — zero-setup, in-process (dev / fallback).
//!   * `RedisStore`  — production: blob + Redis List of single-use tokens + TTL.
//!
//! Both share identical semantics: pop one token per view, destroy the blob the
//! instant the last token is consumed.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize)]
struct BlobJson {
    ciphertext: String,
    iv: String,
}

pub struct Meta {
    pub remaining: i64,
    pub expires_at: Option<u64>, // unix ms
}

pub enum ConsumeResult {
    Ok {
        ciphertext: String,
        iv: String,
        remaining: i64,
    },
    Gone,
}

#[derive(Clone)]
pub enum Store {
    Memory(MemoryStore),
    Redis(RedisStore),
}

impl Store {
    pub async fn create_secret(
        &self,
        id: &str,
        ciphertext: String,
        iv: String,
        tokens: Vec<String>,
        ttl: u64,
    ) -> anyhow::Result<()> {
        match self {
            Store::Memory(m) => {
                m.create_secret(id, ciphertext, iv, tokens, ttl).await;
                Ok(())
            }
            Store::Redis(r) => {
                r.create_secret(id, ciphertext, iv, tokens, ttl).await?;
                Ok(())
            }
        }
    }

    pub async fn get_meta(&self, id: &str) -> anyhow::Result<Option<Meta>> {
        match self {
            Store::Memory(m) => Ok(m.get_meta(id).await),
            Store::Redis(r) => Ok(r.get_meta(id).await?),
        }
    }

    pub async fn consume_view(&self, id: &str) -> anyhow::Result<ConsumeResult> {
        match self {
            Store::Memory(m) => Ok(m.consume_view(id).await),
            Store::Redis(r) => Ok(r.consume_view(id).await?),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Store::Memory(_) => "memory",
            Store::Redis(_) => "redis",
        }
    }
}

// --- In-memory implementation ------------------------------------------------

struct Record {
    ciphertext: String,
    iv: String,
    tokens: VecDeque<String>,
    expires_at_ms: u64,
}

#[derive(Clone)]
pub struct MemoryStore {
    inner: Arc<Mutex<HashMap<String, Record>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn create_secret(
        &self,
        id: &str,
        ciphertext: String,
        iv: String,
        tokens: Vec<String>,
        ttl: u64,
    ) {
        let mut map = self.inner.lock().await;
        map.insert(
            id.to_string(),
            Record {
                ciphertext,
                iv,
                tokens: VecDeque::from(tokens),
                expires_at_ms: now_ms() + ttl * 1000,
            },
        );
    }

    async fn get_meta(&self, id: &str) -> Option<Meta> {
        let mut map = self.inner.lock().await;
        let now = now_ms();
        match map.get(id) {
            Some(r) if r.expires_at_ms > now => Some(Meta {
                remaining: r.tokens.len() as i64,
                expires_at: Some(r.expires_at_ms),
            }),
            Some(_) => {
                map.remove(id);
                None
            }
            None => None,
        }
    }

    async fn consume_view(&self, id: &str) -> ConsumeResult {
        let mut map = self.inner.lock().await;
        let now = now_ms();

        // Expired or missing -> gone (and clean up).
        match map.get(id) {
            Some(r) if r.expires_at_ms <= now => {
                map.remove(id);
                return ConsumeResult::Gone;
            }
            None => return ConsumeResult::Gone,
            _ => {}
        }

        // Pop one token; capture the blob while we hold the borrow.
        let (ciphertext, iv, remaining) = {
            let r = map.get_mut(id).expect("present");
            if r.tokens.pop_front().is_none() {
                (String::new(), String::new(), -1)
            } else {
                (r.ciphertext.clone(), r.iv.clone(), r.tokens.len() as i64)
            }
        };

        if remaining < 0 {
            map.remove(id); // empty list lingered — wipe it
            return ConsumeResult::Gone;
        }
        if remaining == 0 {
            map.remove(id); // final view -> physical deletion
        }
        ConsumeResult::Ok {
            ciphertext,
            iv,
            remaining,
        }
    }
}

// --- Redis implementation ----------------------------------------------------

// Atomic "dispense a ticket": pop a token, check how many remain, and destroy
// the blob on the final view — all in one script so concurrent viewers can
// never both grab the same token or race past the view limit.
//   KEYS[1] = tokens list, KEYS[2] = blob
//   returns { "gone" } | { "ok", <blobJson>, <remainingAsString> }
const CONSUME_SCRIPT: &str = r#"
local token = redis.call('LPOP', KEYS[1])
if not token then
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
  return {'gone'}
end
local blob = redis.call('GET', KEYS[2])
if not blob then
  redis.call('DEL', KEYS[1])
  return {'gone'}
end
local remaining = redis.call('LLEN', KEYS[1])
if remaining == 0 then
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
end
return {'ok', blob, tostring(remaining)}
"#;

#[derive(Clone)]
pub struct RedisStore {
    conn: MultiplexedConnection,
}

impl RedisStore {
    pub async fn connect(url: &str) -> redis::RedisResult<Self> {
        let client = redis::Client::open(url)?;
        let mut conn = client.get_multiplexed_async_connection().await?;
        let _: () = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(RedisStore { conn })
    }

    fn blob_key(id: &str) -> String {
        format!("ghostdrop:blob:{id}")
    }
    fn tokens_key(id: &str) -> String {
        format!("ghostdrop:tokens:{id}")
    }

    async fn create_secret(
        &self,
        id: &str,
        ciphertext: String,
        iv: String,
        tokens: Vec<String>,
        ttl: u64,
    ) -> redis::RedisResult<()> {
        let mut conn = self.conn.clone();
        let blob = serde_json::to_string(&BlobJson { ciphertext, iv }).unwrap_or_default();
        let bkey = Self::blob_key(id);
        let tkey = Self::tokens_key(id);

        let _: () = redis::pipe()
            .cmd("SET")
            .arg(&bkey)
            .arg(blob)
            .arg("EX")
            .arg(ttl)
            .ignore()
            .cmd("RPUSH")
            .arg(&tkey)
            .arg(&tokens)
            .ignore()
            .cmd("EXPIRE")
            .arg(&tkey)
            .arg(ttl)
            .ignore()
            .query_async(&mut conn)
            .await?;
        Ok(())
    }

    async fn get_meta(&self, id: &str) -> redis::RedisResult<Option<Meta>> {
        let mut conn = self.conn.clone();
        let (exists, remaining, pttl): (i64, i64, i64) = redis::pipe()
            .cmd("EXISTS")
            .arg(Self::blob_key(id))
            .cmd("LLEN")
            .arg(Self::tokens_key(id))
            .cmd("PTTL")
            .arg(Self::blob_key(id))
            .query_async(&mut conn)
            .await?;

        if exists == 0 {
            return Ok(None);
        }
        let expires_at = if pttl > 0 {
            Some(now_ms() + pttl as u64)
        } else {
            None
        };
        Ok(Some(Meta {
            remaining,
            expires_at,
        }))
    }

    async fn consume_view(&self, id: &str) -> redis::RedisResult<ConsumeResult> {
        let mut conn = self.conn.clone();
        let res: Vec<String> = redis::Script::new(CONSUME_SCRIPT)
            .key(Self::tokens_key(id))
            .key(Self::blob_key(id))
            .invoke_async(&mut conn)
            .await?;

        if res.first().map(String::as_str) != Some("ok") || res.len() < 3 {
            return Ok(ConsumeResult::Gone);
        }
        let blob: BlobJson = serde_json::from_str(&res[1])
            .map_err(|_| redis::RedisError::from((redis::ErrorKind::TypeError, "bad blob json")))?;
        let remaining: i64 = res[2].parse().unwrap_or(0);
        Ok(ConsumeResult::Ok {
            ciphertext: blob.ciphertext,
            iv: blob.iv,
            remaining,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lifecycle_multi_view_then_destruction() {
        let s = MemoryStore::new();
        s.create_secret(
            "id1",
            "CT".into(),
            "IV".into(),
            vec!["t1".into(), "t2".into()],
            3600,
        )
        .await;

        let m = s.get_meta("id1").await.unwrap();
        assert_eq!(m.remaining, 2);

        match s.consume_view("id1").await {
            ConsumeResult::Ok {
                remaining,
                ciphertext,
                ..
            } => {
                assert_eq!(remaining, 1);
                assert_eq!(ciphertext, "CT");
            }
            _ => panic!("expected ok"),
        }
        match s.consume_view("id1").await {
            ConsumeResult::Ok { remaining, .. } => assert_eq!(remaining, 0),
            _ => panic!("expected ok"),
        }
        // Destroyed.
        assert!(s.get_meta("id1").await.is_none());
        assert!(matches!(s.consume_view("id1").await, ConsumeResult::Gone));
    }

    #[tokio::test]
    async fn expired_is_gone() {
        let s = MemoryStore::new();
        s.create_secret("id2", "CT".into(), "IV".into(), vec!["t1".into()], 0)
            .await;
        // ttl 0 -> already expired on next tick.
        assert!(s.get_meta("id2").await.is_none());
    }
}
