//! Encrypted account store: the one place a deployed server keeps secrets.
//!
//! A single file holds the OAuth client (stored once) and every account's
//! alias, email address, scopes and tokens. It is encrypted with
//! AES-256-GCM; the 32-byte key comes from a separate file (in Docker, a
//! secret mounted at /run/secrets/...), so the volume alone reveals nothing.
//!
//! On-disk format:
//! `{"format":"gmail-mcp-store","version":1,"nonce":"<b64>","ciphertext":"<b64>"}`
//!
//! Writers (the server persisting a refreshed token, or the `accounts` CLI
//! running in another process) take an exclusive lock on `<file>.lock` and do
//! read-modify-write, so neither loses the other's update.

use crate::auth::{write_private, ClientKeys};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const FORMAT: &str = "gmail-mcp-store";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StoredAccount {
    pub alias: String,
    pub email: String,
    pub scopes: Vec<String>,
    pub tokens: Map<String, Value>,
    /// Only set when this account uses a different OAuth client than the
    /// store's shared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientKeys>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StoreData {
    pub client: Option<ClientKeys>,
    pub default: Option<String>,
    pub accounts: Vec<StoredAccount>,
}

impl StoreData {
    pub fn get(&self, alias: &str) -> Option<&StoredAccount> {
        self.accounts.iter().find(|a| a.alias == alias)
    }

    /// The OAuth client an account uses.
    pub fn client_for(&self, acct: &StoredAccount) -> Option<ClientKeys> {
        acct.client.clone().or_else(|| self.client.clone())
    }

    /// Insert or replace an account by alias.
    pub fn upsert(&mut self, acct: StoredAccount) {
        match self.accounts.iter_mut().find(|a| a.alias == acct.alias) {
            Some(existing) => *existing = acct,
            None => self.accounts.push(acct),
        }
    }

    pub fn remove(&mut self, alias: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.alias != alias);
        if self.default.as_deref() == Some(alias) {
            self.default = None;
        }
        self.accounts.len() != before
    }
}

/// Decode a key file: base64 (as printed by `gmail-mcp store keygen`) or hex.
pub fn parse_key(text: &str) -> Result<[u8; 32]> {
    let t = text.trim();
    let bytes = if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        (0..32)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()?
    } else {
        STANDARD
            .decode(t)
            .map_err(|_| anyhow!("store key must be 32 bytes, base64 or hex"))?
    };
    bytes
        .try_into()
        .map_err(|_| anyhow!("store key must be exactly 32 bytes"))
}

pub fn generate_key() -> String {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    STANDARD.encode(k)
}

pub fn encrypt(key: &[u8; 32], data: &StoreData) -> Result<Value> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let plain = serde_json::to_vec(data)?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(json!({
        "format": FORMAT,
        "version": 1,
        "nonce": STANDARD.encode(nonce),
        "ciphertext": STANDARD.encode(ct),
    }))
}

pub fn decrypt(key: &[u8; 32], file: &Value) -> Result<StoreData> {
    if file["format"] != FORMAT || file["version"] != 1 {
        bail!("not a gmail-mcp store file (or an unsupported version)");
    }
    let field = |k: &str| -> Result<Vec<u8>> {
        STANDARD
            .decode(file[k].as_str().unwrap_or_default())
            .with_context(|| format!("store file has a bad {k}"))
    };
    let nonce = field("nonce")?;
    if nonce.len() != 12 {
        bail!("store file has a bad nonce");
    }
    let ct = field("ciphertext")?;
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_slice())
        .map_err(|_| anyhow!("cannot decrypt the account store: wrong key or corrupted file"))?;
    Ok(serde_json::from_slice(&plain)?)
}

#[derive(Clone)]
pub struct Store {
    pub path: PathBuf,
    key: [u8; 32],
}

impl Store {
    pub fn new(path: PathBuf, key: [u8; 32]) -> Self {
        Self { path, key }
    }

    pub fn open(path: PathBuf, key_file: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(key_file)
            .with_context(|| format!("cannot read store key file {}", key_file.display()))?;
        Ok(Self::new(path, parse_key(&text)?))
    }

    /// Current contents; a missing file is an empty store.
    pub fn load(&self) -> Result<StoreData> {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => decrypt(
                &self.key,
                &serde_json::from_str(&t).context("store file is not JSON")?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StoreData::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", self.path.display())),
        }
    }

    /// Modification time, used by the server to pick up CLI changes.
    pub fn modified(&self) -> Option<SystemTime> {
        std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok()
    }

    /// Locked read-modify-write; the new file replaces the old atomically.
    pub fn update<T>(&self, f: impl FnOnce(&mut StoreData) -> Result<T>) -> Result<T> {
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let lock_path = self.path.with_extension("lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("cannot open {}", lock_path.display()))?;
        lock.lock()?;
        let result = (|| {
            let mut data = self.load()?;
            let out = f(&mut data)?;
            let tmp = self.path.with_extension("tmp");
            write_private(&tmp, &encrypt(&self.key, &data)?)?;
            std::fs::rename(&tmp, &self.path)?;
            Ok(out)
        })();
        let _ = lock.unlock();
        result
    }

    /// Merge refreshed tokens into one account (used as the token persister).
    pub fn save_tokens(&self, alias: &str, tokens: &Map<String, Value>) -> Result<()> {
        self.update(|data| {
            let acct = data
                .accounts
                .iter_mut()
                .find(|a| a.alias == alias)
                .ok_or_else(|| anyhow!("account {alias:?} was removed from the store"))?;
            let on_disk = json!({ "tokens": Value::Object(acct.tokens.clone()) });
            let merged = crate::auth::merge_refreshed(&on_disk, tokens);
            acct.tokens = merged["tokens"].as_object().cloned().unwrap_or_default();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoreData {
        let mut tokens = Map::new();
        tokens.insert("refresh_token".into(), json!("1//SECRET-REFRESH"));
        tokens.insert("access_token".into(), json!("ya29.SECRET"));
        StoreData {
            client: Some(ClientKeys {
                client_id: "cid".into(),
                client_secret: "GOCSPX-SECRET".into(),
            }),
            default: Some("work".into()),
            accounts: vec![StoredAccount {
                alias: "work".into(),
                email: "w@x.com".into(),
                scopes: vec!["gmail.modify".into()],
                tokens,
                client: None,
            }],
        }
    }

    #[test]
    fn roundtrip_and_no_plaintext_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let key = parse_key(&generate_key()).unwrap();
        let store = Store::new(tmp.path().join("store.json"), key);
        store
            .update(|d| {
                *d = sample();
                Ok(())
            })
            .unwrap();
        assert_eq!(store.load().unwrap(), sample());
        let raw = std::fs::read_to_string(&store.path).unwrap();
        for secret in ["SECRET-REFRESH", "ya29", "GOCSPX", "w@x.com"] {
            assert!(!raw.contains(secret), "{secret} leaked to disk");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&store.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn wrong_key_and_tampering_fail() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("s.json"), [7u8; 32]);
        store
            .update(|d| {
                *d = sample();
                Ok(())
            })
            .unwrap();
        let other = Store::new(store.path.clone(), [8u8; 32]);
        assert!(other.load().unwrap_err().to_string().contains("wrong key"));
        let mut file: Value =
            serde_json::from_str(&std::fs::read_to_string(&store.path).unwrap()).unwrap();
        let mut ct = STANDARD
            .decode(file["ciphertext"].as_str().unwrap())
            .unwrap();
        ct[0] ^= 1;
        file["ciphertext"] = json!(STANDARD.encode(ct));
        assert!(decrypt(&[7u8; 32], &file).is_err());
    }

    #[test]
    fn missing_file_is_empty_and_key_parsing() {
        let store = Store::new(PathBuf::from("/nonexistent/x.json"), [1u8; 32]);
        assert_eq!(store.load().unwrap(), StoreData::default());
        assert!(parse_key(&"ab".repeat(32)).is_ok());
        assert!(parse_key("short").is_err());
        assert!(parse_key(&STANDARD.encode([0u8; 16])).is_err());
    }

    #[test]
    fn save_tokens_merges_and_keeps_refresh_token() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("s.json"), [3u8; 32]);
        store
            .update(|d| {
                *d = sample();
                Ok(())
            })
            .unwrap();
        let mut new = Map::new();
        new.insert("access_token".into(), json!("ya29.NEW"));
        new.insert("expiry_date".into(), json!(42));
        store.save_tokens("work", &new).unwrap();
        let d = store.load().unwrap();
        let t = &d.get("work").unwrap().tokens;
        assert_eq!(t["access_token"], "ya29.NEW");
        assert_eq!(t["refresh_token"], "1//SECRET-REFRESH");
        assert_eq!(t["expiry_date"], 42);
        assert!(store.save_tokens("gone", &new).is_err());
    }

    #[test]
    fn upsert_remove_default() {
        let mut d = sample();
        let mut p = d.accounts[0].clone();
        p.alias = "personal".into();
        d.upsert(p);
        assert_eq!(d.accounts.len(), 2);
        assert!(d.remove("work"));
        assert_eq!(d.default, None);
        assert!(!d.remove("work"));
    }
}
