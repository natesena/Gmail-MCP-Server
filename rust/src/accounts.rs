//! The runtime set of Gmail accounts one server process serves.
//!
//! Two sources:
//!   - credential files (`--account NAME=DIR`, an accounts file, or the
//!     single-account fallback), as in the stdio setup;
//!   - the encrypted [`Store`], used by the deployed HTTP server. Changes made
//!     by the `accounts` CLI in another process are picked up without a
//!     restart (the store's mtime is checked on each request).

use crate::auth::{self, ClientKeys, PersistFn, TokenStore};
use crate::config::{AccountConfig, Config};
use crate::gmail::Gmail;
use crate::store::{Store, StoreData, StoredAccount};
use anyhow::{anyhow, bail, Result};
use serde_json::{Map, Value};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::sync::OnceCell;

/// Request `account` value that fans a read tool out to every account.
pub const ALL_ACCOUNTS: &str = "all";

#[derive(Clone)]
pub struct Endpoints {
    pub api_base: String,
    pub token_url: String,
}

impl Endpoints {
    /// Real Google endpoints, overridable for tests via
    /// `GMAIL_MCP_API_BASE` / `GMAIL_MCP_TOKEN_URL`.
    pub fn from_env() -> Self {
        Self {
            api_base: std::env::var("GMAIL_MCP_API_BASE")
                .unwrap_or_else(|_| crate::gmail::DEFAULT_API_BASE.to_string()),
            token_url: std::env::var("GMAIL_MCP_TOKEN_URL")
                .unwrap_or_else(|_| auth::DEFAULT_TOKEN_URL.to_string()),
        }
    }
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("gmail-mcp-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("http client")
}

pub struct Account {
    pub name: String,
    /// Authorized scopes (shorthand names). Empty when the account failed to load.
    pub scopes: Vec<String>,
    gmail: Option<Gmail>,
    /// Why this account cannot be used, if it can't. The server still serves
    /// the other accounts.
    pub load_error: Option<String>,
    email: OnceCell<String>,
    /// Identity of the loaded credentials, to reuse the live account (and its
    /// in-memory token) across store reloads.
    fingerprint: String,
}

fn fingerprint(
    name: &str,
    scopes: &[String],
    tokens: &Map<String, Value>,
    client: Option<&ClientKeys>,
) -> String {
    format!(
        "{name}|{}|{}|{}",
        scopes.join(","),
        tokens
            .get("refresh_token")
            .and_then(Value::as_str)
            .unwrap_or(""),
        client.map(|c| c.client_id.as_str()).unwrap_or("")
    )
}

impl Account {
    #[allow(clippy::too_many_arguments)]
    fn ready(
        name: &str,
        keys: ClientKeys,
        tokens: &Map<String, Value>,
        scopes: Vec<String>,
        persist: PersistFn,
        email: Option<String>,
        http: &reqwest::Client,
        endpoints: &Endpoints,
    ) -> Self {
        let fp = fingerprint(name, &scopes, tokens, Some(&keys));
        let store = TokenStore::new(
            keys,
            tokens,
            persist,
            endpoints.token_url.clone(),
            http.clone(),
        );
        let cell = OnceCell::new();
        if let Some(e) = email.filter(|e| !e.is_empty()) {
            let _ = cell.set(e);
        }
        Self {
            name: name.to_string(),
            scopes,
            gmail: Some(Gmail::new(
                http.clone(),
                endpoints.api_base.clone(),
                Arc::new(store),
            )),
            load_error: None,
            email: cell,
            fingerprint: fp,
        }
    }

    fn failed(name: &str, err: String) -> Self {
        Self {
            name: name.to_string(),
            scopes: Vec::new(),
            gmail: None,
            load_error: Some(err.clone()),
            email: OnceCell::new(),
            fingerprint: format!("{name}|error|{err}"),
        }
    }

    /// From credential files (gcp-oauth.keys.json + credentials.json).
    pub fn from_files(
        config: &AccountConfig,
        http: &reqwest::Client,
        endpoints: &Endpoints,
    ) -> Self {
        let loaded = (|| -> Result<_> {
            let keys = auth::load_client_keys(&config.oauth_path)?;
            let text = std::fs::read_to_string(&config.credentials_path).map_err(|_| {
                anyhow!(
                    "Not authenticated: {} not found. Run `gmail-mcp auth {}`",
                    config.credentials_path.display(),
                    config.name
                )
            })?;
            Ok((keys, auth::parse_credentials(&text)?))
        })();
        match loaded {
            Ok((keys, creds)) => Self::ready(
                &config.name,
                keys,
                &creds.tokens,
                creds.scopes,
                auth::file_persist(config.credentials_path.clone()),
                None,
                http,
                endpoints,
            ),
            Err(e) => Self::failed(&config.name, format!("{e:#}")),
        }
    }

    /// From the encrypted store; refreshed tokens are written back to it.
    pub fn from_store(
        acct: &StoredAccount,
        data: &StoreData,
        store: &Store,
        http: &reqwest::Client,
        endpoints: &Endpoints,
    ) -> Self {
        let Some(keys) = data.client_for(acct) else {
            return Self::failed(&acct.alias, "the store has no OAuth client; run `gmail-mcp accounts import` or `store set-client`".into());
        };
        let store = store.clone();
        let alias = acct.alias.clone();
        let persist: PersistFn =
            Arc::new(move |t: &Map<String, Value>| store.save_tokens(&alias, t));
        Self::ready(
            &acct.alias,
            keys,
            &acct.tokens,
            acct.scopes.clone(),
            persist,
            Some(acct.email.clone()),
            http,
            endpoints,
        )
    }

    pub fn gmail(&self) -> Result<&Gmail> {
        match &self.gmail {
            Some(g) => Ok(g),
            None => bail!(
                "Account {:?} is unavailable: {}",
                self.name,
                self.load_error.as_deref().unwrap_or("unknown error")
            ),
        }
    }

    /// The email address known without a network call (store accounts).
    pub fn known_email(&self) -> Option<String> {
        self.email.get().cloned()
    }

    /// The account's email address (users.getProfile), cached after the first call.
    pub async fn email(&self) -> Result<String> {
        let g = self.gmail()?;
        self.email
            .get_or_try_init(|| async {
                let p = g.get("/profile", Vec::new()).await?;
                Ok::<_, anyhow::Error>(
                    p.get("emailAddress")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .await
            .cloned()
    }
}

pub struct Accounts {
    pub list: Vec<Arc<Account>>,
    pub default: Option<String>,
}

impl Accounts {
    pub fn load(config: &Config, endpoints: &Endpoints) -> Self {
        let http = http_client();
        Self {
            list: config
                .accounts
                .iter()
                .map(|a| Arc::new(Account::from_files(a, &http, endpoints)))
                .collect(),
            default: config.default_account.clone(),
        }
    }

    fn from_store_data(
        data: &StoreData,
        store: &Store,
        http: &reqwest::Client,
        endpoints: &Endpoints,
        previous: Option<&Accounts>,
    ) -> Self {
        let list = data
            .accounts
            .iter()
            .map(|sa| {
                let fp = fingerprint(
                    &sa.alias,
                    &sa.scopes,
                    &sa.tokens,
                    data.client_for(sa).as_ref(),
                );
                previous
                    .and_then(|p| p.list.iter().find(|a| a.fingerprint == fp).cloned())
                    .unwrap_or_else(|| {
                        Arc::new(Account::from_store(sa, data, store, http, endpoints))
                    })
            })
            .collect::<Vec<_>>();
        let default = data
            .default
            .clone()
            .or_else(|| (list.len() == 1).then(|| list[0].name.clone()));
        Self { list, default }
    }

    pub fn names(&self) -> Vec<String> {
        self.list.iter().map(|a| a.name.clone()).collect()
    }

    pub fn is_multi(&self) -> bool {
        self.list.len() > 1
    }

    /// Pick the account a tool call targets, by alias or email address.
    pub fn resolve(&self, requested: Option<&str>) -> Result<Arc<Account>> {
        let name = match requested {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => match &self.default {
                Some(d) => d.clone(),
                None => bail!(
                    "This server serves several Gmail accounts; pass \"account\" as one of: {}",
                    self.names().join(", ")
                ),
            },
        };
        let by_alias = self.list.iter().find(|a| a.name == name);
        let by_email = || {
            self.list.iter().find(|a| {
                a.known_email()
                    .is_some_and(|e| e.eq_ignore_ascii_case(&name))
            })
        };
        by_alias.or_else(by_email).cloned().ok_or_else(|| {
            anyhow!(
                "Unknown account {name:?}. Configured accounts: {}",
                self.names().join(", ")
            )
        })
    }
}

/// The accounts a server currently serves; reloads from the store when the
/// `accounts` CLI changes it.
pub struct AccountsHandle {
    current: RwLock<Arc<Accounts>>,
    store: Option<StoreSource>,
}

struct StoreSource {
    store: Store,
    seen: Mutex<Option<SystemTime>>,
    http: reqwest::Client,
    endpoints: Endpoints,
}

impl From<Accounts> for AccountsHandle {
    fn from(a: Accounts) -> Self {
        Self {
            current: RwLock::new(Arc::new(a)),
            store: None,
        }
    }
}

impl AccountsHandle {
    pub fn from_store(store: Store, endpoints: Endpoints) -> Result<Self> {
        let http = http_client();
        let seen = store.modified();
        let data = store.load()?;
        let accounts = Accounts::from_store_data(&data, &store, &http, &endpoints, None);
        Ok(Self {
            current: RwLock::new(Arc::new(accounts)),
            store: Some(StoreSource {
                store,
                seen: Mutex::new(seen),
                http,
                endpoints,
            }),
        })
    }

    /// The current accounts (reloading first if the store file changed).
    pub fn get(&self) -> Arc<Accounts> {
        if let Some(src) = &self.store {
            let now = src.store.modified();
            let changed = {
                let mut seen = src.seen.lock().expect("lock");
                let changed = *seen != now;
                *seen = now;
                changed
            };
            if changed {
                match src.store.load() {
                    Ok(data) => {
                        let prev = self.current.read().expect("lock").clone();
                        let next = Accounts::from_store_data(
                            &data,
                            &src.store,
                            &src.http,
                            &src.endpoints,
                            Some(&prev),
                        );
                        *self.current.write().expect("lock") = Arc::new(next);
                    }
                    Err(e) => eprintln!("gmail-mcp: could not reload account store: {e:#}"),
                }
            }
        }
        self.current.read().expect("lock").clone()
    }
}
