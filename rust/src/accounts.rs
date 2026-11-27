//! The runtime set of Gmail accounts one server process serves.

use crate::auth::{self, TokenStore};
use crate::config::{AccountConfig, Config};
use crate::gmail::Gmail;
use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::OnceCell;

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

pub struct Account {
    pub name: String,
    pub config: AccountConfig,
    /// Authorized scopes (shorthand names). Empty when the account failed to load.
    pub scopes: Vec<String>,
    gmail: Option<Gmail>,
    /// Why this account cannot be used, if it can't. The server still serves
    /// the other accounts.
    pub load_error: Option<String>,
    email: OnceCell<String>,
}

impl Account {
    pub fn load(config: &AccountConfig, http: &reqwest::Client, endpoints: &Endpoints) -> Self {
        let loaded = (|| -> Result<(Vec<String>, Gmail)> {
            let keys = auth::load_client_keys(&config.oauth_path)?;
            let text = std::fs::read_to_string(&config.credentials_path).map_err(|_| {
                anyhow!(
                    "Not authenticated: {} not found. Run `gmail-mcp auth {}`",
                    config.credentials_path.display(),
                    config.name
                )
            })?;
            let creds = auth::parse_credentials(&text)?;
            let store = TokenStore::new(
                keys,
                &creds,
                config.credentials_path.clone(),
                endpoints.token_url.clone(),
                http.clone(),
            );
            let gmail = Gmail::new(http.clone(), endpoints.api_base.clone(), Arc::new(store));
            Ok((creds.scopes, gmail))
        })();
        match loaded {
            Ok((scopes, gmail)) => Self {
                name: config.name.clone(),
                config: config.clone(),
                scopes,
                gmail: Some(gmail),
                load_error: None,
                email: OnceCell::new(),
            },
            Err(e) => Self {
                name: config.name.clone(),
                config: config.clone(),
                scopes: Vec::new(),
                gmail: None,
                load_error: Some(format!("{e:#}")),
                email: OnceCell::new(),
            },
        }
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
        let http = reqwest::Client::builder()
            .user_agent(concat!("gmail-mcp-rust/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("http client");
        let list = config
            .accounts
            .iter()
            .map(|a| Arc::new(Account::load(a, &http, endpoints)))
            .collect();
        Self {
            list,
            default: config.default_account.clone(),
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.list.iter().map(|a| a.name.clone()).collect()
    }

    pub fn is_multi(&self) -> bool {
        self.list.len() > 1
    }

    /// Pick the account a tool call targets.
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
        self.list
            .iter()
            .find(|a| a.name == name)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "Unknown account {name:?}. Configured accounts: {}",
                    self.names().join(", ")
                )
            })
    }
}
