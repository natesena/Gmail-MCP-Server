//! Minimal Gmail REST client bound to one account's tokens.

use crate::auth::TokenStore;
use anyhow::Result;
use reqwest::Method;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

pub const DEFAULT_API_BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

/// A Gmail API error with its HTTP status, so callers can special-case 404s
/// the way the Node server checks `error.code`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ApiError {}

/// HTTP status of an error if it came from the Gmail API.
pub fn api_status(err: &anyhow::Error) -> Option<u16> {
    err.downcast_ref::<ApiError>().map(|e| e.status)
}

pub type Query = Vec<(String, String)>;

pub fn q(pairs: &[(&str, &str)]) -> Query {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[derive(Clone)]
pub struct Gmail {
    http: reqwest::Client,
    base: String,
    tokens: Arc<TokenStore>,
}

impl Gmail {
    pub fn new(http: reqwest::Client, base: String, tokens: Arc<TokenStore>) -> Self {
        Self { http, base, tokens }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &Query,
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut rejected: Option<String> = None;
        loop {
            let token = self.tokens.access_token(rejected.as_deref()).await?;
            let mut req = self
                .http
                .request(method.clone(), &url)
                .bearer_auth(&token)
                .query(query);
            if let Some(b) = body {
                req = req.json(b);
            }
            let resp = req.send().await?;
            let status = resp.status();
            // One forced refresh on 401, for tokens revoked or expired early.
            if status.as_u16() == 401 && rejected.is_none() {
                rejected = Some(token);
                continue;
            }
            let text = resp.text().await?;
            if !status.is_success() {
                let message = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|v| v["error"]["message"].as_str().map(String::from))
                    .unwrap_or_else(|| {
                        format!("Gmail API request failed with status {}", status.as_u16())
                    });
                return Err(ApiError {
                    status: status.as_u16(),
                    message,
                }
                .into());
            }
            if text.trim().is_empty() {
                return Ok(Value::Null);
            }
            return Ok(serde_json::from_str(&text)?);
        }
    }

    pub async fn get(&self, path: &str, query: Query) -> Result<Value> {
        self.call(Method::GET, path, &query, None).await
    }
    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.call(Method::POST, path, &Vec::new(), Some(&body))
            .await
    }
    pub async fn put(&self, path: &str, body: Value) -> Result<Value> {
        self.call(Method::PUT, path, &Vec::new(), Some(&body)).await
    }
    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.call(Method::DELETE, path, &Vec::new(), None).await
    }
}

/// Percent-encode one path segment (IDs come from the model, so never trust
/// them to be URL-safe).
pub fn seg(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}
