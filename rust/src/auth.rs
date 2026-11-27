//! OAuth2 for one Gmail account: load keys and stored tokens, refresh access
//! tokens on demand, persist refreshed tokens, and run the interactive `auth`
//! flow. Every account owns its own [`TokenStore`], so accounts refresh and
//! persist independently.

use crate::config::AccountConfig;
use crate::scopes;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

pub const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const DEFAULT_CALLBACK: &str = "http://localhost:3000/oauth2callback";

/// Refresh this long before the recorded expiry.
const EXPIRY_MARGIN_MS: i64 = 60_000;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct ClientKeys {
    pub client_id: String,
    pub client_secret: String,
}

/// Read `gcp-oauth.keys.json` (either the `installed` or `web` shape).
pub fn load_client_keys(path: &Path) -> Result<ClientKeys> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("OAuth keys file not found: {}", path.display()))?;
    let v: Value = serde_json::from_str(&text)
        .with_context(|| format!("OAuth keys file is not valid JSON: {}", path.display()))?;
    let keys = v
        .get("installed")
        .or_else(|| v.get("web"))
        .ok_or_else(|| {
            anyhow!(
                "Invalid OAuth keys file format ({}): it should contain \"installed\" or \"web\" credentials",
                path.display()
            )
        })?;
    let get = |k: &str| {
        keys.get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| anyhow!("OAuth keys file {} is missing {k}", path.display()))
    };
    Ok(ClientKeys {
        client_id: get("client_id")?,
        client_secret: get("client_secret")?,
    })
}

/// Stored credentials. Supports the v1.2.0+ shape `{ tokens, scopes }` and
/// the legacy shape where the file is the token object itself (legacy files
/// get the default scopes until re-authenticated).
#[derive(Debug, Clone)]
pub struct StoredCredentials {
    pub tokens: Map<String, Value>,
    pub scopes: Vec<String>,
}

pub fn parse_credentials(text: &str) -> Result<StoredCredentials> {
    let v: Value = serde_json::from_str(text).context("credentials file is not valid JSON")?;
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow!("credentials file must be a JSON object"))?;
    let tokens = match obj.get("tokens") {
        Some(Value::Object(t)) => t.clone(),
        _ => obj.clone(),
    };
    let scopes = obj
        .get("scopes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_else(scopes::default_scopes);
    Ok(StoredCredentials { tokens, scopes })
}

/// Merge freshly refreshed tokens into the on-disk credentials JSON, matching
/// the Node server: with a new refresh_token everything is merged; otherwise
/// only access_token and expiry_date change. The file shape (wrapped or
/// legacy) is preserved.
pub fn merge_refreshed(on_disk: &Value, new_tokens: &Map<String, Value>) -> Value {
    let wrapped = on_disk.get("tokens").map(Value::is_object).unwrap_or(false);
    let current = if wrapped {
        on_disk["tokens"].as_object().cloned().unwrap_or_default()
    } else {
        on_disk.as_object().cloned().unwrap_or_default()
    };
    let mut merged = current;
    if new_tokens.contains_key("refresh_token") {
        for (k, v) in new_tokens {
            merged.insert(k.clone(), v.clone());
        }
    } else {
        for k in ["access_token", "expiry_date"] {
            if let Some(v) = new_tokens.get(k) {
                merged.insert(k.to_string(), v.clone());
            }
        }
    }
    if wrapped {
        let mut out = on_disk.as_object().cloned().unwrap_or_default();
        out.insert("tokens".into(), Value::Object(merged));
        Value::Object(out)
    } else {
        Value::Object(merged)
    }
}

pub fn write_private(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let text = serde_json::to_string_pretty(value)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, text)?;
    Ok(())
}

/// Turn a token-endpoint response into the token map we store: compute
/// `expiry_date` (ms since epoch) from `expires_in`, like google-auth-library.
pub fn normalize_token_response(resp: &Value) -> Result<Map<String, Value>> {
    let mut obj = resp
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("token endpoint returned a non-object"))?;
    if obj.get("access_token").and_then(Value::as_str).is_none() {
        let err = obj
            .get("error_description")
            .or_else(|| obj.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("no access_token in response");
        bail!("Token request failed: {err}");
    }
    if let Some(secs) = obj.remove("expires_in").and_then(|v| v.as_i64()) {
        obj.insert("expiry_date".into(), json!(now_ms() + secs * 1000));
    }
    Ok(obj)
}

struct TokenState {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expiry_date: Option<i64>,
}

/// One account's tokens plus what it needs to refresh them.
pub struct TokenStore {
    keys: ClientKeys,
    credentials_path: PathBuf,
    token_url: String,
    http: reqwest::Client,
    state: Mutex<TokenState>,
}

impl TokenStore {
    pub fn new(
        keys: ClientKeys,
        creds: &StoredCredentials,
        credentials_path: PathBuf,
        token_url: String,
        http: reqwest::Client,
    ) -> Self {
        let s = |k: &str| {
            creds
                .tokens
                .get(k)
                .and_then(Value::as_str)
                .map(String::from)
        };
        let state = TokenState {
            access_token: s("access_token"),
            refresh_token: s("refresh_token"),
            expiry_date: creds.tokens.get("expiry_date").and_then(Value::as_i64),
        };
        Self {
            keys,
            credentials_path,
            token_url,
            http,
            state: Mutex::new(state),
        }
    }

    /// A valid access token, refreshing first if it is missing or about to
    /// expire. `force` refreshes unconditionally (used after a 401).
    pub async fn access_token(&self, force: bool) -> Result<String> {
        let mut st = self.state.lock().await;
        let fresh = match (&st.access_token, st.expiry_date) {
            (Some(_), Some(exp)) => exp - EXPIRY_MARGIN_MS > now_ms(),
            (Some(_), None) => true,
            (None, _) => false,
        };
        if fresh && !force {
            return Ok(st.access_token.clone().unwrap_or_default());
        }
        let refresh = st.refresh_token.clone().ok_or_else(|| {
            anyhow!("No refresh token stored; re-run `gmail-mcp auth` for this account")
        })?;
        let resp = self
            .http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", self.keys.client_id.as_str()),
                ("client_secret", self.keys.client_secret.as_str()),
            ])
            .send()
            .await
            .context("Token refresh request failed")?;
        let body: Value = resp
            .json()
            .await
            .context("Token refresh returned non-JSON")?;
        let tokens = normalize_token_response(&body)?;
        st.access_token = tokens
            .get("access_token")
            .and_then(Value::as_str)
            .map(String::from);
        st.expiry_date = tokens.get("expiry_date").and_then(Value::as_i64);
        if let Some(r) = tokens.get("refresh_token").and_then(Value::as_str) {
            st.refresh_token = Some(r.to_string());
        }
        // Persist so the next process start doesn't re-read a stale token.
        if let Err(e) = self.persist(&tokens) {
            eprintln!(
                "Failed to persist refreshed tokens to {}: {e:#}",
                self.credentials_path.display()
            );
        }
        Ok(st.access_token.clone().unwrap_or_default())
    }

    fn persist(&self, tokens: &Map<String, Value>) -> Result<()> {
        let on_disk: Value = match std::fs::read_to_string(&self.credentials_path) {
            Ok(t) => serde_json::from_str(&t).unwrap_or_else(|_| json!({})),
            Err(_) => json!({}),
        };
        write_private(&self.credentials_path, &merge_refreshed(&on_disk, tokens))
    }
}

/// Port derivation for the local callback listener (same as the Node server):
/// explicit port -> it; portless http -> 80; https -> 3000 (reverse proxy).
pub fn callback_port(callback: &url::Url) -> u16 {
    match callback.port() {
        Some(p) => p,
        None if callback.scheme() == "https" => 3000,
        None => 80,
    }
}

pub fn build_auth_url(keys: &ClientKeys, callback: &str, scope_names: &[String]) -> String {
    let scope = scopes::scope_names_to_urls(scope_names).join(" ");
    let mut u = url::Url::parse(AUTH_URL).expect("static url");
    u.query_pairs_mut()
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("scope", &scope)
        .append_pair("response_type", "code")
        .append_pair("client_id", &keys.client_id)
        .append_pair("redirect_uri", callback);
    u.to_string()
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let r = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let r = std::process::Command::new("xdg-open").arg(url).spawn();
    if r.is_err() {
        eprintln!("Could not open a browser; open the URL above manually.");
    }
}

/// Interactive OAuth flow for one account. Writes `{ tokens, scopes }` to the
/// account's credentials file (mode 0600).
pub async fn authenticate(
    account: &AccountConfig,
    scope_names: &[String],
    callback: &str,
    token_url: &str,
) -> Result<()> {
    let keys = load_client_keys(&account.oauth_path)?;
    let callback_url = url::Url::parse(callback).context("Invalid callback URL")?;
    if callback_url.scheme() == "https" {
        println!("https callback URL detected: assuming a reverse proxy terminates TLS and forwards to the local listener on port 3000.");
    }
    let port = callback_port(&callback_url);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("Cannot listen on 127.0.0.1:{port} for the OAuth callback"))?;

    let auth_url = build_auth_url(&keys, callback, scope_names);
    println!("Authorizing account {:?}", account.name);
    println!("Requesting scopes: {}", scope_names.join(", "));
    println!("Please visit this URL to authenticate: {auth_url}");
    open_browser(&auth_url);

    let http = reqwest::Client::new();
    loop {
        let (mut sock, _) = listener.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let target = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        if !target.starts_with(callback_url.path()) {
            let _ = sock
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await;
            continue;
        }
        let parsed = url::Url::parse(&format!("http://localhost{target}"))?;
        let code = parsed
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.to_string());
        let reply = |status: &str, body: &str| {
            format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let Some(code) = code else {
            let _ = sock
                .write_all(reply("400 Bad Request", "No code provided").as_bytes())
                .await;
            bail!("No code provided");
        };
        let result: Result<Map<String, Value>> = async {
            let resp = http
                .post(token_url)
                .form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code.as_str()),
                    ("redirect_uri", callback),
                    ("client_id", keys.client_id.as_str()),
                    ("client_secret", keys.client_secret.as_str()),
                ])
                .send()
                .await?;
            normalize_token_response(&resp.json::<Value>().await?)
        }
        .await;
        match result {
            Ok(tokens) => {
                write_private(
                    &account.credentials_path,
                    &json!({ "tokens": tokens, "scopes": scope_names }),
                )?;
                let _ = sock
                    .write_all(
                        reply(
                            "200 OK",
                            "Authentication successful! You can close this window.",
                        )
                        .as_bytes(),
                    )
                    .await;
                println!("Credentials saved with scopes: {}", scope_names.join(", "));
                return Ok(());
            }
            Err(e) => {
                let _ = sock
                    .write_all(
                        reply("500 Internal Server Error", "Authentication failed").as_bytes(),
                    )
                    .await;
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wrapped_and_legacy_credentials() {
        let c = parse_credentials(r#"{"tokens":{"access_token":"a"},"scopes":["gmail.readonly"]}"#)
            .unwrap();
        assert_eq!(c.tokens["access_token"], "a");
        assert_eq!(c.scopes, vec!["gmail.readonly"]);
        let legacy = parse_credentials(r#"{"access_token":"b","refresh_token":"r"}"#).unwrap();
        assert_eq!(legacy.tokens["refresh_token"], "r");
        assert_eq!(legacy.scopes, scopes::default_scopes());
    }

    #[test]
    fn merge_without_new_refresh_token_only_updates_access_and_expiry() {
        let disk = json!({"tokens":{"access_token":"old","refresh_token":"keep","scope":"s"},"scopes":["gmail.modify"]});
        let mut new = Map::new();
        new.insert("access_token".into(), json!("new"));
        new.insert("expiry_date".into(), json!(5));
        new.insert("scope".into(), json!("changed"));
        let m = merge_refreshed(&disk, &new);
        assert_eq!(m["tokens"]["access_token"], "new");
        assert_eq!(m["tokens"]["refresh_token"], "keep");
        assert_eq!(m["tokens"]["scope"], "s");
        assert_eq!(m["tokens"]["expiry_date"], 5);
        assert_eq!(m["scopes"], json!(["gmail.modify"]));
    }

    #[test]
    fn merge_with_new_refresh_token_merges_all_and_keeps_legacy_shape() {
        let disk = json!({"access_token":"old","refresh_token":"r1","x":1});
        let mut new = Map::new();
        new.insert("access_token".into(), json!("new"));
        new.insert("refresh_token".into(), json!("r2"));
        let m = merge_refreshed(&disk, &new);
        assert_eq!(m, json!({"access_token":"new","refresh_token":"r2","x":1}));
    }

    #[test]
    fn token_response_gets_expiry_date() {
        let t = normalize_token_response(&json!({"access_token":"a","expires_in":3600})).unwrap();
        assert!(t["expiry_date"].as_i64().unwrap() > now_ms());
        assert!(!t.contains_key("expires_in"));
        assert!(normalize_token_response(&json!({"error":"invalid_grant"}))
            .unwrap_err()
            .to_string()
            .contains("invalid_grant"));
    }

    #[test]
    fn callback_port_derivation() {
        let p = |s: &str| callback_port(&url::Url::parse(s).unwrap());
        assert_eq!(p("http://localhost:3000/cb"), 3000);
        assert_eq!(p("http://localhost/cb"), 80);
        assert_eq!(p("https://example.com/cb"), 3000);
    }

    #[test]
    fn auth_url_contains_offline_consent_and_scope_urls() {
        let keys = ClientKeys {
            client_id: "cid".into(),
            client_secret: "s".into(),
        };
        let u = build_auth_url(&keys, DEFAULT_CALLBACK, &["gmail.readonly".into()]);
        assert!(u.contains("access_type=offline"));
        assert!(u.contains("prompt=consent"));
        assert!(u.contains("client_id=cid"));
        assert!(u.contains("gmail.readonly"));
    }
}
