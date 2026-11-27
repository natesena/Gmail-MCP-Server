//! `gmail-mcp accounts ...` and `gmail-mcp store ...`: managing the encrypted
//! store on the host, so Google sign-in happens on one machine only.

use crate::accounts::{http_client, Endpoints};
use crate::auth::{self, ClientKeys, TokenStore};
use crate::gmail::Gmail;
use crate::scopes;
use crate::store::{Store, StoredAccount};
use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use serde_json::{Map, Value};
use std::path::Path;
use std::sync::Arc;

/// Redirect for the paste-back flow. Google "Desktop app" OAuth clients
/// accept any loopback redirect; nothing needs to listen there: the browser
/// shows an error page and the user copies its address back.
pub const PASTE_REDIRECT: &str = "http://localhost:8765/oauth2callback";

/// Fetch the account's email address with a just-obtained token.
pub async fn email_for(
    keys: &ClientKeys,
    tokens: &Map<String, Value>,
    endpoints: &Endpoints,
) -> Result<String> {
    let http = http_client();
    let noop: auth::PersistFn = Arc::new(|_| Ok(()));
    let ts = TokenStore::new(
        keys.clone(),
        tokens,
        noop,
        endpoints.token_url.clone(),
        http.clone(),
    );
    let g = Gmail::new(http, endpoints.api_base.clone(), Arc::new(ts));
    let p = g
        .get("/profile", Vec::new())
        .await
        .context("could not read the account's Gmail profile")?;
    p["emailAddress"]
        .as_str()
        .filter(|e| !e.is_empty())
        .map(String::from)
        .ok_or_else(|| anyhow!("Gmail profile has no emailAddress"))
}

/// Store the OAuth client (gcp-oauth.keys.json) once for every account.
pub fn set_client(store: &Store, keys_file: &Path) -> Result<ClientKeys> {
    let keys = auth::load_client_keys(keys_file)?;
    store.update(|d| {
        d.client = Some(keys.clone());
        Ok(())
    })?;
    Ok(keys)
}

/// Import an existing credentials directory (the Node server's layout)
/// without a new Google sign-in.
pub async fn import(
    store: &Store,
    alias: &str,
    dir: &Path,
    endpoints: &Endpoints,
) -> Result<StoredAccount> {
    crate::config::validate_account_name(alias)?;
    let keys = auth::load_client_keys(&dir.join(crate::config::OAUTH_FILE))?;
    let creds_path = dir.join(crate::config::CREDENTIALS_FILE);
    let creds = auth::parse_credentials(
        &std::fs::read_to_string(&creds_path)
            .with_context(|| format!("cannot read {}", creds_path.display()))?,
    )?;
    if creds
        .tokens
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_none()
    {
        bail!(
            "{} has no refresh_token; authorize it again with `accounts add`",
            creds_path.display()
        );
    }
    let email = email_for(&keys, &creds.tokens, endpoints).await?;
    let acct = store.update(|d| {
        let own_client = match &d.client {
            None => {
                d.client = Some(keys.clone());
                None
            }
            Some(c) if *c == keys => None,
            Some(_) => Some(keys.clone()),
        };
        let acct = StoredAccount {
            alias: alias.to_string(),
            email: email.clone(),
            scopes: creds.scopes.clone(),
            tokens: creds.tokens.clone(),
            client: own_client,
        };
        d.upsert(acct.clone());
        Ok(acct)
    })?;
    Ok(acct)
}

pub struct PendingAdd {
    pub url: String,
    pub state: String,
    pub redirect: String,
    pub scopes: Vec<String>,
    pub keys: ClientKeys,
}

/// Step 1 of `accounts add`: the consent URL to open in any browser.
pub fn begin_add(store: &Store, scope_names: &[String], redirect: &str) -> Result<PendingAdd> {
    let bad = scopes::invalid_scopes(scope_names);
    if !bad.is_empty() {
        bail!(
            "Invalid scope(s): {}. Available: {}",
            bad.join(", "),
            scopes::available_scope_names().join(", ")
        );
    }
    let keys = store
        .load()?
        .client
        .ok_or_else(|| anyhow!("no OAuth client in the store yet: run `gmail-mcp store set-client gcp-oauth.keys.json`"))?;
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    let state: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut url = url::Url::parse(&auth::build_auth_url(&keys, redirect, scope_names))?;
    url.query_pairs_mut().append_pair("state", &state);
    Ok(PendingAdd {
        url: url.to_string(),
        state,
        redirect: redirect.to_string(),
        scopes: scope_names.to_vec(),
        keys,
    })
}

/// Pull the authorization code out of what the user pasted: the full
/// redirect URL (state is checked) or just the code.
pub fn extract_code(pasted: &str, expected_state: &str) -> Result<String> {
    let p = pasted.trim();
    if p.starts_with("http://") || p.starts_with("https://") {
        let u = url::Url::parse(p).context("could not parse the pasted URL")?;
        let get = |k: &str| {
            u.query_pairs()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.to_string())
        };
        if let Some(err) = get("error") {
            bail!("Google returned an error: {err}");
        }
        if get("state").as_deref() != Some(expected_state) {
            bail!("the pasted URL is from a different sign-in attempt (state mismatch)");
        }
        get("code").ok_or_else(|| anyhow!("the pasted URL has no code"))
    } else if p.is_empty() {
        bail!("nothing pasted")
    } else {
        Ok(p.to_string())
    }
}

/// Step 2 of `accounts add`: exchange the code, look up the email, save.
pub async fn finish_add(
    store: &Store,
    alias: &str,
    pending: &PendingAdd,
    pasted: &str,
    endpoints: &Endpoints,
) -> Result<StoredAccount> {
    crate::config::validate_account_name(alias)?;
    let code = extract_code(pasted, &pending.state)?;
    let resp = http_client()
        .post(&endpoints.token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", pending.redirect.as_str()),
            ("client_id", pending.keys.client_id.as_str()),
            ("client_secret", pending.keys.client_secret.as_str()),
        ])
        .send()
        .await?;
    let tokens = auth::normalize_token_response(&resp.json::<Value>().await?)?;
    if tokens
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_none()
    {
        bail!("Google returned no refresh token; remove the app's access at myaccount.google.com/permissions and try again");
    }
    let email = email_for(&pending.keys, &tokens, endpoints).await?;
    store.update(|d| {
        let acct = StoredAccount {
            alias: alias.to_string(),
            email: email.clone(),
            scopes: pending.scopes.clone(),
            tokens: tokens.clone(),
            client: None,
        };
        d.upsert(acct.clone());
        Ok(acct)
    })
}

pub fn list_text(store: &Store) -> Result<String> {
    let d = store.load()?;
    if d.accounts.is_empty() {
        return Ok(
            "No accounts. Add one with `gmail-mcp accounts import` or `accounts add`.".into(),
        );
    }
    let default = d
        .default
        .clone()
        .or_else(|| (d.accounts.len() == 1).then(|| d.accounts[0].alias.clone()));
    Ok(d.accounts
        .iter()
        .map(|a| {
            format!(
                "{}{}  {}  [{}]",
                if default.as_deref() == Some(a.alias.as_str()) {
                    "* "
                } else {
                    "  "
                },
                a.alias,
                a.email,
                a.scopes.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub fn remove(store: &Store, alias: &str) -> Result<()> {
    store.update(|d| {
        if d.remove(alias) {
            Ok(())
        } else {
            bail!("no account {alias:?}")
        }
    })
}

pub fn set_default(store: &Store, alias: &str) -> Result<()> {
    store.update(|d| {
        if d.get(alias).is_none() {
            bail!("no account {alias:?}");
        }
        d.default = Some(alias.to_string());
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_code_checks_state() {
        let u = "http://localhost:8765/oauth2callback?state=abc&code=4/xyz&scope=s";
        assert_eq!(extract_code(u, "abc").unwrap(), "4/xyz");
        assert!(extract_code(u, "zzz")
            .unwrap_err()
            .to_string()
            .contains("state mismatch"));
        assert!(extract_code(
            "http://localhost:8765/cb?error=access_denied&state=abc",
            "abc"
        )
        .is_err());
        assert_eq!(
            extract_code("  4/raw-code \n", "abc").unwrap(),
            "4/raw-code"
        );
        assert!(extract_code("", "abc").is_err());
    }
}
