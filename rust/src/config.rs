//! Account configuration: which Gmail accounts this one process serves.
//!
//! Resolution order (first match wins):
//!   1. `--account NAME=DIR` flags (repeatable). DIR holds `gcp-oauth.keys.json`
//!      and `credentials.json`, the layout the Node server already uses.
//!   2. An accounts file: `--config PATH`, else `$GMAIL_MCP_CONFIG`, else
//!      `~/.gmail-mcp/accounts.json` when it exists.
//!   3. Single-account fallback (backward compatible): `$GMAIL_OAUTH_PATH` /
//!      `$GMAIL_CREDENTIALS_PATH`, else `~/.gmail-mcp/`. The account is named
//!      `default`.
//!
//! Accounts file format:
//! ```json
//! {
//!   "default": "personal",
//!   "accounts": {
//!     "personal": { "dir": "~/.gmail-personal" },
//!     "work": {
//!       "oauthPath": "~/.gmail-work/gcp-oauth.keys.json",
//!       "credentialsPath": "~/.gmail-work/credentials.json"
//!     }
//!   }
//! }
//! ```

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const OAUTH_FILE: &str = "gcp-oauth.keys.json";
pub const CREDENTIALS_FILE: &str = "credentials.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountConfig {
    pub name: String,
    pub oauth_path: PathBuf,
    pub credentials_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Accounts in a stable order (file order / flag order).
    pub accounts: Vec<AccountConfig>,
    /// Account used when a tool call omits `account`. Always set when there is
    /// exactly one account.
    pub default_account: Option<String>,
    /// Where the config came from, for diagnostics.
    pub source: String,
}

impl Config {
    pub fn get(&self, name: &str) -> Option<&AccountConfig> {
        self.accounts.iter().find(|a| a.name == name)
    }

    pub fn names(&self) -> Vec<String> {
        self.accounts.iter().map(|a| a.name.clone()).collect()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileAccount {
    dir: Option<String>,
    oauth_path: Option<String>,
    credentials_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    default: Option<String>,
    // serde_json's preserve_order keeps file order in the Map.
    accounts: serde_json::Map<String, serde_json::Value>,
}

/// Inputs to resolution, gathered from argv and the environment so the logic
/// is testable without touching the real process state.
#[derive(Debug, Default, Clone)]
pub struct ConfigInputs {
    pub account_flags: Vec<String>,
    pub config_flag: Option<String>,
    pub default_flag: Option<String>,
    pub env: HashMap<String, String>,
    pub home: PathBuf,
}

pub fn expand_tilde(p: &str, home: &Path) -> PathBuf {
    if p == "~" {
        home.to_path_buf()
    } else if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(p)
    }
}

pub fn validate_account_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!("Invalid account name {name:?}: use letters, digits, '-' or '_'");
    }
    Ok(())
}

fn from_dir(name: &str, dir: &Path) -> AccountConfig {
    AccountConfig {
        name: name.to_string(),
        oauth_path: dir.join(OAUTH_FILE),
        credentials_path: dir.join(CREDENTIALS_FILE),
    }
}

fn finish(accounts: Vec<AccountConfig>, default: Option<String>, source: String) -> Result<Config> {
    if accounts.is_empty() {
        bail!("No Gmail accounts configured ({source})");
    }
    let mut seen = std::collections::HashSet::new();
    for a in &accounts {
        validate_account_name(&a.name)?;
        if !seen.insert(a.name.clone()) {
            bail!("Account {:?} is configured twice ({source})", a.name);
        }
    }
    let default_account = match default {
        Some(d) => {
            if !accounts.iter().any(|a| a.name == d) {
                bail!(
                    "Default account {d:?} is not one of the configured accounts: {}",
                    accounts
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Some(d)
        }
        None if accounts.len() == 1 => Some(accounts[0].name.clone()),
        None => None,
    };
    Ok(Config {
        accounts,
        default_account,
        source,
    })
}

pub fn parse_config_file(
    text: &str,
    home: &Path,
    source: &str,
) -> Result<(Vec<AccountConfig>, Option<String>)> {
    let file: ConfigFile =
        serde_json::from_str(text).with_context(|| format!("Invalid accounts file {source}"))?;
    let mut accounts = Vec::new();
    for (name, value) in file.accounts {
        let fa: FileAccount = serde_json::from_value(value)
            .with_context(|| format!("Invalid entry for account {name:?} in {source}"))?;
        let acct = match (fa.dir, fa.oauth_path, fa.credentials_path) {
            (_, Some(o), Some(c)) => AccountConfig {
                name: name.clone(),
                oauth_path: expand_tilde(&o, home),
                credentials_path: expand_tilde(&c, home),
            },
            (Some(dir), o, c) => {
                let d = expand_tilde(&dir, home);
                let mut a = from_dir(&name, &d);
                if let Some(o) = o {
                    a.oauth_path = expand_tilde(&o, home);
                }
                if let Some(c) = c {
                    a.credentials_path = expand_tilde(&c, home);
                }
                a
            }
            _ => bail!(
                "Account {name:?} in {source} needs \"dir\" or both \"oauthPath\" and \"credentialsPath\""
            ),
        };
        accounts.push(acct);
    }
    Ok((accounts, file.default))
}

pub fn resolve(inputs: &ConfigInputs) -> Result<Config> {
    let home = &inputs.home;

    // 1. --account NAME=DIR flags
    if !inputs.account_flags.is_empty() {
        let mut accounts = Vec::new();
        for flag in &inputs.account_flags {
            let (name, dir) = flag
                .split_once('=')
                .ok_or_else(|| anyhow!("--account expects NAME=DIR, got {flag:?}"))?;
            accounts.push(from_dir(name.trim(), &expand_tilde(dir.trim(), home)));
        }
        return finish(
            accounts,
            inputs.default_flag.clone(),
            "--account flags".into(),
        );
    }

    // 2. accounts file
    let explicit = inputs
        .config_flag
        .clone()
        .or_else(|| inputs.env.get("GMAIL_MCP_CONFIG").cloned());
    let implicit = home.join(".gmail-mcp").join("accounts.json");
    let file_path = match explicit {
        Some(p) => Some(expand_tilde(&p, home)),
        None if implicit.exists() => Some(implicit),
        None => None,
    };
    if let Some(path) = file_path {
        let source = path.display().to_string();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Cannot read accounts file {source}"))?;
        let (accounts, default) = parse_config_file(&text, home, &source)?;
        return finish(accounts, inputs.default_flag.clone().or(default), source);
    }

    // 3. single-account fallback (same env vars as the Node server)
    let dir = home.join(".gmail-mcp");
    let oauth_path = inputs
        .env
        .get("GMAIL_OAUTH_PATH")
        .map(|p| expand_tilde(p, home))
        .unwrap_or_else(|| dir.join(OAUTH_FILE));
    let credentials_path = inputs
        .env
        .get("GMAIL_CREDENTIALS_PATH")
        .map(|p| expand_tilde(p, home))
        .unwrap_or_else(|| dir.join(CREDENTIALS_FILE));
    finish(
        vec![AccountConfig {
            name: "default".into(),
            oauth_path,
            credentials_path,
        }],
        None,
        "single-account mode".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(home: &Path) -> ConfigInputs {
        ConfigInputs {
            home: home.to_path_buf(),
            ..Default::default()
        }
    }

    #[test]
    fn account_flags_define_accounts_in_order() {
        let home = Path::new("/h");
        let mut i = inputs(home);
        i.account_flags = vec!["personal=~/.gmail-personal".into(), "work=/x/work".into()];
        let c = resolve(&i).unwrap();
        assert_eq!(c.names(), vec!["personal", "work"]);
        assert_eq!(
            c.get("personal").unwrap().credentials_path,
            PathBuf::from("/h/.gmail-personal/credentials.json")
        );
        assert_eq!(
            c.get("work").unwrap().oauth_path,
            PathBuf::from("/x/work/gcp-oauth.keys.json")
        );
        assert_eq!(c.default_account, None, "two accounts, no default");
    }

    #[test]
    fn default_flag_must_exist() {
        let mut i = inputs(Path::new("/h"));
        i.account_flags = vec!["a=/a".into(), "b=/b".into()];
        i.default_flag = Some("b".into());
        assert_eq!(resolve(&i).unwrap().default_account.as_deref(), Some("b"));
        i.default_flag = Some("zzz".into());
        assert!(resolve(&i).is_err());
    }

    #[test]
    fn rejects_duplicates_and_bad_names() {
        let mut i = inputs(Path::new("/h"));
        i.account_flags = vec!["a=/a".into(), "a=/b".into()];
        assert!(resolve(&i).unwrap_err().to_string().contains("twice"));
        i.account_flags = vec!["has space=/a".into()];
        assert!(resolve(&i).is_err());
        i.account_flags = vec!["nodir".into()];
        assert!(resolve(&i).is_err());
    }

    #[test]
    fn config_file_dir_and_explicit_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("accounts.json");
        std::fs::write(
            &path,
            r#"{"default":"work","accounts":{
                "personal":{"dir":"~/.gmail-personal"},
                "work":{"oauthPath":"/o.json","credentialsPath":"/c.json"}}}"#,
        )
        .unwrap();
        let mut i = inputs(Path::new("/h"));
        i.config_flag = Some(path.display().to_string());
        let c = resolve(&i).unwrap();
        assert_eq!(c.names(), vec!["personal", "work"]);
        assert_eq!(c.default_account.as_deref(), Some("work"));
        assert_eq!(c.get("work").unwrap().oauth_path, PathBuf::from("/o.json"));
        assert_eq!(
            c.get("personal").unwrap().oauth_path,
            PathBuf::from("/h/.gmail-personal/gcp-oauth.keys.json")
        );
    }

    #[test]
    fn config_file_via_env_and_implicit_home_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".gmail-mcp")).unwrap();
        std::fs::write(
            tmp.path().join(".gmail-mcp/accounts.json"),
            r#"{"accounts":{"only":{"dir":"/d"}}}"#,
        )
        .unwrap();
        let c = resolve(&inputs(tmp.path())).unwrap();
        assert_eq!(c.names(), vec!["only"]);
        assert_eq!(
            c.default_account.as_deref(),
            Some("only"),
            "single account is default"
        );
    }

    #[test]
    fn invalid_account_entry_is_reported() {
        let r = parse_config_file(r#"{"accounts":{"x":{}}}"#, Path::new("/h"), "f");
        assert!(r.unwrap_err().to_string().contains("needs"));
    }

    #[test]
    fn single_account_fallback_uses_env_paths() {
        let mut i = inputs(Path::new("/h"));
        i.env
            .insert("GMAIL_OAUTH_PATH".into(), "/k/oauth.json".into());
        let c = resolve(&i).unwrap();
        assert_eq!(c.names(), vec!["default"]);
        assert_eq!(c.default_account.as_deref(), Some("default"));
        assert_eq!(c.accounts[0].oauth_path, PathBuf::from("/k/oauth.json"));
        assert_eq!(
            c.accounts[0].credentials_path,
            PathBuf::from("/h/.gmail-mcp/credentials.json")
        );
    }
}
