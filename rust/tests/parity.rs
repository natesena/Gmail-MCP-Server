//! Verification 2: tool-surface parity with the Node server.
//! `fixtures/ts-tools.json` is the Node server's tools/list output (all scopes
//! granted). The single-account Rust surface must match it exactly; the
//! multi-account surface may only add `account` and `list_accounts`.

use gmail_mcp::accounts::{Accounts, Endpoints};
use gmail_mcp::config::{AccountConfig, Config};
use gmail_mcp::tools::list_tools;
use serde_json::Value;
use std::path::Path;

fn fixture() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/ts-tools.json")).unwrap()
}

fn write_account(dir: &Path, scopes: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("gcp-oauth.keys.json"),
        r#"{"installed":{"client_id":"id","client_secret":"secret"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("credentials.json"),
        serde_json::json!({"tokens":{"access_token":"a","refresh_token":"r"},"scopes":scopes})
            .to_string(),
    )
    .unwrap();
}

fn accounts(dirs: &[(&str, &Path)], default: Option<&str>) -> Accounts {
    let cfg = Config {
        accounts: dirs
            .iter()
            .map(|(n, d)| AccountConfig {
                name: n.to_string(),
                oauth_path: d.join("gcp-oauth.keys.json"),
                credentials_path: d.join("credentials.json"),
            })
            .collect(),
        default_account: default
            .map(String::from)
            .or_else(|| (dirs.len() == 1).then(|| dirs[0].0.to_string())),
        source: "test".into(),
    };
    Accounts::load(
        &cfg,
        &Endpoints {
            api_base: "http://unused".into(),
            token_url: "http://unused".into(),
        },
    )
}

fn strip_schema_meta(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(o) = v.as_object_mut() {
        o.remove("$schema");
    }
    v
}

const ALL: &[&str] = &["gmail.modify", "gmail.settings.basic", "gmail.full"];

#[test]
fn single_account_surface_is_identical_to_node() {
    let tmp = tempfile::tempdir().unwrap();
    write_account(tmp.path(), ALL);
    let rust = list_tools(&accounts(&[("default", tmp.path())], None), "");
    let ts = fixture();
    assert_eq!(rust.len(), ts.len(), "tool count");
    for (r, t) in rust.iter().zip(ts.iter()) {
        assert_eq!(r["name"], t["name"]);
        assert_eq!(r["description"], t["description"], "{}", t["name"]);
        assert_eq!(r["annotations"], t["annotations"], "{}", t["name"]);
        assert_eq!(
            r["inputSchema"],
            strip_schema_meta(&t["inputSchema"]),
            "{}",
            t["name"]
        );
    }
}

#[test]
fn multi_account_surface_only_adds_account_and_list_accounts() {
    let tmp = tempfile::tempdir().unwrap();
    let (p, w) = (tmp.path().join("p"), tmp.path().join("w"));
    write_account(&p, ALL);
    write_account(&w, ALL);
    let rust = list_tools(&accounts(&[("personal", &p), ("work", &w)], None), "");
    assert_eq!(rust[0]["name"], "list_accounts");
    let ts = fixture();
    assert_eq!(rust.len(), ts.len() + 1);
    for (r, t) in rust[1..].iter().zip(ts.iter()) {
        assert_eq!(r["name"], t["name"]);
        assert_eq!(r["annotations"], t["annotations"]);
        let mut rs = r["inputSchema"].clone();
        let acct = rs["properties"]
            .as_object_mut()
            .unwrap()
            .remove("account")
            .expect("account prop");
        let fan_out = gmail_mcp::tools::ALL_ACCOUNT_TOOLS.contains(&t["name"].as_str().unwrap());
        let expected = if fan_out {
            serde_json::json!(["personal", "work", "all"])
        } else {
            serde_json::json!(["personal", "work"])
        };
        assert_eq!(acct["enum"], expected, "{}", t["name"]);
        // no default => account is required, appended last
        let req = rs["required"].as_array_mut().unwrap();
        assert_eq!(req.pop().unwrap(), "account", "{}", t["name"]);
        if req.is_empty() && t["inputSchema"].get("required").is_none() {
            rs.as_object_mut().unwrap().remove("required");
        }
        assert_eq!(rs, strip_schema_meta(&t["inputSchema"]), "{}", t["name"]);
    }
}

#[test]
fn default_account_makes_account_optional() {
    let tmp = tempfile::tempdir().unwrap();
    let (p, w) = (tmp.path().join("p"), tmp.path().join("w"));
    write_account(&p, ALL);
    write_account(&w, ALL);
    let rust = list_tools(
        &accounts(&[("personal", &p), ("work", &w)], Some("personal")),
        "",
    );
    for t in &rust[1..] {
        let req = t["inputSchema"]["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(!req.contains(&"account".into()), "{}", t["name"]);
        assert!(t["inputSchema"]["properties"]["account"]["description"]
            .as_str()
            .unwrap()
            .contains("Defaults to \"personal\""));
    }
}

#[test]
fn per_account_scopes_shape_the_tool_list() {
    let tmp = tempfile::tempdir().unwrap();
    let (p, w) = (tmp.path().join("p"), tmp.path().join("w"));
    write_account(&p, &["gmail.readonly"]);
    write_account(&w, &["gmail.modify", "gmail.settings.basic"]);
    let tools = list_tools(&accounts(&[("personal", &p), ("work", &w)], None), "x_");
    let find = |n: &str| {
        tools
            .iter()
            .find(|t| t["name"] == format!("x_{n}"))
            .cloned()
    };
    // read tools: both accounts
    let read = find("read_email").unwrap();
    assert_eq!(
        read["inputSchema"]["properties"]["account"]["enum"],
        serde_json::json!(["personal", "work"])
    );
    // modify: work only, and the description says so
    let modify = find("modify_email").unwrap();
    assert_eq!(
        modify["inputSchema"]["properties"]["account"]["enum"],
        serde_json::json!(["work"])
    );
    assert!(modify["description"]
        .as_str()
        .unwrap()
        .contains("Available for accounts: work"));
    // gmail.full tools: nobody
    assert!(find("delete_email").is_none());
    assert!(find("list_accounts").is_some());
}

#[test]
fn single_readonly_account_matches_node_scope_filtering() {
    let tmp = tempfile::tempdir().unwrap();
    write_account(tmp.path(), &["gmail.readonly"]);
    let names: Vec<String> = list_tools(&accounts(&[("default", tmp.path())], None), "")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"read_email".to_string()));
    assert!(names.contains(&"list_email_labels".to_string()));
    assert!(!names.contains(&"send_email".to_string()));
    assert!(!names.contains(&"list_filters".to_string()));
    assert!(!names.contains(&"list_accounts".to_string()));
}
