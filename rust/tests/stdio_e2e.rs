//! Verification 4: run the real binary over stdio with two accounts (from an
//! accounts file) against a mock Gmail API: initialize, tools/list,
//! tools/call on both accounts, in one process.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn write_account(dir: &std::path::Path, token: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("gcp-oauth.keys.json"),
        r#"{"installed":{"client_id":"id","client_secret":"s"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("credentials.json"),
        json!({"tokens":{"access_token":token,"refresh_token":"r","expiry_date":4_102_444_800_000i64},"scopes":["gmail.modify","gmail.settings.basic"]}).to_string(),
    )
    .unwrap();
}

#[tokio::test]
async fn binary_serves_two_accounts_over_stdio() {
    let mock = MockServer::start().await;
    for (tok, email) in [("tok-a", "a@personal.test"), ("tok-b", "b@work.test")] {
        Mock::given(method("GET"))
            .and(path("/gmail/v1/users/me/profile"))
            .and(header("authorization", format!("Bearer {tok}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"emailAddress": email})))
            .mount(&mock)
            .await;
    }
    let tmp = tempfile::tempdir().unwrap();
    write_account(&tmp.path().join("p"), "tok-a");
    write_account(&tmp.path().join("w"), "tok-b");
    let cfg = tmp.path().join("accounts.json");
    std::fs::write(
        &cfg,
        json!({"accounts":{"personal":{"dir":tmp.path().join("p")},"work":{"dir":tmp.path().join("w")}}}).to_string(),
    )
    .unwrap();

    let uri = mock.uri();
    let bin = env!("CARGO_BIN_EXE_gmail-mcp");
    let cfg_s = cfg.display().to_string();
    let out = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(bin)
            .args(["--config", &cfg_s])
            .env("GMAIL_MCP_API_BASE", format!("{uri}/gmail/v1/users/me"))
            .env("GMAIL_MCP_TOKEN_URL", format!("{uri}/token"))
            .env("HOME", "/nonexistent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let reqs = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_accounts","arguments":{}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_emails","arguments":{"query":"x"}}}),
            json!({"jsonrpc":"2.0","id":5,"method":"bogus"}),
        ];
        for r in &reqs {
            writeln!(stdin, "{r}").unwrap();
        }
        drop(stdin); // EOF -> server finishes in-flight work and exits
        let lines: Vec<Value> = BufReader::new(child.stdout.take().unwrap())
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect();
        assert!(child.wait().unwrap().success());
        lines
    })
    .await
    .unwrap();

    let by_id = |id: i64| {
        out.iter()
            .find(|v| v["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("no response {id}: {out:?}"))
    };
    assert_eq!(out.len(), 5, "notification gets no response");
    let init = by_id(1);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "gmail");

    let tools = by_id(2)["result"]["tools"].as_array().cloned().unwrap();
    assert_eq!(tools[0]["name"], "list_accounts");
    assert_eq!(tools.len(), 29, "28 modify+settings tools + list_accounts");

    let accts: Value =
        serde_json::from_str(by_id(3)["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(accts["accounts"][0]["email"], "a@personal.test");
    assert_eq!(accts["accounts"][1]["email"], "b@work.test");

    let missing = by_id(4);
    assert_eq!(missing["result"]["isError"], true);
    assert_eq!(by_id(5)["error"]["code"], -32601);
}
