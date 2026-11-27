//! GMCP-2 verification against a mock Gmail API: the encrypted store, the
//! accounts CLI, Streamable HTTP with Tailscale-login auth, account "all",
//! one refresh shared by concurrent callers, and store reloads.

use gmail_mcp::accounts::{AccountsHandle, Endpoints};
use gmail_mcp::admin;
use gmail_mcp::handlers::Server;
use gmail_mcp::http::{self, HttpAuth};
use gmail_mcp::store::{Store, StoredAccount};
use serde_json::{json, Value};
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FAR: i64 = 4_102_444_800_000;
const ME: &str = "owner@example.com";

fn endpoints(m: &MockServer) -> Endpoints {
    Endpoints {
        api_base: format!("{}/gmail/v1/users/me", m.uri()),
        token_url: format!("{}/token", m.uri()),
    }
}

fn write_dir(dir: &std::path::Path, token: &str, expiry: i64) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("gcp-oauth.keys.json"),
        r#"{"installed":{"client_id":"cid","client_secret":"GOCSPX-shh"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("credentials.json"),
        json!({"tokens":{"access_token":token,"refresh_token":format!("1//refresh-{token}"),"expiry_date":expiry},
               "scopes":["gmail.modify","gmail.settings.basic"]}).to_string(),
    )
    .unwrap();
}

async fn profile(m: &MockServer, token: &str, email: &str) {
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"emailAddress": email})))
        .mount(m)
        .await;
}

async fn search(m: &MockServer, token: &str, id: &str) {
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages":[{"id":id}]})))
        .mount(m)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/gmail/v1/users/me/messages/{id}")))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":id,"payload":{"headers":[{"name":"Subject","value":format!("subj-{id}")}]}})))
        .mount(m)
        .await;
}

struct Env {
    tmp: tempfile::TempDir,
    mock: MockServer,
    store: Store,
}

/// A store with personal + work imported through the real `accounts import`.
async fn env_with_two(work_expiry: i64) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let mock = MockServer::start().await;
    write_dir(&tmp.path().join("p"), "tok-p", FAR);
    write_dir(&tmp.path().join("w"), "tok-w", work_expiry);
    profile(&mock, "tok-p", "me@personal.test").await;
    profile(&mock, "tok-w", "me@work.test").await;
    let store = Store::new(tmp.path().join("data/store.json"), [9u8; 32]);
    let ep = endpoints(&mock);
    // work's token may be expired: email lookup will refresh, so allow it
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=1%2F%2Frefresh-tok-w"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok-w","expires_in":3600})),
        )
        .mount(&mock)
        .await;
    admin::import(&store, "personal", &tmp.path().join("p"), &ep)
        .await
        .unwrap();
    admin::import(&store, "work", &tmp.path().join("w"), &ep)
        .await
        .unwrap();
    Env { tmp, mock, store }
}

fn text(v: &Value) -> String {
    v["content"][0]["text"].as_str().unwrap_or("").to_string()
}

#[tokio::test]
async fn import_stores_client_once_and_no_plaintext_secrets() {
    let e = env_with_two(FAR).await;
    let d = e.store.load().unwrap();
    assert_eq!(d.client.as_ref().unwrap().client_id, "cid");
    assert!(
        d.accounts.iter().all(|a| a.client.is_none()),
        "shared client stored once"
    );
    assert_eq!(d.get("personal").unwrap().email, "me@personal.test");
    assert_eq!(d.get("work").unwrap().email, "me@work.test");
    // nothing secret in any file under the store directory
    for entry in std::fs::read_dir(e.tmp.path().join("data")).unwrap() {
        let raw = std::fs::read(entry.unwrap().path()).unwrap();
        let raw = String::from_utf8_lossy(&raw);
        for s in ["1//refresh", "GOCSPX", "tok-p", "me@personal.test"] {
            assert!(!raw.contains(s), "{s} found in store dir");
        }
    }
    let listing = admin::list_text(&e.store).unwrap();
    assert!(
        listing.contains("personal  me@personal.test") && listing.contains("work  me@work.test")
    );
    admin::set_default(&e.store, "work").unwrap();
    assert!(admin::list_text(&e.store).unwrap().contains("* work"));
    assert!(admin::set_default(&e.store, "nope").is_err());
    admin::remove(&e.store, "personal").unwrap();
    assert_eq!(e.store.load().unwrap().accounts.len(), 1);
}

#[tokio::test]
async fn add_with_pasted_redirect_url() {
    let e = env_with_two(FAR).await;
    let pending =
        admin::begin_add(&e.store, &["gmail.readonly".into()], admin::PASTE_REDIRECT).unwrap();
    assert!(pending.url.contains("state=") && pending.url.contains("access_type=offline"));
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=4%2Fthe-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token":"tok-new","refresh_token":"1//new","expires_in":3600}),
        ))
        .expect(1)
        .mount(&e.mock)
        .await;
    profile(&e.mock, "tok-new", "third@example.test").await;
    let pasted = format!(
        "{}?state={}&code=4/the-code&scope=x",
        admin::PASTE_REDIRECT,
        pending.state
    );
    let a = admin::finish_add(&e.store, "third", &pending, &pasted, &endpoints(&e.mock))
        .await
        .unwrap();
    assert_eq!(a.email, "third@example.test");
    assert_eq!(a.scopes, vec!["gmail.readonly"]);
    assert_eq!(e.store.load().unwrap().accounts.len(), 3);
    // a URL from another attempt is refused before any network call
    let bad = format!("{}?state=other&code=x", admin::PASTE_REDIRECT);
    assert!(
        admin::finish_add(&e.store, "x", &pending, &bad, &endpoints(&e.mock))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn account_all_merges_and_tolerates_a_failing_account() {
    let e = env_with_two(FAR).await;
    search(&e.mock, "tok-p", "p1").await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(header("authorization", "Bearer tok-w"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(json!({"error":{"code":500,"message":"Backend Error"}})),
        )
        .mount(&e.mock)
        .await;
    let server = Server {
        accounts: AccountsHandle::from_store(e.store.clone(), endpoints(&e.mock)).unwrap(),
        prefix: String::new(),
    };
    let r = server
        .call_tool("search_emails", json!({"query":"x","account":"all"}))
        .await;
    assert!(r.get("isError").is_none(), "{r}");
    let v: Value = serde_json::from_str(&text(&r)).unwrap();
    assert_eq!(v["accounts"][0]["account"], "personal");
    assert_eq!(v["accounts"][0]["email"], "me@personal.test");
    assert!(v["accounts"][0]["result"]
        .as_str()
        .unwrap()
        .contains("ID: p1"));
    assert_eq!(v["accounts"][1]["account"], "work");
    assert!(v["accounts"][1]["error"]
        .as_str()
        .unwrap()
        .contains("Backend Error"));
    // write tools can't fan out
    let r = server
        .call_tool(
            "send_email",
            json!({"to":["a@b.com"],"subject":"s","body":"b","account":"all"}),
        )
        .await;
    assert!(text(&r).contains("only supported by"), "{r}");
    // lookup by email address works too
    let r = server
        .call_tool(
            "search_emails",
            json!({"query":"x","account":"ME@personal.test"}),
        )
        .await;
    assert!(text(&r).contains("ID: p1"), "{r}");
}

#[tokio::test]
async fn concurrent_calls_share_one_refresh() {
    let e = env_with_two(FAR).await;
    // expire work's token in the store
    e.store
        .update(|d| {
            let a = d.accounts.iter_mut().find(|a| a.alias == "work").unwrap();
            a.tokens.insert("expiry_date".into(), json!(1));
            a.tokens.insert("access_token".into(), json!("stale"));
            Ok(())
        })
        .unwrap();
    e.mock.reset().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok-w2","expires_in":3600}))
                .set_delay(std::time::Duration::from_millis(100)),
        )
        .expect(1)
        .mount(&e.mock)
        .await;
    search(&e.mock, "tok-w2", "w9").await;
    let server = Arc::new(Server {
        accounts: AccountsHandle::from_store(e.store.clone(), endpoints(&e.mock)).unwrap(),
        prefix: String::new(),
    });
    let calls = (0..8).map(|_| {
        let s = server.clone();
        tokio::spawn(async move {
            s.call_tool("search_emails", json!({"query":"x","account":"work"}))
                .await
        })
    });
    for r in futures::future::join_all(calls).await {
        assert!(text(&r.unwrap()).contains("ID: w9"));
    }
    // refreshed token persisted to the encrypted store, refresh token kept
    let d = e.store.load().unwrap();
    assert_eq!(d.get("work").unwrap().tokens["access_token"], "tok-w2");
    assert_eq!(
        d.get("work").unwrap().tokens["refresh_token"],
        "1//refresh-tok-w"
    );
    // wiremock verifies .expect(1) on drop
}

#[tokio::test]
async fn server_picks_up_cli_changes_without_restart() {
    let e = env_with_two(FAR).await;
    let handle = AccountsHandle::from_store(e.store.clone(), endpoints(&e.mock)).unwrap();
    assert_eq!(handle.get().names(), vec!["personal", "work"]);
    let before = handle.get().list[0].clone();
    std::thread::sleep(std::time::Duration::from_millis(20)); // distinct mtime
    e.store
        .update(|d| {
            d.upsert(StoredAccount {
                alias: "extra".into(),
                email: "x@y.z".into(),
                scopes: vec!["gmail.readonly".into()],
                ..Default::default()
            });
            d.default = Some("extra".into());
            Ok(())
        })
        .unwrap();
    let now = handle.get();
    assert_eq!(now.names(), vec!["personal", "work", "extra"]);
    assert_eq!(now.default.as_deref(), Some("extra"));
    assert!(
        Arc::ptr_eq(&before, &now.list[0]),
        "unchanged account (and its live token) reused"
    );
}

// ---------------------------------------------------------------- HTTP

async fn spawn_http(server: Server, auth: HttpAuth) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, http::router(Arc::new(server), auth))
            .await
            .unwrap()
    });
    format!("http://{addr}/mcp")
}

#[tokio::test]
async fn http_transport_auth_and_handshake() {
    let e = env_with_two(FAR).await;
    search(&e.mock, "tok-w", "w1").await;
    let server = Server {
        accounts: AccountsHandle::from_store(e.store.clone(), endpoints(&e.mock)).unwrap(),
        prefix: String::new(),
    };
    let auth = HttpAuth {
        allowed_logins: vec![ME.into()],
        bearer_tokens: vec!["robot-token".into()],
        insecure_no_auth: false,
    };
    let url = spawn_http(server, auth).await;
    let c = reqwest::Client::new();
    let post = |body: Value, login: Option<&str>| {
        let mut r = c
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(l) = login {
            r = r.header("Tailscale-User-Login", l);
        }
        r.send()
    };

    // refused: no identity, wrong login, cross-origin browser request
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}});
    assert_eq!(post(init.clone(), None).await.unwrap().status(), 403);
    assert_eq!(
        post(init.clone(), Some("someone-else@example.com"))
            .await
            .unwrap()
            .status(),
        403
    );
    let xo = c
        .post(&url)
        .header("Tailscale-User-Login", ME)
        .header("origin", "https://evil.example")
        .json(&init)
        .send()
        .await
        .unwrap();
    assert_eq!(xo.status(), 403);

    // allowed login: full handshake
    let r = post(init.clone(), Some(ME)).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "application/json");
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    let n = post(
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        Some(ME),
    )
    .await
    .unwrap();
    assert_eq!(n.status(), 202);
    let tools: Value = post(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        Some(ME),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(tools["result"]["tools"][0]["name"], "list_accounts");
    let call: Value = post(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_emails","arguments":{"query":"x","account":"work"}}}), Some(ME))
        .await.unwrap().json().await.unwrap();
    assert!(text(&call["result"]).contains("ID: w1"), "{call}");

    // bearer token for tagged devices / automation
    let b = c
        .post(&url)
        .bearer_auth("robot-token")
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(b.status(), 200);
    let b = c
        .post(&url)
        .bearer_auth("nope")
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(b.status(), 403);

    // GET has no SSE stream
    assert_eq!(
        c.get(&url)
            .header("Tailscale-User-Login", ME)
            .send()
            .await
            .unwrap()
            .status(),
        405
    );
    // health check needs no identity
    let health = url.replace("/mcp", "/healthz");
    assert_eq!(
        c.get(&health).send().await.unwrap().text().await.unwrap(),
        "ok"
    );
}

#[tokio::test]
async fn http_refuses_to_start_without_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::new(tmp.path().join("s.json"), [1u8; 32]);
    let server = Arc::new(Server {
        accounts: AccountsHandle::from_store(
            store,
            Endpoints {
                api_base: "http://x".into(),
                token_url: "http://x".into(),
            },
        )
        .unwrap(),
        prefix: String::new(),
    });
    let err = http::serve(server, HttpAuth::default(), "127.0.0.1:0")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("--allow-login"));
}
