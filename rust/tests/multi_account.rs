//! Verification 3: multi-account routing against a mock Gmail API.
//! Two accounts with different tokens share one server; every request must
//! carry the right account's bearer token, and refreshes must persist to the
//! right account's credentials file only.

use gmail_mcp::accounts::{Accounts, Endpoints};
use gmail_mcp::config::{AccountConfig, Config};
use gmail_mcp::handlers::Server;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FAR_FUTURE: i64 = 4_102_444_800_000; // 2100-01-01

fn write_account(dir: &Path, token: &str, expiry: i64, scopes: &[&str]) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("gcp-oauth.keys.json"),
        r#"{"installed":{"client_id":"id","client_secret":"secret"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("credentials.json"),
        json!({"tokens":{"access_token":token,"refresh_token":format!("refresh-{token}"),"expiry_date":expiry},"scopes":scopes}).to_string(),
    )
    .unwrap();
}

struct Fixture {
    _tmp: tempfile::TempDir,
    mock: MockServer,
    server: Server,
    personal: PathBuf,
    work: PathBuf,
}

async fn fixture(work_expiry: i64, default: Option<&str>) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let personal = tmp.path().join("personal");
    let work = tmp.path().join("work");
    write_account(&personal, "tok-personal", FAR_FUTURE, &["gmail.readonly"]);
    write_account(
        &work,
        "tok-work",
        work_expiry,
        &["gmail.modify", "gmail.settings.basic"],
    );
    let mock = MockServer::start().await;
    let cfg = Config {
        accounts: [("personal", &personal), ("work", &work)]
            .iter()
            .map(|(n, d)| AccountConfig {
                name: n.to_string(),
                oauth_path: d.join("gcp-oauth.keys.json"),
                credentials_path: d.join("credentials.json"),
            })
            .collect(),
        default_account: default.map(String::from),
        source: "test".into(),
    };
    let endpoints = Endpoints {
        api_base: format!("{}/gmail/v1/users/me", mock.uri()),
        token_url: format!("{}/token", mock.uri()),
    };
    let server = Server {
        accounts: Accounts::load(&cfg, &endpoints),
        prefix: String::new(),
    };
    Fixture {
        _tmp: tmp,
        mock,
        server,
        personal,
        work,
    }
}

fn text(v: &Value) -> String {
    v["content"][0]["text"].as_str().unwrap_or("").to_string()
}

async fn mock_profile(m: &MockServer, token: &str, email: &str) {
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/profile"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"emailAddress": email})))
        .mount(m)
        .await;
}

async fn mock_search(m: &MockServer, token: &str, id: &str, subject: &str) {
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages":[{"id":id}]})))
        .mount(m)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/gmail/v1/users/me/messages/{id}")))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .and(query_param("format", "metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": id,
            "payload": {"headers": [
                {"name":"Subject","value":subject},
                {"name":"From","value":"x@y.com"},
                {"name":"Date","value":"Mon, 1 Jan 2026 00:00:00 +0000"}
            ]}
        })))
        .mount(m)
        .await;
}

#[tokio::test]
async fn routes_each_call_with_its_accounts_token() {
    let f = fixture(FAR_FUTURE, None).await;
    mock_search(&f.mock, "tok-personal", "p1", "personal subject").await;
    mock_search(&f.mock, "tok-work", "w1", "work subject").await;

    let p = f
        .server
        .call_tool("search_emails", json!({"query":"x","account":"personal"}))
        .await;
    let w = f
        .server
        .call_tool("search_emails", json!({"query":"x","account":"work"}))
        .await;
    assert!(
        text(&p).contains("ID: p1") && text(&p).contains("personal subject"),
        "{p}"
    );
    assert!(
        text(&w).contains("ID: w1") && text(&w).contains("work subject"),
        "{w}"
    );
    // concurrent calls on both accounts
    let (a, b) = tokio::join!(
        f.server
            .call_tool("search_emails", json!({"query":"x","account":"work"})),
        f.server
            .call_tool("search_emails", json!({"query":"x","account":"personal"})),
    );
    assert!(text(&a).contains("w1") && text(&b).contains("p1"));
}

#[tokio::test]
async fn missing_and_unknown_account_errors() {
    let f = fixture(FAR_FUTURE, None).await;
    let r = f
        .server
        .call_tool("search_emails", json!({"query":"x"}))
        .await;
    assert_eq!(r["isError"], true);
    assert!(
        text(&r).contains("pass \"account\" as one of: personal, work"),
        "{r}"
    );
    let r = f
        .server
        .call_tool("search_emails", json!({"query":"x","account":"nope"}))
        .await;
    assert!(text(&r).contains("Unknown account \"nope\""), "{r}");
}

#[tokio::test]
async fn default_account_is_used_when_omitted() {
    let f = fixture(FAR_FUTURE, Some("work")).await;
    mock_search(&f.mock, "tok-work", "w1", "work subject").await;
    let r = f
        .server
        .call_tool("search_emails", json!({"query":"x"}))
        .await;
    assert!(text(&r).contains("ID: w1"), "{r}");
}

#[tokio::test]
async fn scopes_are_enforced_per_account() {
    let f = fixture(FAR_FUTURE, None).await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/m1/modify"))
        .and(header("authorization", "Bearer tok-work"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&f.mock)
        .await;
    // personal is read-only: refused before any request is made
    let r = f
        .server
        .call_tool(
            "modify_email",
            json!({"messageId":"m1","addLabelIds":["X"],"account":"personal"}),
        )
        .await;
    assert!(
        text(&r).contains("not available for account \"personal\""),
        "{r}"
    );
    let r = f
        .server
        .call_tool(
            "modify_email",
            json!({"messageId":"m1","addLabelIds":["X"],"account":"work"}),
        )
        .await;
    assert_eq!(text(&r), "Email m1 labels updated successfully");
}

#[tokio::test]
async fn expired_token_refreshes_and_persists_only_to_that_account() {
    let f = fixture(1_000, None).await; // work token long expired
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=refresh-tok-work"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok-work-2","expires_in":3600})),
        )
        .expect(1)
        .mount(&f.mock)
        .await;
    mock_search(&f.mock, "tok-work-2", "w2", "after refresh").await;
    mock_search(&f.mock, "tok-personal", "p1", "personal").await;

    let before_personal = std::fs::read_to_string(f.personal.join("credentials.json")).unwrap();
    let r = f
        .server
        .call_tool("search_emails", json!({"query":"x","account":"work"}))
        .await;
    assert!(text(&r).contains("ID: w2"), "{r}");
    let r = f
        .server
        .call_tool("search_emails", json!({"query":"x","account":"personal"}))
        .await;
    assert!(text(&r).contains("ID: p1"), "{r}");

    let work: Value =
        serde_json::from_str(&std::fs::read_to_string(f.work.join("credentials.json")).unwrap())
            .unwrap();
    assert_eq!(work["tokens"]["access_token"], "tok-work-2");
    assert_eq!(
        work["tokens"]["refresh_token"], "refresh-tok-work",
        "refresh token kept"
    );
    assert!(work["tokens"]["expiry_date"].as_i64().unwrap() > 1_000);
    assert_eq!(
        work["scopes"],
        json!(["gmail.modify", "gmail.settings.basic"])
    );
    let after_personal = std::fs::read_to_string(f.personal.join("credentials.json")).unwrap();
    assert_eq!(
        before_personal, after_personal,
        "other account's file untouched"
    );
}

#[tokio::test]
async fn unauthorized_response_forces_one_refresh() {
    let f = fixture(FAR_FUTURE, None).await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(header("authorization", "Bearer tok-work"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"error":{"code":401,"message":"Invalid Credentials"}})),
        )
        .mount(&f.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token":"tok-work-new","expires_in":3600})),
        )
        .expect(1)
        .mount(&f.mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .and(header("authorization", "Bearer tok-work-new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"labels":[
            {"id":"INBOX","name":"INBOX","type":"system"},
            {"id":"L1","name":"Clients","type":"user"}
        ]})))
        .mount(&f.mock)
        .await;
    let r = f
        .server
        .call_tool("list_email_labels", json!({"account":"work"}))
        .await;
    assert_eq!(
        text(&r),
        "Found 2 labels (1 system, 1 user):\n\nSystem Labels:\nID: INBOX\nName: INBOX\n\nUser Labels:\nID: L1\nName: Clients\n"
    );
}

#[tokio::test]
async fn list_accounts_reports_emails_scopes_and_default() {
    let f = fixture(FAR_FUTURE, Some("personal")).await;
    mock_profile(&f.mock, "tok-personal", "me@personal.test").await;
    mock_profile(&f.mock, "tok-work", "me@work.test").await;
    let r = f.server.call_tool("list_accounts", json!({})).await;
    let v: Value = serde_json::from_str(&text(&r)).unwrap();
    assert_eq!(v["defaultAccount"], "personal");
    assert_eq!(v["accounts"][0]["email"], "me@personal.test");
    assert_eq!(v["accounts"][0]["default"], true);
    assert_eq!(v["accounts"][1]["email"], "me@work.test");
    assert_eq!(
        v["accounts"][1]["scopes"],
        json!(["gmail.modify", "gmail.settings.basic"])
    );
}

#[tokio::test]
async fn reply_all_uses_the_target_accounts_identity() {
    let f = fixture(FAR_FUTURE, None).await;
    mock_profile(&f.mock, "tok-work", "me@work.test").await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/orig"))
        .and(header("authorization", "Bearer tok-work"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"orig","threadId":"t9",
            "payload":{"headers":[
                {"name":"From","value":"Boss <boss@work.test>"},
                {"name":"To","value":"me@work.test, peer@work.test"},
                {"name":"Cc","value":"cc@work.test"},
                {"name":"Subject","value":"Plan"},
                {"name":"Message-ID","value":"<orig@x>"},
                {"name":"References","value":"<root@x>"}
            ]}
        })))
        .mount(&f.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/send"))
        .and(header("authorization", "Bearer tok-work"))
        .and(body_string_contains("\"threadId\":\"t9\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"sent1"})))
        .expect(1)
        .mount(&f.mock)
        .await;
    let r = f
        .server
        .call_tool(
            "reply_all",
            json!({"messageId":"orig","body":"ok","account":"work"}),
        )
        .await;
    assert_eq!(
        text(&r),
        "Reply-all sent successfully!\nTo: boss@work.test\nCC: peer@work.test, cc@work.test\nSubject: Re: Plan\nThread ID: t9"
    );
    // Inspect the raw message that was sent
    let reqs = f.mock.received_requests().await.unwrap();
    let send = reqs
        .iter()
        .find(|r| r.url.path().ends_with("/messages/send"))
        .unwrap();
    let body: Value = serde_json::from_slice(&send.body).unwrap();
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body["raw"].as_str().unwrap())
        .unwrap();
    let raw = String::from_utf8(raw).unwrap();
    assert!(raw.contains("In-Reply-To: <orig@x>"));
    assert!(raw.contains("References: <root@x> <orig@x>"));
    assert!(!raw.contains("Cc: me@work.test"));
}

#[tokio::test]
async fn draft_lifecycle_and_thread_header_resolution() {
    let f = fixture(FAR_FUTURE, Some("work")).await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/threads/t1"))
        .and(query_param("format", "metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messages":[
            {"internalDate":"300","payload":{"headers":[{"name":"Message-ID","value":"<new@x>"}]}},
            {"internalDate":"100","payload":{"headers":[{"name":"Message-ID","value":"<old@x>"}]}}
        ]})))
        .mount(&f.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/drafts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"d1"})))
        .mount(&f.mock)
        .await;
    Mock::given(method("PUT"))
        .and(path("/gmail/v1/users/me/drafts/d1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"d1"})))
        .mount(&f.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/drafts/send"))
        .and(body_string_contains("\"id\":\"d1\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"m77"})))
        .mount(&f.mock)
        .await;
    let r = f
        .server
        .call_tool(
            "draft_email",
            json!({"to":["a@b.com"],"subject":"s","body":"b","threadId":"t1"}),
        )
        .await;
    assert_eq!(text(&r), "Email draft created successfully with ID: d1");
    let reqs = f.mock.received_requests().await.unwrap();
    let draft = reqs
        .iter()
        .find(|r| r.url.path().ends_with("/drafts"))
        .unwrap();
    let body: Value = serde_json::from_slice(&draft.body).unwrap();
    assert_eq!(body["message"]["threadId"], "t1");
    use base64::Engine;
    let raw = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body["message"]["raw"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(raw.contains("In-Reply-To: <new@x>"), "{raw}");
    assert!(raw.contains("References: <old@x> <new@x>"), "{raw}");

    let r = f
        .server
        .call_tool(
            "update_draft",
            json!({"draftId":"d1","to":["a@b.com"],"subject":"s2","body":"b2"}),
        )
        .await;
    assert_eq!(
        text(&r),
        "Draft d1 updated successfully (draft ID unchanged, content replaced)."
    );
    let r = f
        .server
        .call_tool("send_draft", json!({"draftId":"d1"}))
        .await;
    assert_eq!(
        text(&r),
        "Draft d1 sent successfully as message ID: m77. The draft has been removed from Drafts."
    );
}

#[tokio::test]
async fn api_404_is_mapped_like_node() {
    let f = fixture(FAR_FUTURE, Some("work")).await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/settings/filters/f404"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error":{"code":404,"message":"Not Found"}})),
        )
        .mount(&f.mock)
        .await;
    let r = f
        .server
        .call_tool("get_filter", json!({"filterId":"f404"}))
        .await;
    assert_eq!(text(&r), "Error: Filter with ID \"f404\" not found.");
    assert_eq!(r["isError"], true);
}

#[tokio::test]
async fn batch_retries_items_individually() {
    let f = fixture(FAR_FUTURE, Some("work")).await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/bad/modify"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"error":{"code":400,"message":"Invalid id"}})),
        )
        .mount(&f.mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/messages/good/modify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&f.mock)
        .await;
    let r = f
        .server
        .call_tool(
            "batch_modify_emails",
            json!({"messageIds":["good","bad"],"addLabelIds":["X"]}),
        )
        .await;
    assert_eq!(
        text(&r),
        "Batch label modification complete.\nSuccessfully processed: 1 messages\nFailed to process: 1 messages\n\nFailed message IDs:\n- bad... (Invalid id)"
    );
}
