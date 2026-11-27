//! MCP over Streamable HTTP (single JSON response per POST; no SSE needed
//! because the server never streams or sends server-initiated messages).
//!
//! Caller auth, for a server behind `tailscale serve`:
//!   - `Tailscale-User-Login` must be in the allowlist. `tailscale serve`
//!     sets this header for tailnet users and strips any client-supplied
//!     copy, which is only trustworthy if nothing else can reach the server:
//!     bind to 127.0.0.1 inside the Tailscale sidecar's network namespace.
//!   - or `Authorization: Bearer <token>` from the token list (for tagged
//!     devices / automation, which get no user identity).
//!
//! With neither configured the server refuses to start unless
//! `--insecure-no-auth` is given.

use crate::handlers::Server;
use crate::mcp;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use std::sync::Arc;

pub const LOGIN_HEADER: &str = "tailscale-user-login";

#[derive(Debug, Clone, Default)]
pub struct HttpAuth {
    pub allowed_logins: Vec<String>,
    pub bearer_tokens: Vec<String>,
    pub insecure_no_auth: bool,
}

impl HttpAuth {
    pub fn is_configured(&self) -> bool {
        !self.allowed_logins.is_empty() || !self.bearer_tokens.is_empty() || self.insecure_no_auth
    }

    /// Who is calling, or None if not allowed.
    pub fn authorize(&self, headers: &HeaderMap) -> Option<String> {
        if let Some(login) = headers.get(LOGIN_HEADER).and_then(|v| v.to_str().ok()) {
            if self
                .allowed_logins
                .iter()
                .any(|a| a.eq_ignore_ascii_case(login.trim()))
            {
                return Some(login.trim().to_string());
            }
        }
        if let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            if self
                .bearer_tokens
                .iter()
                .any(|t| constant_eq(t.as_bytes(), token.trim().as_bytes()))
            {
                return Some("bearer-token".into());
            }
        }
        self.insecure_no_auth.then(|| "anonymous".into())
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Reject browser cross-origin requests (DNS-rebinding guard from the MCP
/// spec). CLI harnesses send no Origin header.
fn origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    url::Url::parse(origin)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .is_some_and(|o| o.eq_ignore_ascii_case(host) || host.split(':').next() == Some(o.as_str()))
}

#[derive(Clone)]
struct AppState {
    server: Arc<Server>,
    auth: Arc<HttpAuth>,
}

fn json_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        json!({"error": msg}).to_string(),
    )
        .into_response()
}

async fn post_mcp(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !origin_ok(&headers) {
        return json_error(StatusCode::FORBIDDEN, "cross-origin request refused");
    }
    let Some(caller) = st.auth.authorize(&headers) else {
        return json_error(StatusCode::FORBIDDEN, "caller is not allowed");
    };
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let e =
                json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}});
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                e.to_string(),
            )
                .into_response();
        }
    };
    let messages = match msg {
        Value::Array(a) => a,
        one => vec![one],
    };
    let mut responses = Vec::new();
    for m in messages {
        if m["method"] == "tools/call" {
            eprintln!(
                "gmail-mcp: caller={caller} tool={} account={}",
                m["params"]["name"].as_str().unwrap_or("?"),
                m["params"]["arguments"]["account"]
                    .as_str()
                    .unwrap_or("(default)")
            );
        }
        if let Some(r) = mcp::handle(&st.server, m).await {
            responses.push(r);
        }
    }
    let body = match responses.len() {
        0 => return StatusCode::ACCEPTED.into_response(),
        1 => responses.pop().unwrap_or_default(),
        _ => Value::Array(responses),
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        "",
    )
        .into_response()
}

pub fn router(server: Arc<Server>, auth: HttpAuth) -> Router {
    let state = AppState {
        server,
        auth: Arc::new(auth),
    };
    Router::new()
        .route(
            "/mcp",
            get(method_not_allowed)
                .post(post_mcp)
                .delete(method_not_allowed),
        )
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

pub async fn serve(server: Arc<Server>, auth: HttpAuth, addr: &str) -> anyhow::Result<()> {
    if !auth.is_configured() {
        anyhow::bail!("HTTP mode needs --allow-login (Tailscale logins) and/or bearer tokens, or --insecure-no-auth");
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!(
        "gmail-mcp: listening on http://{}/mcp",
        listener.local_addr()?
    );
    axum::serve(listener, router(server, auth)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn login_allowlist_and_bearer() {
        let a = HttpAuth {
            allowed_logins: vec!["me@example.com".into()],
            bearer_tokens: vec!["tok123".into()],
            insecure_no_auth: false,
        };
        assert_eq!(
            a.authorize(&h(&[(LOGIN_HEADER, "ME@example.com")]))
                .as_deref(),
            Some("ME@example.com")
        );
        assert_eq!(
            a.authorize(&h(&[(LOGIN_HEADER, "other@example.com")])),
            None
        );
        assert_eq!(a.authorize(&h(&[])), None);
        assert!(a
            .authorize(&h(&[("authorization", "Bearer tok123")]))
            .is_some());
        assert!(a
            .authorize(&h(&[("authorization", "Bearer tok124")]))
            .is_none());
        assert!(!HttpAuth::default().is_configured());
    }

    #[test]
    fn origin_guard() {
        assert!(origin_ok(&h(&[])));
        assert!(origin_ok(&h(&[
            ("origin", "https://gmail.x.ts.net"),
            ("host", "gmail.x.ts.net")
        ])));
        assert!(!origin_ok(&h(&[
            ("origin", "https://evil.com"),
            ("host", "gmail.x.ts.net")
        ])));
        assert!(!origin_ok(&h(&[
            ("origin", "null"),
            ("host", "gmail.x.ts.net")
        ])));
    }
}
