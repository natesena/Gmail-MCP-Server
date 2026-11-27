//! MCP over stdio: newline-delimited JSON-RPC 2.0. Requests are handled
//! concurrently; responses are written by a single writer task.

use crate::handlers::Server;
use crate::tools;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handle one JSON-RPC message; `None` for notifications.
pub async fn handle(server: &Server, msg: Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let id = match id {
        Some(id) if !id.is_null() => id,
        _ => return None, // notification (initialized, cancelled, ...)
    };
    let resp = match method {
        "initialize" => {
            let requested = params["protocolVersion"].as_str().unwrap_or("");
            let version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
                requested
            } else {
                SUPPORTED_PROTOCOL_VERSIONS[0]
            };
            ok(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "gmail", "version": env!("CARGO_PKG_VERSION") },
                }),
            )
        }
        "ping" => ok(id, json!({})),
        "tools/list" => ok(
            id,
            json!({ "tools": tools::list_tools(&server.accounts, &server.prefix) }),
        ),
        "tools/call" => {
            let Some(name) = params["name"].as_str() else {
                return Some(err(id, -32602, "tools/call requires params.name"));
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            ok(id, server.call_tool(name, args).await)
        }
        _ => err(id, -32601, &format!("Method not found: {method}")),
    };
    Some(resp)
}

pub async fn serve<R, W>(server: Arc<Server>, input: R, mut output: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        while let Some(v) = rx.recv().await {
            let mut line = serde_json::to_string(&v).unwrap_or_default();
            line.push('\n');
            if output.write_all(line.as_bytes()).await.is_err() || output.flush().await.is_err() {
                break;
            }
        }
    });

    let mut lines = BufReader::new(input).lines();
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                let _ = tx.send(err(Value::Null, -32700, "Parse error"));
                continue;
            }
        };
        let server = server.clone();
        let tx = tx.clone();
        tasks.spawn(async move {
            if let Some(resp) = handle(&server, msg).await {
                let _ = tx.send(resp);
            }
        });
    }
    // stdin closed: finish in-flight requests, then flush.
    while tasks.join_next().await.is_some() {}
    drop(tx);
    let _ = writer.await;
    Ok(())
}
