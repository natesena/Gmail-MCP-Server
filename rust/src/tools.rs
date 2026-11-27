//! Tool registry. The 30 Gmail tool definitions (names, descriptions, JSON
//! schemas, annotations, scopes) live in `tools.json`, carried over from the
//! Node server's zod schemas; `tests/parity.rs` checks them against a
//! tools/list dump of that server so the two never drift silently.
//!
//! Multi-account additions (only when 2+ accounts are configured):
//!   - every tool gets an `account` property (enum of account names), which
//!     is required when there is no default account;
//!   - a `list_accounts` tool.
//!
//! With one account the tool surface is identical to the Node server.

use crate::accounts::Accounts;
use crate::scopes::has_scope;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const LIST_ACCOUNTS: &str = "list_accounts";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub scopes: Vec<String>,
    pub annotations: Value,
    pub input_schema: Value,
}

pub static TOOLS: LazyLock<Vec<ToolDef>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("tools.json")).expect("tools.json is valid")
});

pub fn get_tool(name: &str) -> Option<&'static ToolDef> {
    TOOLS.iter().find(|t| t.name == name)
}

pub fn is_known_tool(name: &str) -> bool {
    name == LIST_ACCOUNTS || get_tool(name).is_some()
}

/// Port of `resolveToolPrefix`: `--tool-prefix=<v>` / `--tool-prefix <v>`,
/// then `$GMAIL_MCP_TOOL_PREFIX`, then empty.
pub fn resolve_tool_prefix(args: &[String], env_prefix: Option<&str>) -> String {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = arg.strip_prefix("--tool-prefix=") {
            return v.to_string();
        }
        if arg == "--tool-prefix" && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        i += 1;
    }
    env_prefix.unwrap_or("").to_string()
}

/// Map a called tool name back to a base tool name. The prefix is stripped
/// only when what's left is a known tool (guards prefix/tool-name overlap,
/// e.g. prefix "send_" + "send_email").
pub fn strip_prefix<'a>(raw: &'a str, prefix: &str) -> &'a str {
    if !prefix.is_empty() {
        if let Some(rest) = raw.strip_prefix(prefix) {
            if is_known_tool(rest) {
                return rest;
            }
        }
    }
    raw
}

/// Names of loaded accounts whose scopes grant `tool`.
pub fn accounts_for_tool(accounts: &Accounts, tool: &ToolDef) -> Vec<String> {
    accounts
        .list
        .iter()
        .filter(|a| a.load_error.is_none() && has_scope(&a.scopes, &tool.scopes))
        .map(|a| a.name.clone())
        .collect()
}

fn account_property(accounts: &Accounts, allowed: &[String]) -> Value {
    let mut desc = format!("Gmail account to use. One of: {}.", allowed.join(", "));
    if let Some(d) = &accounts.default {
        if allowed.contains(d) {
            desc.push_str(&format!(" Defaults to \"{d}\"."));
        }
    }
    json!({ "type": "string", "enum": allowed, "description": desc })
}

fn with_account(schema: &Value, accounts: &Accounts, allowed: &[String]) -> Value {
    let mut s = schema.clone();
    let obj = s.as_object_mut().expect("schema object");
    let props = obj
        .entry("properties")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("properties object");
    props.insert("account".into(), account_property(accounts, allowed));
    let default_ok = accounts
        .default
        .as_ref()
        .map(|d| allowed.contains(d))
        .unwrap_or(false);
    if !default_ok {
        let req = obj.entry("required").or_insert_with(|| json!([]));
        if let Some(arr) = req.as_array_mut() {
            arr.push(json!("account"));
        }
    }
    s
}

pub fn list_accounts_def(accounts: &Accounts) -> Value {
    json!({
        "name": LIST_ACCOUNTS,
        "description": format!(
            "Lists the Gmail accounts this server can act on ({}), with each account's email address, authorized scopes and status. Pass one of these names as `account` to any other tool.",
            accounts.names().join(", ")
        ),
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        "annotations": { "title": "List Accounts", "readOnlyHint": true },
    })
}

/// tools/list payload: tools usable by at least one account, prefixed.
pub fn list_tools(accounts: &Accounts, prefix: &str) -> Vec<Value> {
    let multi = accounts.is_multi();
    let mut out = Vec::new();
    if multi {
        let mut t = list_accounts_def(accounts);
        t["name"] = json!(format!("{prefix}{LIST_ACCOUNTS}"));
        out.push(t);
    }
    for tool in TOOLS.iter() {
        let allowed = accounts_for_tool(accounts, tool);
        if allowed.is_empty() {
            continue;
        }
        let (description, schema) = if multi {
            let mut d = tool.description.clone();
            let loaded = accounts
                .list
                .iter()
                .filter(|a| a.load_error.is_none())
                .count();
            if allowed.len() < loaded {
                d.push_str(&format!(
                    " (Available for accounts: {}.)",
                    allowed.join(", ")
                ));
            }
            (d, with_account(&tool.input_schema, accounts, &allowed))
        } else {
            (tool.description.clone(), tool.input_schema.clone())
        };
        out.push(json!({
            "name": format!("{prefix}{}", tool.name),
            "description": description,
            "inputSchema": schema,
            "annotations": tool.annotations,
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    // Port of tool-prefix.test.ts
    #[test]
    fn prefix_resolution_precedence() {
        assert_eq!(
            resolve_tool_prefix(&s(&["--tool-prefix=work_"]), None),
            "work_"
        );
        assert_eq!(
            resolve_tool_prefix(&s(&["--tool-prefix", "p_"]), Some("env_")),
            "p_"
        );
        assert_eq!(resolve_tool_prefix(&s(&[]), Some("env_")), "env_");
        assert_eq!(resolve_tool_prefix(&s(&[]), None), "");
        assert_eq!(resolve_tool_prefix(&s(&["--tool-prefix"]), None), "");
        assert_eq!(
            resolve_tool_prefix(&s(&["--tool-prefix="]), Some("env_")),
            ""
        );
    }

    #[test]
    fn strip_prefix_only_when_result_is_a_tool() {
        assert_eq!(strip_prefix("work_search_emails", "work_"), "search_emails");
        // "send_" + "send_email" -> "email" is not a tool, keep raw name.
        assert_eq!(strip_prefix("send_email", "send_"), "send_email");
        assert_eq!(strip_prefix("search_emails", ""), "search_emails");
        assert_eq!(strip_prefix("p_list_accounts", "p_"), "list_accounts");
    }

    #[test]
    fn registry_has_thirty_tools_with_scopes() {
        assert_eq!(TOOLS.len(), 30);
        assert!(TOOLS.iter().all(|t| !t.scopes.is_empty()));
        assert_eq!(get_tool("delete_email").unwrap().scopes, vec!["gmail.full"]);
        assert_eq!(
            get_tool("list_filters").unwrap().scopes,
            vec!["gmail.settings.basic"]
        );
    }
}
