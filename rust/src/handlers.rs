//! Tool implementations (port of the `CallToolRequestSchema` handler in
//! `index.ts`). Output text matches the Node server so existing prompts and
//! habits keep working; every handler runs against one resolved account.

use crate::accounts::{Account, Accounts, AccountsHandle, ALL_ACCOUNTS};
use crate::gmail::{api_status, q, seg, Gmail, Query};
use crate::message::{self as msg, EmailContent};
use crate::mime::{self, EmailArgs};
use crate::scopes::has_scope;
use crate::tools::{self, LIST_ACCOUNTS};
use anyhow::{anyhow, bail, Context, Result};
use futures::future::join_all;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub struct Server {
    pub accounts: AccountsHandle,
    pub prefix: String,
}

pub fn text_result(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }] })
}

fn error_result(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": true })
}

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T> {
    let v = if args.is_null() {
        json!({})
    } else {
        args.clone()
    };
    serde_json::from_value(v).map_err(|e| anyhow!("Invalid arguments: {e}"))
}

fn check_enum(field: &str, value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        bail!(
            "Invalid {field} {value:?}: expected one of {}",
            allowed.join(", ")
        )
    }
}

impl Server {
    /// tools/call entry point. Never fails: errors become tool results.
    pub async fn call_tool(&self, raw_name: &str, args: Value) -> Value {
        let accounts = self.accounts.get();
        let name = tools::strip_prefix(raw_name, &self.prefix);
        if name == LIST_ACCOUNTS {
            return match list_accounts(&accounts).await {
                Ok(v) => v,
                Err(e) => error_result(format!("Error: {e:#}")),
            };
        }
        let not_available = |extra: &str| {
            error_result(format!(
                "Error: Tool \"{name}\" is not available{extra}. You may need to re-authenticate with additional scopes."
            ))
        };
        let Some(def) = tools::get_tool(name) else {
            return not_available("");
        };
        let requested = args
            .get("account")
            .and_then(Value::as_str)
            .map(String::from);
        let mut args = args;
        if let Some(obj) = args.as_object_mut() {
            obj.remove("account");
        }
        if requested.as_deref() == Some(ALL_ACCOUNTS) {
            return all_accounts(&accounts, def, name, &args).await;
        }
        let account = match accounts.resolve(requested.as_deref()) {
            Ok(a) => a,
            Err(e) => return error_result(format!("Error: {e:#}")),
        };
        if let Some(err) = &account.load_error {
            return error_result(format!(
                "Error: Account \"{}\" is unavailable: {err}",
                account.name
            ));
        }
        // Guards direct calls that bypass tools/list; scopes are per account.
        if !has_scope(&account.scopes, &def.scopes) {
            let extra = if accounts.is_multi() {
                format!(" for account \"{}\"", account.name)
            } else {
                String::new()
            };
            return not_available(&extra);
        }
        match dispatch(name, &account, &args).await {
            Ok(v) => v,
            Err(e) => error_result(format!("Error: {e:#}")),
        }
    }
}

/// `account: "all"`: run a read tool on every usable account concurrently and
/// return one JSON document with a result (or error) per account.
async fn all_accounts(
    accounts: &Accounts,
    def: &tools::ToolDef,
    name: &str,
    args: &Value,
) -> Value {
    if !tools::ALL_ACCOUNT_TOOLS.contains(&name) {
        return error_result(format!(
            "Error: account \"all\" is only supported by: {}",
            tools::ALL_ACCOUNT_TOOLS.join(", ")
        ));
    }
    let targets: Vec<Arc<Account>> = accounts
        .list
        .iter()
        .filter(|a| a.load_error.is_none() && has_scope(&a.scopes, &def.scopes))
        .cloned()
        .collect();
    if targets.is_empty() {
        return error_result("Error: no account can run this tool");
    }
    let results = join_all(targets.iter().map(|a| async move {
        let mut e = Map::new();
        e.insert("account".into(), json!(a.name));
        if let Ok(email) = a.email().await {
            e.insert("email".into(), json!(email));
        }
        match dispatch(name, a, args).await {
            Ok(v) => {
                let text = v["content"][0]["text"].as_str().unwrap_or("").to_string();
                if v["isError"] == true {
                    e.insert("error".into(), json!(text));
                } else {
                    let parsed = serde_json::from_str::<Value>(&text).unwrap_or(json!(text));
                    e.insert("result".into(), parsed);
                }
            }
            Err(err) => {
                e.insert("error".into(), json!(format!("{err:#}")));
            }
        }
        Value::Object(e)
    }))
    .await;
    let any_ok = results.iter().any(|r| r.get("result").is_some());
    let body = serde_json::to_string_pretty(&json!({ "accounts": results })).unwrap_or_default();
    if any_ok {
        text_result(body)
    } else {
        error_result(body)
    }
}

async fn list_accounts(accounts: &Accounts) -> Result<Value> {
    let entries = join_all(accounts.list.iter().map(|a| async move {
        let mut e = Map::new();
        e.insert("account".into(), json!(a.name));
        e.insert(
            "default".into(),
            json!(accounts.default.as_deref() == Some(a.name.as_str())),
        );
        match &a.load_error {
            Some(err) => {
                e.insert("status".into(), json!("unavailable"));
                e.insert("error".into(), json!(err));
            }
            None => {
                match a.email().await {
                    Ok(email) => {
                        e.insert("email".into(), json!(email));
                        e.insert("status".into(), json!("ok"));
                    }
                    Err(err) => {
                        e.insert("status".into(), json!("error"));
                        e.insert("error".into(), json!(format!("{err:#}")));
                    }
                }
                e.insert("scopes".into(), json!(a.scopes));
            }
        }
        Value::Object(e)
    }))
    .await;
    Ok(text_result(serde_json::to_string_pretty(&json!({
        "accounts": entries,
        "defaultAccount": accounts.default,
    }))?))
}

// ------------------------------------------------------------------ arg types

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageIdArgs {
    message_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchArgs {
    query: String,
    max_results: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ModifyArgs {
    message_id: String,
    label_ids: Option<Vec<String>>,
    add_label_ids: Option<Vec<String>>,
    remove_label_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DraftIdArgs {
    draft_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateDraftArgs {
    draft_id: String,
    #[serde(flatten)]
    email: EmailArgs,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BatchArgs {
    message_ids: Vec<String>,
    add_label_ids: Option<Vec<String>>,
    remove_label_ids: Option<Vec<String>>,
    batch_size: Option<f64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabelArgs {
    id: Option<String>,
    name: Option<String>,
    message_list_visibility: Option<String>,
    label_list_visibility: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FilterIdArgs {
    filter_id: String,
}

#[derive(Deserialize)]
struct CreateFilterArgs {
    criteria: Map<String, Value>,
    action: Map<String, Value>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TemplateParams {
    sender_email: Option<String>,
    subject_text: Option<String>,
    search_text: Option<String>,
    list_identifier: Option<String>,
    size_in_bytes: Option<f64>,
    label_ids: Option<Vec<String>>,
    archive: Option<bool>,
    mark_as_read: Option<bool>,
    mark_important: Option<bool>,
}

#[derive(Deserialize)]
struct TemplateArgs {
    template: String,
    parameters: TemplateParams,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentArgs {
    message_id: String,
    attachment_id: String,
    filename: Option<String>,
    save_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadEmailArgs {
    message_id: String,
    save_path: String,
    format: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ThreadModifyArgs {
    thread_id: String,
    add_label_ids: Option<Vec<String>>,
    remove_label_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetThreadArgs {
    thread_id: String,
    format: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListThreadsArgs {
    query: Option<String>,
    max_results: Option<f64>,
    expand_threads: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplyAllArgs {
    message_id: String,
    body: String,
    html_body: Option<String>,
    mime_type: Option<String>,
    attachments: Option<Vec<String>>,
    inline_images: Option<Vec<mime::InlineImage>>,
}

fn parse_email_args(args: &Value) -> Result<EmailArgs> {
    let a: EmailArgs = parse(args)?;
    a.validate()?;
    Ok(a)
}

fn num(v: Option<f64>, default: u64) -> u64 {
    match v {
        // JS `x || default`: 0 / NaN fall back to the default
        Some(n) if n.is_finite() && n >= 1.0 => n as u64,
        _ => default,
    }
}

fn label_body(add: &Option<Vec<String>>, remove: &Option<Vec<String>>) -> Value {
    let mut body = Map::new();
    if let Some(a) = add {
        body.insert("addLabelIds".into(), json!(a));
    }
    if let Some(r) = remove {
        body.insert("removeLabelIds".into(), json!(r));
    }
    Value::Object(body)
}

// ------------------------------------------------------------------ dispatch

async fn dispatch(name: &str, account: &Arc<Account>, args: &Value) -> Result<Value> {
    let g = account.gmail()?;
    match name {
        "send_email" | "draft_email" => {
            let a = parse_email_args(args)?;
            email_action(g, name == "send_email", a).await
        }
        "read_email" => read_email(g, parse(args)?).await,
        "search_emails" => search_emails(g, parse(args)?).await,
        "download_email" => {
            let a: DownloadEmailArgs = parse(args)?;
            match download_email(g, a).await {
                Ok(v) => Ok(v),
                Err(e) => Ok(text_result(format!("Failed to download email: {e:#}"))),
            }
        }
        "modify_email" => {
            let a: ModifyArgs = parse(args)?;
            let mut body = Map::new();
            if let Some(l) = &a.label_ids {
                body.insert("addLabelIds".into(), json!(l));
            }
            if let Some(l) = &a.add_label_ids {
                body.insert("addLabelIds".into(), json!(l));
            }
            if let Some(l) = &a.remove_label_ids {
                body.insert("removeLabelIds".into(), json!(l));
            }
            g.post(
                &format!("/messages/{}/modify", seg(&a.message_id)),
                Value::Object(body),
            )
            .await?;
            Ok(text_result(format!(
                "Email {} labels updated successfully",
                a.message_id
            )))
        }
        "delete_email" => {
            let a: MessageIdArgs = parse(args)?;
            g.delete(&format!("/messages/{}", seg(&a.message_id)))
                .await?;
            Ok(text_result(format!(
                "Email {} deleted successfully",
                a.message_id
            )))
        }
        "send_draft" => {
            let a: DraftIdArgs = parse(args)?;
            let r = g.post("/drafts/send", json!({ "id": a.draft_id })).await?;
            Ok(text_result(format!(
                "Draft {} sent successfully as message ID: {}. The draft has been removed from Drafts.",
                a.draft_id,
                r["id"].as_str().unwrap_or("")
            )))
        }
        "delete_draft" => {
            let a: DraftIdArgs = parse(args)?;
            g.delete(&format!("/drafts/{}", seg(&a.draft_id))).await?;
            Ok(text_result(format!(
                "Draft {} deleted successfully.",
                a.draft_id
            )))
        }
        "update_draft" => {
            let a: UpdateDraftArgs = parse(args)?;
            a.email.validate()?;
            let raw = mime::encode_raw(&mime::build_message(&a.email)?);
            let mut message = json!({ "raw": raw });
            if let Some(t) = &a.email.thread_id {
                message["threadId"] = json!(t);
            }
            g.put(
                &format!("/drafts/{}", seg(&a.draft_id)),
                json!({ "id": a.draft_id, "message": message }),
            )
            .await?;
            Ok(text_result(format!(
                "Draft {} updated successfully (draft ID unchanged, content replaced).",
                a.draft_id
            )))
        }
        "list_email_labels" => {
            let labels = list_labels(g).await?;
            let (system, user): (Vec<&Value>, Vec<&Value>) =
                labels.iter().partition(|l| l["type"] == "system");
            let user: Vec<&Value> = user.into_iter().filter(|l| l["type"] == "user").collect();
            let fmt = |ls: &[&Value]| {
                ls.iter()
                    .map(|l| {
                        format!(
                            "ID: {}\nName: {}\n",
                            l["id"].as_str().unwrap_or(""),
                            l["name"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            Ok(text_result(format!(
                "Found {} labels ({} system, {} user):\n\nSystem Labels:\n{}\nUser Labels:\n{}",
                labels.len(),
                system.len(),
                user.len(),
                fmt(&system),
                fmt(&user)
            )))
        }
        "batch_modify_emails" => {
            let a: BatchArgs = parse(args)?;
            let body = label_body(&a.add_label_ids, &a.remove_label_ids);
            let (ok, failed) =
                process_batches(&a.message_ids, num(a.batch_size, 50), |batch| {
                    let body = body.clone();
                    async move {
                        let rs =
                            join_all(batch.iter().map(|id| {
                                let body = body.clone();
                                async move {
                                    g.post(&format!("/messages/{}/modify", seg(id)), body).await
                                }
                            }))
                            .await;
                        rs.into_iter()
                            .collect::<Result<Vec<_>>>()
                            .map(|_| batch.len())
                    }
                })
                .await;
            let mut t = format!(
                "Batch label modification complete.\nSuccessfully processed: {ok} messages\n"
            );
            append_failures(&mut t, "Failed to process", &failed);
            Ok(text_result(t))
        }
        "report_phishing" => {
            let a: MessageIdArgs = parse(args)?;
            g.post(
                &format!("/messages/{}/modify", seg(&a.message_id)),
                json!({ "addLabelIds": ["SPAM"] }),
            )
            .await?;
            Ok(text_result(format!(
                "Email {} was updated with the SPAM label as the closest public Gmail API approximation of reporting phishing. Note: the Gmail API does not expose the full native Report phishing workflow.",
                a.message_id
            )))
        }
        "batch_report_phishing" => {
            let a: BatchArgs = parse(args)?;
            let (ok, failed) =
                process_batches(&a.message_ids, num(a.batch_size, 50), |batch| async move {
                    g.post(
                        "/messages/batchModify",
                        json!({ "ids": batch, "addLabelIds": ["SPAM"] }),
                    )
                    .await
                    .map(|_| batch.len())
                })
                .await;
            let mut t = format!(
                "Batch phishing report complete.\nSuccessfully processed: {ok} messages\nBehavior: each message was updated with the SPAM label as the closest public Gmail API approximation of reporting phishing.\nLimitation: the Gmail API does not expose the full native Report phishing workflow.\n"
            );
            append_failures(&mut t, "Failed to process", &failed);
            Ok(text_result(t))
        }
        "batch_delete_emails" => {
            let a: BatchArgs = parse(args)?;
            let (ok, failed) =
                process_batches(&a.message_ids, num(a.batch_size, 50), |batch| async move {
                    let rs = join_all(batch.iter().map(|id| async move {
                        g.delete(&format!("/messages/{}", seg(id))).await
                    }))
                    .await;
                    rs.into_iter()
                        .collect::<Result<Vec<_>>>()
                        .map(|_| batch.len())
                })
                .await;
            let mut t =
                format!("Batch delete operation complete.\nSuccessfully deleted: {ok} messages\n");
            append_failures(&mut t, "Failed to delete", &failed);
            Ok(text_result(t))
        }
        "create_label" => {
            let a: LabelArgs = parse(args)?;
            let name = a
                .name
                .clone()
                .ok_or_else(|| anyhow!("Invalid arguments: missing field `name`"))?;
            let l = create_label(g, &name, &a).await?;
            Ok(text_result(label_text("Label created successfully", &l)))
        }
        "update_label" => {
            let a: LabelArgs = parse(args)?;
            let id =
                a.id.clone()
                    .ok_or_else(|| anyhow!("Invalid arguments: missing field `id`"))?;
            let l = update_label(g, &id, &a).await?;
            Ok(text_result(label_text("Label updated successfully", &l)))
        }
        "delete_label" => {
            let a: LabelArgs = parse(args)?;
            let id =
                a.id.clone()
                    .ok_or_else(|| anyhow!("Invalid arguments: missing field `id`"))?;
            Ok(text_result(delete_label(g, &id).await?))
        }
        "get_or_create_label" => {
            let a: LabelArgs = parse(args)?;
            let name = a
                .name
                .clone()
                .ok_or_else(|| anyhow!("Invalid arguments: missing field `name`"))?;
            let (l, found) = get_or_create_label(g, &name, &a)
                .await
                .map_err(|e| anyhow!("Failed to get or create label: {e:#}"))?;
            let action = if found {
                "found existing"
            } else {
                "created new"
            };
            Ok(text_result(label_text(
                &format!("Successfully {action} label"),
                &l,
            )))
        }
        "create_filter" => {
            let a: CreateFilterArgs = parse(args)?;
            let r = create_filter(g, &a.criteria, &a.action).await?;
            Ok(text_result(format!(
                "Filter created successfully:\nID: {}\nCriteria: {}\nActions: {}",
                r["id"].as_str().unwrap_or(""),
                criteria_text(&a.criteria),
                action_text(&a.action)
            )))
        }
        "list_filters" => {
            let r = g
                .get("/settings/filters", Vec::new())
                .await
                .map_err(|e| anyhow!("Failed to list filters: {e:#}"))?;
            let filters = r["filter"].as_array().cloned().unwrap_or_default();
            if filters.is_empty() {
                return Ok(text_result("No filters found."));
            }
            let body = filters
                .iter()
                .map(|f| {
                    format!(
                        "ID: {}\nCriteria: {}\nActions: {}\n",
                        f["id"].as_str().unwrap_or(""),
                        criteria_text(f["criteria"].as_object().unwrap_or(&Map::new())),
                        action_text(f["action"].as_object().unwrap_or(&Map::new()))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(text_result(format!(
                "Found {} filters:\n\n{body}",
                filters.len()
            )))
        }
        "get_filter" => {
            let a: FilterIdArgs = parse(args)?;
            let f = g
                .get(
                    &format!("/settings/filters/{}", seg(&a.filter_id)),
                    Vec::new(),
                )
                .await
                .map_err(|e| match api_status(&e) {
                    Some(404) => anyhow!("Filter with ID \"{}\" not found.", a.filter_id),
                    _ => anyhow!("Failed to get filter: {e:#}"),
                })?;
            Ok(text_result(format!(
                "Filter details:\nID: {}\nCriteria: {}\nActions: {}",
                f["id"].as_str().unwrap_or(""),
                criteria_text(f["criteria"].as_object().unwrap_or(&Map::new())),
                action_text(f["action"].as_object().unwrap_or(&Map::new()))
            )))
        }
        "delete_filter" => {
            let a: FilterIdArgs = parse(args)?;
            g.delete(&format!("/settings/filters/{}", seg(&a.filter_id)))
                .await
                .map_err(|e| match api_status(&e) {
                    Some(404) => anyhow!("Filter with ID \"{}\" not found.", a.filter_id),
                    _ => anyhow!("Failed to delete filter: {e:#}"),
                })?;
            Ok(text_result(format!(
                "Filter \"{}\" deleted successfully.",
                a.filter_id
            )))
        }
        "create_filter_from_template" => {
            let a: TemplateArgs = parse(args)?;
            let (criteria, action) = filter_template(&a.template, &a.parameters)?;
            let r = create_filter(g, &criteria, &action).await?;
            Ok(text_result(format!(
                "Filter created from template '{}':\nID: {}\nTemplate used: {}",
                a.template,
                r["id"].as_str().unwrap_or(""),
                a.template
            )))
        }
        "download_attachment" => {
            let a: AttachmentArgs = parse(args)?;
            match download_attachment(g, a).await {
                Ok(v) => Ok(v),
                Err(e) => Ok(text_result(format!("Failed to download attachment: {e:#}"))),
            }
        }
        "get_thread" => {
            let a: GetThreadArgs = parse(args)?;
            let format = a.format.unwrap_or_else(|| "full".into());
            check_enum("format", &format, &["full", "metadata", "minimal"])?;
            let t = g
                .get(
                    &format!("/threads/{}", seg(&a.thread_id)),
                    q(&[("format", &format)]),
                )
                .await?;
            let messages: Vec<Value> = t["messages"]
                .as_array()
                .map(|ms| {
                    ms.iter()
                        .map(|m| msg::thread_message_json(m, format != "minimal"))
                        .collect()
                })
                .unwrap_or_default();
            Ok(text_result(serde_json::to_string_pretty(&json!({
                "threadId": a.thread_id,
                "messageCount": messages.len(),
                "messages": messages,
            }))?))
        }
        "list_inbox_threads" => {
            let a: ListThreadsArgs = parse(args)?;
            let threads = list_threads(g, &a).await?;
            let summaries = thread_summaries(g, &threads).await?;
            Ok(text_result(serde_json::to_string_pretty(&json!({
                "resultCount": summaries.len(),
                "threads": summaries,
            }))?))
        }
        "get_inbox_with_threads" => {
            let a: ListThreadsArgs = parse(args)?;
            let threads = list_threads(g, &a).await?;
            if !a.expand_threads.unwrap_or(true) {
                let summaries = thread_summaries(g, &threads).await?;
                return Ok(text_result(serde_json::to_string_pretty(&json!({
                    "resultCount": summaries.len(),
                    "threads": summaries,
                }))?));
            }
            let expanded = join_all(threads.iter().map(|t| async move {
                let id = t["id"].as_str().unwrap_or("");
                let d = g
                    .get(&format!("/threads/{}", seg(id)), q(&[("format", "full")]))
                    .await?;
                let messages: Vec<Value> = d["messages"]
                    .as_array()
                    .map(|ms| {
                        ms.iter()
                            .map(|m| msg::thread_message_json(m, true))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok::<_, anyhow::Error>(json!({
                    "threadId": id,
                    "messageCount": messages.len(),
                    "messages": messages,
                }))
            }))
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
            Ok(text_result(serde_json::to_string_pretty(&json!({
                "resultCount": expanded.len(),
                "threads": expanded,
            }))?))
        }
        "reply_all" => reply_all(g, account, parse(args)?).await,
        "modify_thread" => {
            let a: ThreadModifyArgs = parse(args)?;
            g.post(
                &format!("/threads/{}/modify", seg(&a.thread_id)),
                label_body(&a.add_label_ids, &a.remove_label_ids),
            )
            .await?;
            Ok(text_result(format!(
                "Thread {} labels updated successfully (all messages in thread modified)",
                a.thread_id
            )))
        }
        other => bail!("Unknown tool: {other}"),
    }
}

// ------------------------------------------------------------------ helpers

/// Send or draft. Fills In-Reply-To / References from the thread when a
/// threadId is given without inReplyTo.
async fn email_action(g: &Gmail, send: bool, mut a: EmailArgs) -> Result<Value> {
    if let (Some(tid), None) = (a.thread_id.clone(), a.in_reply_to.as_ref()) {
        let query: Query = q(&[("format", "metadata"), ("metadataHeaders", "Message-ID")]);
        match g.get(&format!("/threads/{}", seg(&tid)), query).await {
            Ok(t) => {
                let ms = t["messages"].as_array().cloned().unwrap_or_default();
                let (irt, refs) = msg::resolve_thread_headers(&ms);
                if irt.is_some() {
                    a.in_reply_to = irt;
                }
                if refs.is_some() {
                    a.references = refs;
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not fetch thread {tid} for header resolution: {e:#}")
            }
        }
    }
    let message = mime::build_message(&a).inspect_err(|e| {
        if mime::needs_raw_builder(&a) {
            eprintln!(
                "Failed to send email with {} attachment(s) and {} inline image(s): {e:#}",
                a.attachments.as_ref().map_or(0, Vec::len),
                a.inline_images.as_ref().map_or(0, Vec::len)
            );
        }
    })?;
    let mut request = json!({ "raw": mime::encode_raw(&message) });
    if let Some(t) = &a.thread_id {
        request["threadId"] = json!(t);
    }
    if send {
        let r = g.post("/messages/send", request).await?;
        Ok(text_result(format!(
            "Email sent successfully with ID: {}",
            r["id"].as_str().unwrap_or("")
        )))
    } else {
        let r = g.post("/drafts", json!({ "message": request })).await?;
        Ok(text_result(format!(
            "Email draft created successfully with ID: {}",
            r["id"].as_str().unwrap_or("")
        )))
    }
}

async fn read_email(g: &Gmail, a: MessageIdArgs) -> Result<Value> {
    let m = g
        .get(
            &format!("/messages/{}", seg(&a.message_id)),
            q(&[("format", "full")]),
        )
        .await?;
    let p = &m["payload"];
    let h = |n: &str| msg::header(p, n);
    let EmailContent { text, html } = msg::extract_email_content(p);
    let attachments = msg::extract_attachments(p);
    let note = if text.is_empty() && !html.is_empty() {
        "[Note: This email is HTML-formatted. Plain text version not available.]\n\n"
    } else {
        ""
    };
    let body = if text.is_empty() { html } else { text };
    let att_info = if attachments.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nAttachments ({}):\n{}",
            attachments.len(),
            attachments
                .iter()
                .map(|a| format!(
                    "- {} ({}, {} KB, ID: {})",
                    a.filename,
                    a.mime_type,
                    (a.size as f64 / 1024.0).round(),
                    a.id
                ))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let cc = h("cc");
    let bcc = h("bcc");
    Ok(text_result(format!(
        "Thread ID: {}\nMessage-ID: {}\nSubject: {}\nFrom: {}\nTo: {}{}{}\nDate: {}\n\n{note}{body}{att_info}",
        m["threadId"].as_str().unwrap_or(""),
        h("message-id"),
        h("subject"),
        h("from"),
        h("to"),
        if cc.is_empty() { String::new() } else { format!("\nCC: {cc}") },
        if bcc.is_empty() { String::new() } else { format!("\nBCC: {bcc}") },
        h("date"),
    )))
}

async fn search_emails(g: &Gmail, a: SearchArgs) -> Result<Value> {
    let max = num(a.max_results, 10).to_string();
    let r = g
        .get("/messages", q(&[("q", &a.query), ("maxResults", &max)]))
        .await?;
    let ids: Vec<String> = r["messages"]
        .as_array()
        .map(|ms| {
            ms.iter()
                .filter_map(|m| m["id"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let details = join_all(ids.iter().map(|id| async move {
        let d = g
            .get(
                &format!("/messages/{}", seg(id)),
                q(&[
                    ("format", "metadata"),
                    ("metadataHeaders", "Subject"),
                    ("metadataHeaders", "From"),
                    ("metadataHeaders", "Date"),
                ]),
            )
            .await?;
        let p = &d["payload"];
        Ok::<_, anyhow::Error>(format!(
            "ID: {id}\nSubject: {}\nFrom: {}\nDate: {}\n",
            msg::header_exact(p, "Subject"),
            msg::header_exact(p, "From"),
            msg::header_exact(p, "Date")
        ))
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    Ok(text_result(details.join("\n")))
}

/// Resolve `name` inside `dir`, refusing anything that would escape it.
pub fn safe_join(dir: &Path, name: &str) -> Result<PathBuf> {
    let base = Path::new(name)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .filter(|f| !f.is_empty() && f != "." && f != "..")
        .ok_or_else(|| anyhow!("Invalid filename: path traversal detected"))?;
    let full = dir.join(&base);
    let escapes = full
        .strip_prefix(dir)
        .map(|rest| {
            rest.components()
                .any(|c| !matches!(c, Component::Normal(_)))
        })
        .unwrap_or(true);
    if escapes {
        bail!("Invalid filename: path traversal detected");
    }
    Ok(full)
}

fn absolute(p: &Path) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

async fn download_email(g: &Gmail, a: DownloadEmailArgs) -> Result<Value> {
    let format = a.format.clone().unwrap_or_else(|| "json".into());
    check_enum("format", &format, &["json", "eml", "txt", "html"])?;
    let dir = absolute(Path::new(&a.save_path))?;
    std::fs::create_dir_all(&dir)?;
    let full = g
        .get(
            &format!("/messages/{}", seg(&a.message_id)),
            q(&[("format", "full")]),
        )
        .await?;
    let p = &full["payload"];
    let attachments = msg::extract_attachments(p);
    let content = if format == "eml" {
        let raw = g
            .get(
                &format!("/messages/{}", seg(&a.message_id)),
                q(&[("format", "raw")]),
            )
            .await?;
        String::from_utf8_lossy(&msg::decode_b64(raw["raw"].as_str().unwrap_or(""))).to_string()
    } else {
        let c = msg::extract_email_content(p);
        match format.as_str() {
            "json" => serde_json::to_string_pretty(&msg::message_to_json(&full, &c, &attachments))?,
            "txt" => msg::message_to_txt(&full, &c, &attachments),
            _ => msg::message_to_html(&c)?,
        }
    };
    let path = safe_join(&dir, &format!("{}.{format}", a.message_id))?;
    std::fs::write(&path, &content)?;
    let size = std::fs::metadata(&path)?.len();
    Ok(text_result(serde_json::to_string_pretty(&json!({
        "status": "saved",
        "path": path.display().to_string(),
        "size": size,
        "messageId": a.message_id,
        "subject": msg::header(p, "subject"),
        "from": msg::header(p, "from"),
        "date": msg::header(p, "date"),
        "attachments": attachments,
    }))?))
}

async fn download_attachment(g: &Gmail, a: AttachmentArgs) -> Result<Value> {
    let r = g
        .get(
            &format!(
                "/messages/{}/attachments/{}",
                seg(&a.message_id),
                seg(&a.attachment_id)
            ),
            Vec::new(),
        )
        .await?;
    let data = r["data"]
        .as_str()
        .ok_or_else(|| anyhow!("No attachment data received"))?;
    let bytes = msg::decode_b64(data);
    let dir = match &a.save_path {
        Some(p) => absolute(Path::new(p))?,
        None => std::env::current_dir()?,
    };
    let filename = match a.filename.clone() {
        Some(f) => f,
        None => {
            let m = g
                .get(
                    &format!("/messages/{}", seg(&a.message_id)),
                    q(&[("format", "full")]),
                )
                .await?;
            msg::find_attachment_filename(&m["payload"], &a.attachment_id)
                .unwrap_or_else(|| format!("attachment-{}", a.attachment_id))
        }
    };
    std::fs::create_dir_all(&dir)?;
    let path = safe_join(&dir, &filename)?;
    std::fs::write(&path, &bytes)?;
    let shown = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    Ok(text_result(format!(
        "Attachment downloaded successfully:\nFile: {shown}\nSize: {} bytes\nSaved to: {}",
        bytes.len(),
        path.display()
    )))
}

async fn list_threads(g: &Gmail, a: &ListThreadsArgs) -> Result<Vec<Value>> {
    let query = a
        .query
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "in:inbox".into());
    let max = num(a.max_results, 50).to_string();
    let r = g
        .get("/threads", q(&[("q", &query), ("maxResults", &max)]))
        .await?;
    Ok(r["threads"].as_array().cloned().unwrap_or_default())
}

async fn thread_summaries(g: &Gmail, threads: &[Value]) -> Result<Vec<Value>> {
    join_all(threads.iter().map(|t| async move {
        let id = t["id"].as_str().unwrap_or("");
        let d = g
            .get(
                &format!("/threads/{}", seg(id)),
                q(&[
                    ("format", "metadata"),
                    ("metadataHeaders", "Subject"),
                    ("metadataHeaders", "From"),
                    ("metadataHeaders", "Date"),
                ]),
            )
            .await?;
        let ms = d["messages"].as_array().cloned().unwrap_or_default();
        let latest = ms
            .last()
            .map(|m| m["payload"].clone())
            .unwrap_or(Value::Null);
        Ok(json!({
            "threadId": id,
            "snippet": t["snippet"].as_str().unwrap_or(""),
            "historyId": t["historyId"].as_str().unwrap_or(""),
            "messageCount": ms.len(),
            "latestMessage": {
                "from": msg::header_exact(&latest, "From"),
                "subject": msg::header_exact(&latest, "Subject"),
                "date": msg::header_exact(&latest, "Date"),
            },
        }))
    }))
    .await
    .into_iter()
    .collect()
}

async fn reply_all(g: &Gmail, account: &Arc<Account>, a: ReplyAllArgs) -> Result<Value> {
    if let Some(m) = &a.mime_type {
        check_enum(
            "mimeType",
            m,
            &["text/plain", "text/html", "multipart/alternative"],
        )?;
    }
    for img in a.inline_images.iter().flatten() {
        mime::validate_inline_image(img)?;
    }
    let original = g
        .get(
            &format!("/messages/{}", seg(&a.message_id)),
            q(&[("format", "full")]),
        )
        .await?;
    let p = &original["payload"];
    let h = |n: &str| msg::header(p, n);
    let thread_id = original["threadId"].as_str().unwrap_or("").to_string();
    let my_email = account.email().await?.to_lowercase();
    let (to, cc) = msg::build_reply_all_recipients(&h("from"), &h("to"), &h("cc"), &my_email);
    if to.is_empty() {
        bail!("Could not determine recipient for reply");
    }
    let subject = msg::add_re_prefix(&h("subject"));
    let original_id = h("message-id");
    let references = msg::build_references_header(&h("references"), &original_id);
    let email = EmailArgs {
        to: to.clone(),
        cc: (!cc.is_empty()).then(|| cc.clone()),
        subject: subject.clone(),
        body: a.body,
        html_body: a.html_body,
        mime_type: a.mime_type,
        thread_id: Some(thread_id.clone()).filter(|t| !t.is_empty()),
        in_reply_to: Some(original_id).filter(|s| !s.is_empty()),
        references: Some(references).filter(|s| !s.is_empty()),
        attachments: a.attachments,
        inline_images: a.inline_images,
        ..Default::default()
    };
    email_action(g, true, email).await?;
    Ok(text_result(format!(
        "Reply-all sent successfully!\nTo: {}{}\nSubject: {subject}\nThread ID: {thread_id}",
        to.join(", "),
        if cc.is_empty() {
            String::new()
        } else {
            format!("\nCC: {}", cc.join(", "))
        }
    )))
}

/// Sequential batches; a failed batch is retried item by item so one bad ID
/// doesn't sink the rest. Returns (succeeded, [(id, error)]).
async fn process_batches<'a, F, Fut>(
    ids: &'a [String],
    batch_size: u64,
    f: F,
) -> (usize, Vec<(String, String)>)
where
    F: Fn(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<usize>> + 'a,
{
    let mut ok = 0;
    let mut failed = Vec::new();
    for batch in ids.chunks(batch_size.max(1) as usize) {
        match f(batch.to_vec()).await {
            Ok(n) => ok += n,
            Err(_) => {
                for id in batch {
                    match f(vec![id.clone()]).await {
                        Ok(n) => ok += n,
                        Err(e) => failed.push((id.clone(), format!("{e:#}"))),
                    }
                }
            }
        }
    }
    (ok, failed)
}

fn append_failures(t: &mut String, verb: &str, failed: &[(String, String)]) {
    if failed.is_empty() {
        return;
    }
    t.push_str(&format!(
        "{verb}: {} messages\n\nFailed message IDs:\n",
        failed.len()
    ));
    t.push_str(
        &failed
            .iter()
            .map(|(id, e)| format!("- {}... ({e})", id.chars().take(16).collect::<String>()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

async fn list_labels(g: &Gmail) -> Result<Vec<Value>> {
    let r = g
        .get("/labels", Vec::new())
        .await
        .map_err(|e| anyhow!("Failed to list labels: {e:#}"))?;
    Ok(r["labels"].as_array().cloned().unwrap_or_default())
}

fn label_text(title: &str, l: &Value) -> String {
    format!(
        "{title}:\nID: {}\nName: {}\nType: {}",
        l["id"].as_str().unwrap_or(""),
        l["name"].as_str().unwrap_or(""),
        l["type"].as_str().unwrap_or("")
    )
}

async fn create_label(g: &Gmail, name: &str, a: &LabelArgs) -> Result<Value> {
    if let Some(v) = &a.message_list_visibility {
        check_enum("messageListVisibility", v, &["show", "hide"])?;
    }
    if let Some(v) = &a.label_list_visibility {
        check_enum(
            "labelListVisibility",
            v,
            &["labelShow", "labelShowIfUnread", "labelHide"],
        )?;
    }
    g.post(
        "/labels",
        json!({
            "name": name,
            "messageListVisibility": a.message_list_visibility.as_deref().unwrap_or("show"),
            "labelListVisibility": a.label_list_visibility.as_deref().unwrap_or("labelShow"),
        }),
    )
    .await
    .map_err(|e| {
        let m = format!("{e:#}");
        if m.contains("already exists") {
            anyhow!("Label \"{name}\" already exists. Please use a different name.")
        } else {
            anyhow!("Failed to create label: {m}")
        }
    })
}

async fn update_label(g: &Gmail, id: &str, a: &LabelArgs) -> Result<Value> {
    let path = format!("/labels/{}", seg(id));
    let wrap = |e: anyhow::Error| match api_status(&e) {
        Some(404) => anyhow!("Label with ID \"{id}\" not found."),
        _ => anyhow!("Failed to update label: {e:#}"),
    };
    g.get(&path, Vec::new()).await.map_err(wrap)?;
    let mut body = Map::new();
    body.insert("id".into(), json!(id));
    if let Some(n) = a.name.as_ref().filter(|n| !n.is_empty()) {
        body.insert("name".into(), json!(n));
    }
    if let Some(v) = a.message_list_visibility.as_ref().filter(|v| !v.is_empty()) {
        body.insert("messageListVisibility".into(), json!(v));
    }
    if let Some(v) = a.label_list_visibility.as_ref().filter(|v| !v.is_empty()) {
        body.insert("labelListVisibility".into(), json!(v));
    }
    g.put(&path, Value::Object(body)).await.map_err(wrap)
}

async fn delete_label(g: &Gmail, id: &str) -> Result<String> {
    let path = format!("/labels/{}", seg(id));
    let wrap = |e: anyhow::Error| match api_status(&e) {
        Some(404) => anyhow!("Label with ID \"{id}\" not found."),
        _ => anyhow!("Failed to delete label: {e:#}"),
    };
    let label = g.get(&path, Vec::new()).await.map_err(wrap)?;
    if label["type"] == "system" {
        bail!("Failed to delete label: Cannot delete system label with ID \"{id}\".");
    }
    g.delete(&path).await.map_err(wrap)?;
    Ok(format!(
        "Label \"{}\" deleted successfully.",
        label["name"].as_str().unwrap_or("")
    ))
}

async fn get_or_create_label(g: &Gmail, name: &str, a: &LabelArgs) -> Result<(Value, bool)> {
    let labels = list_labels(g).await?;
    let lower = name.to_lowercase();
    if let Some(l) = labels
        .into_iter()
        .find(|l| l["name"].as_str().map(str::to_lowercase).as_deref() == Some(lower.as_str()))
    {
        return Ok((l, true));
    }
    Ok((create_label(g, name, a).await?, false))
}

fn display_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(display_value).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

fn criteria_text(c: &Map<String, Value>) -> String {
    c.iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| format!("{k}: {}", display_value(v)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn action_text(a: &Map<String, Value>) -> String {
    a.iter()
        .filter(|(_, v)| !v.is_null() && v.as_array().is_none_or(|x| !x.is_empty()))
        .map(|(k, v)| format!("{k}: {}", display_value(v)))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn create_filter(
    g: &Gmail,
    criteria: &Map<String, Value>,
    action: &Map<String, Value>,
) -> Result<Value> {
    if let Some(sc) = criteria.get("sizeComparison").and_then(Value::as_str) {
        check_enum("sizeComparison", sc, &["unspecified", "smaller", "larger"])?;
    }
    g.post(
        "/settings/filters",
        json!({ "criteria": criteria, "action": action }),
    )
    .await
    .map_err(|e| match api_status(&e) {
        Some(400) => anyhow!("Invalid filter criteria or action: {e:#}"),
        _ => anyhow!("Failed to create filter: {e:#}"),
    })
}

/// Port of `filterTemplates`.
fn filter_template(
    template: &str,
    p: &TemplateParams,
) -> Result<(Map<String, Value>, Map<String, Value>)> {
    let labels = p.label_ids.clone().unwrap_or_default();
    let obj = |v: Value| v.as_object().cloned().unwrap_or_default();
    let with_remove = |mut action: Map<String, Value>, flag: bool, label: &str| {
        if flag {
            action.insert("removeLabelIds".into(), json!([label]));
        }
        action
    };
    let base_action = obj(json!({ "addLabelIds": labels }));
    let r = match template {
        "fromSender" => {
            let s = p
                .sender_email
                .as_ref()
                .filter(|s| !s.is_empty())
                .context("senderEmail is required for fromSender template")?;
            (
                obj(json!({ "from": s })),
                with_remove(base_action, p.archive.unwrap_or(false), "INBOX"),
            )
        }
        "withSubject" => {
            let s = p
                .subject_text
                .as_ref()
                .filter(|s| !s.is_empty())
                .context("subjectText is required for withSubject template")?;
            (
                obj(json!({ "subject": s })),
                with_remove(base_action, p.mark_as_read.unwrap_or(false), "UNREAD"),
            )
        }
        "withAttachments" => (obj(json!({ "hasAttachment": true })), base_action),
        "largeEmails" => {
            let size = p
                .size_in_bytes
                .filter(|n| *n != 0.0)
                .context("sizeInBytes is required for largeEmails template")?;
            (
                obj(json!({ "size": size as i64, "sizeComparison": "larger" })),
                base_action,
            )
        }
        "containingText" => {
            let s = p
                .search_text
                .as_ref()
                .filter(|s| !s.is_empty())
                .context("searchText is required for containingText template")?;
            let mut l = labels.clone();
            if p.mark_important.unwrap_or(false) {
                l.push("IMPORTANT".into());
            }
            (
                obj(json!({ "query": format!("\"{s}\"") })),
                obj(json!({ "addLabelIds": l })),
            )
        }
        "mailingList" => {
            let s = p
                .list_identifier
                .as_ref()
                .filter(|s| !s.is_empty())
                .context("listIdentifier is required for mailingList template")?;
            (
                obj(json!({ "query": format!("list:{s} OR subject:[{s}]") })),
                with_remove(base_action, p.archive.unwrap_or(true), "INBOX"),
            )
        }
        other => bail!("Unknown template: {other}"),
    };
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_blocks_traversal() {
        let d = Path::new("/tmp/save");
        assert_eq!(
            safe_join(d, "a.pdf").unwrap(),
            PathBuf::from("/tmp/save/a.pdf")
        );
        assert_eq!(
            safe_join(d, "../../etc/passwd").unwrap(),
            PathBuf::from("/tmp/save/passwd")
        );
        assert!(safe_join(d, "..").is_err());
        assert!(safe_join(d, "").is_err());
        assert!(safe_join(d, "/").is_err());
    }

    #[test]
    fn thread_arg_parsing_matches_zod() {
        let a: GetThreadArgs = parse(&json!({"threadId": "t"})).unwrap();
        assert_eq!(a.format, None);
        assert!(parse::<GetThreadArgs>(&json!({})).is_err());
        assert!(parse::<GetThreadArgs>(&json!({"threadId": 5})).is_err());
        assert!(parse::<ThreadModifyArgs>(&json!({"threadId": "t", "addLabelIds": "x"})).is_err());
        let l: ListThreadsArgs = parse(&Value::Null).unwrap();
        assert!(l.query.is_none() && l.max_results.is_none());
        assert!(parse::<MessageIdArgs>(&json!({})).is_err());
        let b: BatchArgs = parse(&json!({"messageIds": ["a"]})).unwrap();
        assert_eq!(num(b.batch_size, 50), 50);
    }

    #[test]
    fn filter_templates() {
        let p = TemplateParams {
            sender_email: Some("a@x.com".into()),
            archive: Some(true),
            ..Default::default()
        };
        let (c, a) = filter_template("fromSender", &p).unwrap();
        assert_eq!(c["from"], "a@x.com");
        assert_eq!(a["removeLabelIds"], json!(["INBOX"]));
        assert!(filter_template("fromSender", &TemplateParams::default()).is_err());
        let p = TemplateParams {
            search_text: Some("hi".into()),
            mark_important: Some(true),
            label_ids: Some(vec!["L".into()]),
            ..Default::default()
        };
        let (c, a) = filter_template("containingText", &p).unwrap();
        assert_eq!(c["query"], "\"hi\"");
        assert_eq!(a["addLabelIds"], json!(["L", "IMPORTANT"]));
        let p = TemplateParams {
            list_identifier: Some("dev".into()),
            ..Default::default()
        };
        let (c, a) = filter_template("mailingList", &p).unwrap();
        assert_eq!(c["query"], "list:dev OR subject:[dev]");
        assert_eq!(
            a["removeLabelIds"],
            json!(["INBOX"]),
            "mailingList archives by default"
        );
        assert!(filter_template("nope", &TemplateParams::default()).is_err());
    }

    #[test]
    fn criteria_and_action_text() {
        let c = json!({"from": "a@x.com", "hasAttachment": true, "size": 10})
            .as_object()
            .cloned()
            .unwrap();
        assert_eq!(
            criteria_text(&c),
            "from: a@x.com, hasAttachment: true, size: 10"
        );
        let a = json!({"addLabelIds": ["A", "B"], "removeLabelIds": []})
            .as_object()
            .cloned()
            .unwrap();
        assert_eq!(action_text(&a), "addLabelIds: A, B");
    }
}
