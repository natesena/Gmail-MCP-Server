//! Reading Gmail message payloads, exporting them, and reply-all helpers
//! (ports of the helpers in `index.ts`, `email-export.ts`,
//! `reply-all-helpers.ts`).

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

/// Decode Gmail's base64 / base64url body data, tolerating padding and whitespace.
pub fn decode_b64(data: &str) -> Vec<u8> {
    let cleaned: String = data
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    STANDARD_NO_PAD
        .decode(cleaned.as_bytes())
        .unwrap_or_default()
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct EmailContent {
    pub text: String,
    pub html: String,
}

/// Recursively collect text/plain and text/html bodies.
pub fn extract_email_content(part: &Value) -> EmailContent {
    let mut out = EmailContent::default();
    if let Some(data) = part["body"]["data"].as_str() {
        let content = String::from_utf8_lossy(&decode_b64(data)).to_string();
        match part["mimeType"].as_str() {
            Some("text/plain") => out.text = content,
            Some("text/html") => out.html = content,
            _ => {}
        }
    }
    if let Some(parts) = part["parts"].as_array() {
        for p in parts {
            let c = extract_email_content(p);
            out.text.push_str(&c.text);
            out.html.push_str(&c.html);
        }
    }
    out
}

/// Case-insensitive header lookup on a payload.
pub fn header(payload: &Value, name: &str) -> String {
    payload["headers"]
        .as_array()
        .and_then(|hs| {
            hs.iter().find(|h| {
                h["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
        })
        .and_then(|h| h["value"].as_str())
        .unwrap_or("")
        .to_string()
}

/// Exact-case header lookup (used where the Node server compared `h.name === 'Subject'`).
pub fn header_exact(payload: &Value, name: &str) -> String {
    payload["headers"]
        .as_array()
        .and_then(|hs| hs.iter().find(|h| h["name"].as_str() == Some(name)))
        .and_then(|h| h["value"].as_str())
        .unwrap_or("")
        .to_string()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
}

pub fn extract_attachments(payload: &Value) -> Vec<Attachment> {
    fn walk(part: &Value, out: &mut Vec<Attachment>) {
        if let Some(id) = part["body"]["attachmentId"].as_str() {
            let filename = part["filename"]
                .as_str()
                .filter(|f| !f.is_empty())
                .map(String::from)
                .unwrap_or_else(|| format!("attachment-{id}"));
            out.push(Attachment {
                id: id.to_string(),
                filename,
                mime_type: part["mimeType"]
                    .as_str()
                    .filter(|m| !m.is_empty())
                    .unwrap_or("application/octet-stream")
                    .to_string(),
                size: part["body"]["size"].as_u64().unwrap_or(0),
            });
        }
        if let Some(parts) = part["parts"].as_array() {
            for p in parts {
                walk(p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(payload, &mut out);
    out
}

/// Find the original filename of an attachment by id.
pub fn find_attachment_filename(payload: &Value, attachment_id: &str) -> Option<String> {
    if payload["body"]["attachmentId"].as_str() == Some(attachment_id) {
        return Some(
            payload["filename"]
                .as_str()
                .filter(|f| !f.is_empty())
                .map(String::from)
                .unwrap_or_else(|| format!("attachment-{attachment_id}")),
        );
    }
    payload["parts"]
        .as_array()?
        .iter()
        .find_map(|p| find_attachment_filename(p, attachment_id))
}

/// The per-message object returned by get_thread / get_inbox_with_threads.
pub fn thread_message_json(msg: &Value, include_body: bool) -> Value {
    let p = &msg["payload"];
    let body = if include_body {
        let c = extract_email_content(p);
        if c.text.is_empty() {
            c.html
        } else {
            c.text
        }
    } else {
        String::new()
    };
    let attachments: Vec<Value> = if p.is_object() {
        extract_attachments(p)
            .into_iter()
            .map(|a| json!({"filename": a.filename, "mimeType": a.mime_type, "size": a.size}))
            .collect()
    } else {
        Vec::new()
    };
    json!({
        "messageId": msg["id"].as_str().unwrap_or(""),
        "threadId": msg["threadId"].as_str().unwrap_or(""),
        "from": header(p, "from"),
        "to": header(p, "to"),
        "cc": header(p, "cc"),
        "bcc": header(p, "bcc"),
        "subject": header(p, "subject"),
        "date": header(p, "date"),
        "body": body,
        "labelIds": msg["labelIds"].as_array().cloned().unwrap_or_default(),
        "attachments": attachments,
    })
}

/// Pick In-Reply-To / References for a reply in a thread: order by
/// internalDate (NOT array position; Gmail's order isn't reliably
/// chronological), keeping array order for messages without one.
pub fn resolve_thread_headers(messages: &[Value]) -> (Option<String>, Option<String>) {
    if messages.is_empty() {
        return (None, None);
    }
    let date = |m: &Value| -> Option<f64> {
        match &m["internalDate"] {
            Value::String(s) => s.parse().ok(),
            Value::Number(n) => n.as_f64(),
            _ => None,
        }
    };
    let mut ordered: Vec<(usize, &Value)> = messages.iter().enumerate().collect();
    ordered.sort_by(|(ia, a), (ib, b)| match (date(a), date(b)) {
        (Some(da), Some(db)) if da != db => {
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        }
        _ => ia.cmp(ib),
    });
    let ids: Vec<String> = ordered
        .iter()
        .map(|(_, m)| header(&m["payload"], "message-id"))
        .filter(|s| !s.is_empty())
        .collect();
    let newest = ordered
        .last()
        .map(|(_, m)| header(&m["payload"], "message-id"))
        .filter(|s| !s.is_empty());
    let refs = (!ids.is_empty()).then(|| ids.join(" "));
    (newest, refs)
}

// ---------------------------------------------------------------- reply-all

/// Naive address extraction (port of reply-all-helpers `parseEmailAddresses`).
pub fn parse_reply_addresses(header_value: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in header_value.split(',') {
        let t = part.trim();
        if let (Some(s), Some(e)) = (t.find('<'), t.find('>')) {
            if s < e {
                out.push(t[s + 1..e].trim().to_string());
                continue;
            }
        }
        if t.contains('@') {
            out.push(t.to_string());
        }
    }
    out
}

pub fn filter_out_email(emails: &[String], mine: &str) -> Vec<String> {
    let mine = mine.to_lowercase();
    emails
        .iter()
        .filter(|e| e.to_lowercase() != mine)
        .cloned()
        .collect()
}

pub fn add_re_prefix(subject: &str) -> String {
    if subject.to_lowercase().starts_with("re:") {
        subject.to_string()
    } else {
        format!("Re: {subject}")
    }
}

pub fn build_references_header(original_refs: &str, original_message_id: &str) -> String {
    if original_message_id.is_empty() {
        original_refs.to_string()
    } else if original_refs.is_empty() {
        original_message_id.to_string()
    } else {
        format!("{original_refs} {original_message_id}")
    }
}

/// TO: original From; CC: original To + CC; both without the user.
pub fn build_reply_all_recipients(
    from: &str,
    to: &str,
    cc: &str,
    mine: &str,
) -> (Vec<String>, Vec<String>) {
    let reply_to = filter_out_email(&parse_reply_addresses(from), mine);
    let mut others = parse_reply_addresses(to);
    others.extend(parse_reply_addresses(cc));
    (reply_to, filter_out_email(&others, mine))
}

// ------------------------------------------------------------------- export

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ParsedAddress {
    pub name: String,
    pub email: String,
}

/// Split an address list on commas outside quotes and angle brackets.
fn split_addresses(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut cur, mut quoted, mut angle) = (String::new(), false, false);
    let mut chars = list.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quoted => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            '<' if !quoted => {
                angle = true;
                cur.push(c);
            }
            '>' if !quoted => {
                angle = false;
                cur.push(c);
            }
            ',' if !quoted && !angle => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_mailbox(addr: &str) -> Option<ParsedAddress> {
    let a = addr.trim();
    if let (Some(s), true) = (a.rfind('<'), a.ends_with('>')) {
        let email = a[s + 1..a.len() - 1].trim().to_string();
        let raw_name = a[..s].trim();
        let name = raw_name
            .strip_prefix('"')
            .and_then(|n| n.strip_suffix('"'))
            .map(|n| n.replace("\\\"", "\"").replace("\\\\", "\\"))
            .unwrap_or_else(|| raw_name.to_string());
        return email.contains('@').then_some(ParsedAddress { name, email });
    }
    (a.contains('@') && !a.contains(char::is_whitespace)).then(|| ParsedAddress {
        name: String::new(),
        email: a.to_string(),
    })
}

/// One address -> name/email (falls back to the trimmed input as email).
pub fn parse_email_address(addr: &str) -> ParsedAddress {
    if addr.is_empty() {
        return ParsedAddress {
            name: String::new(),
            email: String::new(),
        };
    }
    parse_mailbox(addr).unwrap_or_else(|| ParsedAddress {
        name: String::new(),
        email: addr.trim().to_string(),
    })
}

/// Address list -> mailboxes (groups / unparseable entries are skipped).
pub fn parse_email_addresses(list: &str) -> Vec<ParsedAddress> {
    if list.is_empty() {
        return Vec::new();
    }
    split_addresses(list)
        .iter()
        .filter_map(|a| parse_mailbox(a))
        .collect()
}

/// RFC 2822 date -> ISO 8601 UTC with milliseconds (like JS toISOString);
/// unparseable dates are returned unchanged.
pub fn to_iso_date(date: &str) -> String {
    let trimmed = match date.rfind('(') {
        Some(i) if date.trim_end().ends_with(')') => date[..i].trim(),
        _ => date.trim(),
    };
    chrono::DateTime::parse_from_rfc2822(trimmed)
        .map(|d| {
            d.with_timezone(&chrono::Utc)
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string()
        })
        .unwrap_or_else(|_| date.to_string())
}

pub fn message_to_json(msg: &Value, content: &EmailContent, attachments: &[Attachment]) -> Value {
    let p = &msg["payload"];
    json!({
        "messageId": msg["id"],
        "threadId": msg["threadId"],
        "subject": header(p, "subject"),
        "from": parse_email_address(&header(p, "from")),
        "to": parse_email_addresses(&header(p, "to")),
        "cc": parse_email_addresses(&header(p, "cc")),
        "bcc": parse_email_addresses(&header(p, "bcc")),
        "date": to_iso_date(&header(p, "date")),
        "labels": msg["labelIds"].as_array().cloned().unwrap_or_default(),
        "snippet": msg["snippet"].as_str().unwrap_or(""),
        "body": { "plain": content.text, "html": content.html },
        "attachments": attachments,
        "headers": {
            "Message-ID": header(p, "message-id"),
            "In-Reply-To": header(p, "in-reply-to"),
            "References": header(p, "references"),
        },
    })
}

pub fn message_to_txt(msg: &Value, content: &EmailContent, attachments: &[Attachment]) -> String {
    let p = &msg["payload"];
    let mut lines = vec![
        format!("From: {}", header(p, "from")),
        format!("To: {}", header(p, "to")),
    ];
    let cc = header(p, "cc");
    if !cc.is_empty() {
        lines.push(format!("CC: {cc}"));
    }
    lines.push(format!("Subject: {}", header(p, "subject")));
    lines.push(format!("Date: {}", header(p, "date")));
    lines.push(String::new());
    lines.push(if content.text.is_empty() {
        "[No plain text content]".into()
    } else {
        content.text.clone()
    });
    if !attachments.is_empty() {
        lines.push(String::new());
        lines.push("---".into());
        lines.push(format!(
            "Attachments: {}",
            attachments
                .iter()
                .map(|a| a.filename.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines.join("\n")
}

pub fn message_to_html(content: &EmailContent) -> anyhow::Result<String> {
    if content.html.is_empty() {
        anyhow::bail!("This email has no HTML content");
    }
    Ok(content.html.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s)
    }

    fn sample() -> Value {
        json!({
            "id": "m1", "threadId": "t1", "snippet": "snip", "labelIds": ["INBOX"],
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    {"name": "From", "value": "\"Doe, Jane\" <jane@x.com>"},
                    {"name": "To", "value": "a@x.com, Bob <bob@x.com>"},
                    {"name": "Cc", "value": "c@x.com"},
                    {"name": "Subject", "value": "Hello"},
                    {"name": "Date", "value": "Tue, 03 Nov 2026 10:00:00 -0800 (PST)"},
                    {"name": "Message-ID", "value": "<id1@x>"}
                ],
                "parts": [
                    {"mimeType": "multipart/alternative", "parts": [
                        {"mimeType": "text/plain", "body": {"data": b64("plain ✓")}},
                        {"mimeType": "text/html", "body": {"data": b64("<p>html</p>")}}
                    ]},
                    {"mimeType": "application/pdf", "filename": "a.pdf", "body": {"attachmentId": "att1", "size": 2048}},
                    {"mimeType": "", "filename": "", "body": {"attachmentId": "att2"}}
                ]
            }
        })
    }

    #[test]
    fn extracts_nested_content_and_attachments() {
        let m = sample();
        let c = extract_email_content(&m["payload"]);
        assert_eq!(c.text, "plain ✓");
        assert_eq!(c.html, "<p>html</p>");
        let a = extract_attachments(&m["payload"]);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].filename, "a.pdf");
        assert_eq!(a[0].size, 2048);
        assert_eq!(a[1].filename, "attachment-att2");
        assert_eq!(a[1].mime_type, "application/octet-stream");
        assert_eq!(
            find_attachment_filename(&m["payload"], "att1").as_deref(),
            Some("a.pdf")
        );
        assert_eq!(find_attachment_filename(&m["payload"], "zzz"), None);
    }

    #[test]
    fn decodes_padded_and_standard_base64() {
        assert_eq!(decode_b64("aGk="), b"hi");
        assert_eq!(decode_b64("-_8"), vec![0xfb, 0xff]);
    }

    #[test]
    fn header_lookup_case_insensitive() {
        let m = sample();
        assert_eq!(header(&m["payload"], "message-id"), "<id1@x>");
        assert_eq!(header_exact(&m["payload"], "Subject"), "Hello");
        assert_eq!(header_exact(&m["payload"], "subject"), "");
    }

    // ---- download-email.test.ts (export formats)
    #[test]
    fn json_export_shape() {
        let m = sample();
        let c = extract_email_content(&m["payload"]);
        let a = extract_attachments(&m["payload"]);
        let j = message_to_json(&m, &c, &a);
        assert_eq!(
            j["from"],
            json!({"name": "Doe, Jane", "email": "jane@x.com"})
        );
        assert_eq!(
            j["to"],
            json!([{"name": "", "email": "a@x.com"}, {"name": "Bob", "email": "bob@x.com"}])
        );
        assert_eq!(j["date"], "2026-11-03T18:00:00.000Z");
        assert_eq!(j["body"]["plain"], "plain ✓");
        assert_eq!(j["attachments"][0]["mimeType"], "application/pdf");
        assert_eq!(j["headers"]["Message-ID"], "<id1@x>");
        assert_eq!(j["labels"], json!(["INBOX"]));
    }

    #[test]
    fn txt_and_html_export() {
        let m = sample();
        let c = extract_email_content(&m["payload"]);
        let a = extract_attachments(&m["payload"]);
        let t = message_to_txt(&m, &c, &a);
        assert!(t.starts_with("From: \"Doe, Jane\" <jane@x.com>\nTo: a@x.com, Bob <bob@x.com>\nCC: c@x.com\nSubject: Hello\n"));
        assert!(t.ends_with("---\nAttachments: a.pdf, attachment-att2"));
        assert_eq!(message_to_html(&c).unwrap(), "<p>html</p>");
        assert!(message_to_html(&EmailContent::default()).is_err());
        let none = message_to_txt(&json!({"payload": {}}), &EmailContent::default(), &[]);
        assert!(none.contains("[No plain text content]"));
    }

    #[test]
    fn address_parsing_edge_cases() {
        assert_eq!(
            parse_email_address(""),
            ParsedAddress {
                name: "".into(),
                email: "".into()
            }
        );
        assert_eq!(parse_email_address("garbage text").email, "garbage text");
        assert!(parse_email_addresses("").is_empty());
        assert_eq!(
            parse_email_addresses("\"A \\\"Q\\\" B\" <q@x.com>")[0].name,
            "A \"Q\" B"
        );
    }

    #[test]
    fn iso_date_fallback() {
        assert_eq!(to_iso_date("not a date"), "not a date");
        assert_eq!(
            to_iso_date("Wed, 4 Nov 2026 01:02:03 +0000"),
            "2026-11-04T01:02:03.000Z"
        );
    }

    // ---- utl.test.ts: thread header resolution
    fn tmsg(id: &str, date: Option<&str>) -> Value {
        let mut m = json!({"payload": {"headers": [{"name": "Message-ID", "value": id}]}});
        if let Some(d) = date {
            m["internalDate"] = json!(d);
        }
        m
    }

    #[test]
    fn thread_headers_pick_newest_by_internal_date() {
        let out = resolve_thread_headers(&[
            tmsg("<b@x>", Some("200")),
            tmsg("<c@x>", Some("300")),
            tmsg("<a@x>", Some("100")),
        ]);
        assert_eq!(out.0.as_deref(), Some("<c@x>"));
        assert_eq!(out.1.as_deref(), Some("<a@x> <b@x> <c@x>"));
        let chrono = resolve_thread_headers(&[tmsg("<a@x>", Some("1")), tmsg("<b@x>", Some("2"))]);
        assert_eq!(chrono.0.as_deref(), Some("<b@x>"));
        let missing = resolve_thread_headers(&[tmsg("<a@x>", None), tmsg("<b@x>", None)]);
        assert_eq!(missing.0.as_deref(), Some("<b@x>"));
        assert_eq!(missing.1.as_deref(), Some("<a@x> <b@x>"));
        let single = resolve_thread_headers(&[tmsg("<only@x>", Some("5"))]);
        assert_eq!(single, (Some("<only@x>".into()), Some("<only@x>".into())));
        assert_eq!(resolve_thread_headers(&[]), (None, None));
    }

    // ---- reply-all-helpers.test.ts
    #[test]
    fn reply_all_helpers() {
        assert_eq!(
            parse_reply_addresses("John <john@x.com>, jane@x.com, nobody"),
            vec!["john@x.com", "jane@x.com"]
        );
        assert!(parse_reply_addresses("").is_empty());
        assert_eq!(
            filter_out_email(&["Me@X.com".into(), "o@x.com".into()], "me@x.com"),
            vec!["o@x.com"]
        );
        assert_eq!(add_re_prefix("Hello"), "Re: Hello");
        assert_eq!(add_re_prefix("RE: Hello"), "RE: Hello");
        assert_eq!(build_references_header("<a>", "<b>"), "<a> <b>");
        assert_eq!(build_references_header("", "<b>"), "<b>");
        assert_eq!(build_references_header("<a>", ""), "<a>");
        let (to, cc) = build_reply_all_recipients(
            "Sender <s@x.com>",
            "me@x.com, Other <o@x.com>",
            "c@x.com, ME@x.com",
            "me@x.com",
        );
        assert_eq!(to, vec!["s@x.com"]);
        assert_eq!(cc, vec!["o@x.com", "c@x.com"]);
    }

    #[test]
    fn thread_message_json_minimal_has_no_body() {
        let m = sample();
        let j = thread_message_json(&m, false);
        assert_eq!(j["body"], "");
        assert_eq!(
            j["attachments"][0],
            json!({"filename": "a.pdf", "mimeType": "application/pdf", "size": 2048})
        );
        assert_eq!(thread_message_json(&m, true)["body"], "plain ✓");
    }
}
