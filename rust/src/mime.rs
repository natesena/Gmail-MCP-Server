//! RFC 822 message building (port of `src/utl.ts`, replacing nodemailer).
//!
//! Two builders, chosen like the Node server:
//!   - [`create_email_message`]: plain / simple-HTML mail, a faithful port of
//!     `createEmailMessage` (same header order, same mimeType rules);
//!   - [`create_raw_message`]: mail with file attachments and/or inline images
//!     (multipart/mixed > multipart/alternative > multipart/related).

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::Rng;
use serde::Deserialize;
use std::path::Path;

/// Upper bound on the decoded size of a base64 `content` inline image.
pub const MAX_INLINE_IMAGE_CONTENT_BYTES: usize = 10 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/x-icon",
];
const MIME_TYPES: &[&str] = &["text/plain", "text/html", "multipart/alternative"];

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InlineImage {
    pub cid: String,
    pub path: Option<String>,
    pub content: Option<String>,
    pub content_type: Option<String>,
    pub filename: Option<String>,
}

/// Arguments shared by send_email / draft_email / update_draft / reply_all.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EmailArgs {
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    pub from: Option<String>,
    pub html_body: Option<String>,
    pub mime_type: Option<String>,
    pub cc: Option<Vec<String>>,
    pub bcc: Option<Vec<String>>,
    pub thread_id: Option<String>,
    pub in_reply_to: Option<String>,
    /// Internal only (resolved from the thread); never taken from tool input.
    #[serde(skip_deserializing)]
    pub references: Option<String>,
    pub attachments: Option<Vec<String>>,
    pub inline_images: Option<Vec<InlineImage>>,
}

impl EmailArgs {
    /// The checks zod performed on parse.
    pub fn validate(&self) -> Result<()> {
        if let Some(m) = &self.mime_type {
            if !MIME_TYPES.contains(&m.as_str()) {
                bail!(
                    "Invalid mimeType {m:?}: expected one of {}",
                    MIME_TYPES.join(", ")
                );
            }
        }
        for img in self.inline_images.iter().flatten() {
            validate_inline_image(img)?;
        }
        Ok(())
    }
}

pub fn validate_inline_image(img: &InlineImage) -> Result<()> {
    if img.cid.is_empty()
        || img
            .cid
            .chars()
            .any(|c| c.is_whitespace() || c == '<' || c == '>')
    {
        bail!("cid must not contain whitespace or angle brackets");
    }
    let has_path = img.path.as_deref().is_some_and(|p| !p.is_empty());
    let has_content = img.content.as_deref().is_some_and(|c| !c.is_empty());
    if has_path as u8 + has_content as u8 != 1 {
        bail!("Each inline image must set exactly one of `path` or `content`");
    }
    if has_content && img.content_type.is_none() {
        bail!("`contentType` is required when an inline image uses `content`");
    }
    if let Some(ct) = &img.content_type {
        if !ALLOWED_IMAGE_TYPES.contains(&ct.as_str()) {
            bail!(
                "Unsupported inline image contentType {ct:?} (allowed: {}; SVG is intentionally unsupported)",
                ALLOWED_IMAGE_TYPES.join(", ")
            );
        }
    }
    Ok(())
}

/// RFC 2047 B-encoding when the text has non-ASCII characters.
pub fn encode_email_header(text: &str) -> String {
    if text.is_ascii() {
        text.to_string()
    } else {
        format!("=?UTF-8?B?{}?=", STANDARD.encode(text.as_bytes()))
    }
}

pub fn validate_email(email: &str) -> bool {
    // Same as /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let ok = |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c == '@');
    if !ok(local) || domain.contains('@') || domain.chars().any(char::is_whitespace) {
        return false;
    }
    // need some "x.y" split where both sides are non-empty
    domain
        .char_indices()
        .filter(|(_, c)| *c == '.')
        .any(|(i, _)| i > 0 && i + 1 < domain.len())
}

/// Strip CR, LF and NUL to prevent header injection.
pub fn sanitize_header_value(v: &str) -> String {
    v.chars()
        .filter(|c| !matches!(c, '\r' | '\n' | '\0'))
        .collect()
}

fn validate_recipients(to: &[String]) -> Result<()> {
    for e in to {
        if !validate_email(e) {
            bail!("Recipient email address is invalid: {e}");
        }
    }
    Ok(())
}

fn boundary() -> String {
    let n: u64 = rand::thread_rng().gen();
    format!("----=_NextPart_{n:016x}")
}

/// Port of `createEmailMessage`.
pub fn create_email_message(a: &EmailArgs) -> Result<String> {
    let encoded_subject = encode_email_header(&sanitize_header_value(&a.subject));
    let mut mime_type = a.mime_type.clone().unwrap_or_else(|| "text/plain".into());
    if a.html_body.is_some() && mime_type != "text/plain" {
        mime_type = "multipart/alternative".into();
    }
    let boundary = boundary();
    validate_recipients(&a.to)?;

    let join = |v: &Option<Vec<String>>| {
        v.as_ref()
            .map(|l| {
                l.iter()
                    .map(|s| sanitize_header_value(s))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    let from = sanitize_header_value(a.from.as_deref().unwrap_or("me"));
    let to = join(&Some(a.to.clone()));
    let cc = join(&a.cc);
    let bcc = join(&a.bcc);
    let in_reply_to = a
        .in_reply_to
        .as_deref()
        .map(sanitize_header_value)
        .unwrap_or_default();
    let references = a
        .references
        .as_deref()
        .or(a.in_reply_to.as_deref())
        .map(sanitize_header_value)
        .unwrap_or_default();

    let mut parts: Vec<String> = vec![format!("From: {from}"), format!("To: {to}")];
    if !cc.is_empty() {
        parts.push(format!("Cc: {cc}"));
    }
    if !bcc.is_empty() {
        parts.push(format!("Bcc: {bcc}"));
    }
    parts.push(format!("Subject: {encoded_subject}"));
    if !in_reply_to.is_empty() {
        parts.push(format!("In-Reply-To: {in_reply_to}"));
    }
    if !references.is_empty() {
        parts.push(format!("References: {references}"));
    }
    parts.push("MIME-Version: 1.0".into());

    let html = a.html_body.clone().unwrap_or_else(|| a.body.clone());
    match mime_type.as_str() {
        "multipart/alternative" => {
            parts.push(format!(
                "Content-Type: multipart/alternative; boundary=\"{boundary}\""
            ));
            parts.push(String::new());
            parts.push(format!("--{boundary}"));
            parts.push("Content-Type: text/plain; charset=UTF-8".into());
            parts.push("Content-Transfer-Encoding: 7bit".into());
            parts.push(String::new());
            parts.push(a.body.clone());
            parts.push(String::new());
            parts.push(format!("--{boundary}"));
            parts.push("Content-Type: text/html; charset=UTF-8".into());
            parts.push("Content-Transfer-Encoding: 7bit".into());
            parts.push(String::new());
            parts.push(html);
            parts.push(String::new());
            parts.push(format!("--{boundary}--"));
        }
        "text/html" => {
            parts.push("Content-Type: text/html; charset=UTF-8".into());
            parts.push("Content-Transfer-Encoding: 7bit".into());
            parts.push(String::new());
            parts.push(html);
        }
        _ => {
            parts.push("Content-Type: text/plain; charset=UTF-8".into());
            parts.push("Content-Transfer-Encoding: 7bit".into());
            parts.push(String::new());
            parts.push(a.body.clone());
        }
    }
    Ok(parts.join("\r\n"))
}

/// True when the message needs the multipart raw builder.
pub fn needs_raw_builder(a: &EmailArgs) -> bool {
    a.attachments.as_ref().is_some_and(|v| !v.is_empty())
        || a.inline_images.as_ref().is_some_and(|v| !v.is_empty())
}

fn wrap76(b64: &str) -> String {
    b64.as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Quote a MIME parameter, using RFC 2231 for non-ASCII values.
fn mime_param(name: &str, value: &str) -> String {
    let value = sanitize_header_value(value);
    if value.is_ascii() {
        format!(
            "{name}=\"{}\"",
            value.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        let enc: String = url::form_urlencoded::byte_serialize(value.as_bytes())
            .collect::<String>()
            .replace('+', "%20");
        format!("{name}*=UTF-8''{enc}")
    }
}

/// Encode an address list for a header: non-ASCII display names get RFC 2047.
fn encode_address_list(list: &[String]) -> String {
    list.iter()
        .map(|a| {
            let a = sanitize_header_value(a);
            if a.is_ascii() {
                return a;
            }
            match (a.rfind('<'), a.ends_with('>')) {
                (Some(i), true) => {
                    let name = a[..i].trim().trim_matches('"');
                    format!("{} {}", encode_email_header(name), &a[i..])
                }
                _ => a,
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn text_part(content_type: &str, body: &str) -> String {
    let simple = body.is_ascii() && body.lines().all(|l| l.len() <= 998);
    if simple {
        format!(
            "Content-Type: {content_type}; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n{}",
            body.replace("\r\n", "\n").replace('\n', "\r\n")
        )
    } else {
        format!(
            "Content-Type: {content_type}; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
            wrap76(&STANDARD.encode(body.as_bytes()))
        )
    }
}

fn multipart(kind: &str, parts: &[String]) -> String {
    let b = boundary();
    let mut out = format!("Content-Type: multipart/{kind}; boundary=\"{b}\"\r\n\r\n");
    for p in parts {
        out.push_str(&format!("--{b}\r\n{p}\r\n"));
    }
    out.push_str(&format!("--{b}--"));
    out
}

fn guess_type(name: &str) -> String {
    mime_guess::from_path(name)
        .first()
        .map(|m| m.essence_str().to_string())
        .unwrap_or_else(|| "application/octet-stream".into())
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

fn binary_part(
    content_type: &str,
    filename: &str,
    disposition: &str,
    cid: Option<&str>,
    data: &[u8],
) -> String {
    let mut h = format!(
        "Content-Type: {content_type}; {}\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: {disposition}; {}\r\n",
        mime_param("name", filename),
        mime_param("filename", filename)
    );
    if let Some(cid) = cid {
        h.push_str(&format!("Content-ID: <{cid}>\r\n"));
    }
    format!("{h}\r\n{}", wrap76(&STANDARD.encode(data)))
}

/// Multipart builder for attachments and inline images (replaces nodemailer).
pub fn create_raw_message(a: &EmailArgs) -> Result<String> {
    validate_recipients(&a.to)?;
    let inline = a.inline_images.clone().unwrap_or_default();
    if !inline.is_empty() && a.html_body.is_none() {
        bail!("inlineImages require htmlBody — a cid: reference only resolves from HTML content");
    }

    // Read attachments up front so a missing file fails before anything else.
    let mut attachment_parts = Vec::new();
    for p in a.attachments.iter().flatten() {
        let data = std::fs::read(p).map_err(|_| anyhow!("File does not exist: {p}"))?;
        let name = file_name(p);
        attachment_parts.push(binary_part(
            &guess_type(&name),
            &name,
            "attachment",
            None,
            &data,
        ));
    }

    let mut image_parts = Vec::new();
    for img in &inline {
        validate_inline_image(img)?;
        let cid = sanitize_header_value(&img.cid);
        if cid.is_empty() {
            bail!("Inline image cid must be a non-empty string");
        }
        let (data, filename) = if let Some(path) = img.path.as_deref().filter(|p| !p.is_empty()) {
            let data = std::fs::read(path)
                .map_err(|_| anyhow!("Inline image file does not exist: {path}"))?;
            (
                data,
                img.filename.clone().unwrap_or_else(|| file_name(path)),
            )
        } else {
            let content = img.content.clone().unwrap_or_default();
            if content.len() * 3 / 4 > MAX_INLINE_IMAGE_CONTENT_BYTES {
                bail!(
                    "Inline image '{cid}' exceeds the {} MB size limit",
                    MAX_INLINE_IMAGE_CONTENT_BYTES / (1024 * 1024)
                );
            }
            let cleaned: String = content.chars().filter(|c| !c.is_whitespace()).collect();
            let data = STANDARD
                .decode(cleaned.as_bytes())
                .map_err(|_| anyhow!("Inline image '{cid}' content is not valid base64"))?;
            (data, img.filename.clone().unwrap_or_else(|| cid.clone()))
        };
        let ct = img
            .content_type
            .clone()
            .unwrap_or_else(|| guess_type(&filename));
        image_parts.push(binary_part(&ct, &filename, "inline", Some(&cid), &data));
    }

    // Body: text, html (optionally related with images), alternative of both.
    let text = (!a.body.is_empty()).then(|| text_part("text/plain", &a.body));
    let html = a.html_body.as_ref().map(|h| {
        let html = text_part("text/html", h);
        if image_parts.is_empty() {
            html
        } else {
            let mut parts = vec![html];
            parts.extend(image_parts.iter().cloned());
            multipart("related", &parts)
        }
    });
    let body = match (text, html) {
        (Some(t), Some(h)) => multipart("alternative", &[t, h]),
        (Some(t), None) => t,
        (None, Some(h)) => h,
        (None, None) => text_part("text/plain", ""),
    };
    let content = if attachment_parts.is_empty() {
        body
    } else {
        let mut parts = vec![body];
        parts.extend(attachment_parts);
        multipart("mixed", &parts)
    };

    let mut headers = vec![
        format!(
            "From: {}",
            encode_address_list(&[a.from.clone().unwrap_or_else(|| "me".into())])
        ),
        format!("To: {}", encode_address_list(&a.to)),
    ];
    if let Some(cc) = a.cc.as_ref().filter(|v| !v.is_empty()) {
        headers.push(format!("Cc: {}", encode_address_list(cc)));
    }
    if let Some(bcc) = a.bcc.as_ref().filter(|v| !v.is_empty()) {
        headers.push(format!("Bcc: {}", encode_address_list(bcc)));
    }
    headers.push(format!(
        "Subject: {}",
        encode_email_header(&sanitize_header_value(&a.subject))
    ));
    if let Some(irt) = a.in_reply_to.as_deref().filter(|s| !s.is_empty()) {
        headers.push(format!("In-Reply-To: {}", sanitize_header_value(irt)));
    }
    if let Some(r) = a
        .references
        .as_deref()
        .or(a.in_reply_to.as_deref())
        .filter(|s| !s.is_empty())
    {
        headers.push(format!("References: {}", sanitize_header_value(r)));
    }
    headers.push("MIME-Version: 1.0".into());
    Ok(format!("{}\r\n{content}", headers.join("\r\n")))
}

/// Build the message with the right builder.
pub fn build_message(a: &EmailArgs) -> Result<String> {
    if needs_raw_builder(a) {
        create_raw_message(a)
    } else {
        create_email_message(a)
    }
}

/// base64url without padding, as Gmail's `raw` field expects.
pub fn encode_raw(message: &str) -> String {
    URL_SAFE_NO_PAD.encode(message.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        let head = raw.split("\r\n\r\n").next().unwrap_or("");
        head.split("\r\n")
            .find_map(|l| l.strip_prefix(&format!("{name}: ")))
    }

    fn base() -> EmailArgs {
        EmailArgs {
            to: vec!["a@example.com".into()],
            subject: "Hi".into(),
            body: "Body".into(),
            ..Default::default()
        }
    }

    // ---- utl.test.ts: threading headers
    #[test]
    fn uses_references_when_provided() {
        let mut a = base();
        a.in_reply_to = Some("<msg3@example.com>".into());
        a.references = Some("<msg1@example.com> <msg2@example.com> <msg3@example.com>".into());
        let raw = create_email_message(&a).unwrap();
        assert_eq!(
            header(&raw, "References"),
            Some("<msg1@example.com> <msg2@example.com> <msg3@example.com>")
        );
        assert_eq!(header(&raw, "In-Reply-To"), Some("<msg3@example.com>"));
    }

    #[test]
    fn references_fall_back_to_in_reply_to() {
        let mut a = base();
        a.in_reply_to = Some("<single@example.com>".into());
        let raw = create_email_message(&a).unwrap();
        assert_eq!(header(&raw, "References"), Some("<single@example.com>"));
    }

    #[test]
    fn new_email_has_no_threading_headers() {
        let raw = create_email_message(&base()).unwrap();
        assert_eq!(header(&raw, "References"), None);
        assert_eq!(header(&raw, "In-Reply-To"), None);
        assert_eq!(header(&raw, "From"), Some("me"));
    }

    #[test]
    fn raw_builder_uses_references_with_fallback() {
        let mut a = base();
        a.attachments = Some(vec![]);
        a.inline_images = Some(vec![InlineImage {
            cid: "x".into(),
            content: Some(STANDARD.encode(b"img")),
            content_type: Some("image/png".into()),
            ..Default::default()
        }]);
        a.html_body = Some("<img src=\"cid:x\">".into());
        a.in_reply_to = Some("<p@x>".into());
        let raw = create_raw_message(&a).unwrap();
        assert_eq!(header(&raw, "References"), Some("<p@x>"));
        a.references = Some("<a@x> <p@x>".into());
        let raw = create_raw_message(&a).unwrap();
        assert_eq!(header(&raw, "References"), Some("<a@x> <p@x>"));
    }

    #[test]
    fn crlf_injection_is_stripped_from_headers() {
        let mut a = base();
        a.subject = "Hi\r\nBcc: evil@x.com".into();
        a.cc = Some(vec!["c@x.com\r\nX-Injected: 1".into()]);
        let raw = create_email_message(&a).unwrap();
        assert!(!raw.contains("\r\nBcc: evil"));
        assert!(!raw.contains("\r\nX-Injected"));
        assert_eq!(header(&raw, "Subject"), Some("HiBcc: evil@x.com"));
    }

    #[test]
    fn non_ascii_subject_is_rfc2047_encoded() {
        let mut a = base();
        a.subject = "Héllo".into();
        let raw = create_email_message(&a).unwrap();
        assert_eq!(
            header(&raw, "Subject"),
            Some(format!("=?UTF-8?B?{}?=", STANDARD.encode("Héllo")).as_str())
        );
    }

    #[test]
    fn invalid_recipient_is_rejected() {
        let mut a = base();
        a.to = vec!["not-an-email".into()];
        assert!(create_email_message(&a)
            .unwrap_err()
            .to_string()
            .contains("Recipient email address is invalid"));
    }

    #[test]
    fn mime_type_rules_match_node() {
        // htmlBody with default mimeType stays text/plain (Node behaviour)
        let mut a = base();
        a.html_body = Some("<b>x</b>".into());
        let raw = create_email_message(&a).unwrap();
        assert!(raw.contains("Content-Type: text/plain"));
        assert!(!raw.contains("<b>x</b>"));
        a.mime_type = Some("text/html".into());
        let raw = create_email_message(&a).unwrap();
        assert!(
            raw.contains("multipart/alternative"),
            "html + non-plain => alternative"
        );
        assert!(raw.contains("<b>x</b>") && raw.contains("Body"));
        let mut b = base();
        b.mime_type = Some("text/html".into());
        let raw = create_email_message(&b).unwrap();
        assert!(raw.contains("Content-Type: text/html"));
    }

    #[test]
    fn validate_email_matches_regex() {
        assert!(validate_email("a@b.co"));
        assert!(!validate_email("a@b"));
        assert!(!validate_email("a b@c.d"));
        assert!(!validate_email("Name <a@b.com>"));
        assert!(!validate_email("a@.com"));
    }

    // ---- inline-images.test.ts
    fn png_file() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("logo.png");
        std::fs::write(&p, b"\x89PNG fake").unwrap();
        (dir, p.display().to_string())
    }

    fn html_args() -> EmailArgs {
        let mut a = base();
        a.html_body = Some("<p>hi</p><img src=\"cid:logo1\">".into());
        a
    }

    fn img_path(cid: &str, path: &str) -> InlineImage {
        InlineImage {
            cid: cid.into(),
            path: Some(path.into()),
            ..Default::default()
        }
    }

    #[test]
    fn inline_path_emits_related_with_content_id() {
        let (_d, p) = png_file();
        let mut a = html_args();
        a.inline_images = Some(vec![img_path("logo1", &p)]);
        let raw = create_raw_message(&a).unwrap();
        assert!(raw.contains("Content-Type: multipart/related"));
        assert!(raw.contains("Content-ID: <logo1>"));
        assert!(raw.contains("Content-Disposition: inline"));
        assert!(raw.contains("Content-Type: image/png"));
        // keeps plain + html alternative
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("text/html") && raw.contains("text/plain"));
    }

    #[test]
    fn inline_base64_content_source() {
        let mut a = html_args();
        a.inline_images = Some(vec![InlineImage {
            cid: "logo1".into(),
            content: Some(STANDARD.encode(b"PNGDATA")),
            content_type: Some("image/png".into()),
            ..Default::default()
        }]);
        let raw = create_raw_message(&a).unwrap();
        assert!(raw.contains("multipart/related") && raw.contains("Content-ID: <logo1>"));
        assert!(raw.contains(&STANDARD.encode(b"PNGDATA")));
    }

    #[test]
    fn attachment_plus_inline_is_mixed() {
        let (d, p) = png_file();
        let pdf = d.path().join("doc.pdf");
        std::fs::write(&pdf, b"%PDF").unwrap();
        let mut a = html_args();
        a.inline_images = Some(vec![img_path("logo1", &p)]);
        a.attachments = Some(vec![pdf.display().to_string()]);
        let raw = create_raw_message(&a).unwrap();
        assert!(raw.contains("multipart/mixed") && raw.contains("multipart/related"));
        assert!(raw.contains("Content-Disposition: attachment; filename=\"doc.pdf\""));
        assert!(raw.contains("application/pdf"));
    }

    #[test]
    fn multiple_inline_images() {
        let (_d, p) = png_file();
        let mut a = html_args();
        a.inline_images = Some(vec![img_path("a", &p), img_path("b", &p)]);
        let raw = create_raw_message(&a).unwrap();
        assert!(raw.contains("Content-ID: <a>") && raw.contains("Content-ID: <b>"));
    }

    #[test]
    fn cid_with_crlf_is_rejected_and_never_injected() {
        let (_d, p) = png_file();
        let mut a = html_args();
        a.inline_images = Some(vec![img_path("x\r\nX-Injected: 1", &p)]);
        match create_raw_message(&a) {
            Ok(raw) => assert!(!raw.contains("\nX-Injected:")),
            Err(e) => assert!(e.to_string().contains("cid")),
        }
    }

    #[test]
    fn inline_errors() {
        let (_d, p) = png_file();
        let mut a = base();
        a.inline_images = Some(vec![img_path("logo1", &p)]);
        assert!(create_raw_message(&a)
            .unwrap_err()
            .to_string()
            .contains("require htmlBody"));

        let mut b = html_args();
        b.inline_images = Some(vec![img_path("logo1", "/no/such/file.png")]);
        assert!(create_raw_message(&b)
            .unwrap_err()
            .to_string()
            .contains("Inline image file does not exist"));

        let mut c = html_args();
        c.inline_images = Some(vec![InlineImage {
            cid: "big".into(),
            content: Some("A".repeat(MAX_INLINE_IMAGE_CONTENT_BYTES / 3 * 4 + 400)),
            content_type: Some("image/png".into()),
            ..Default::default()
        }]);
        assert!(create_raw_message(&c)
            .unwrap_err()
            .to_string()
            .contains("size limit"));

        let mut d = base();
        d.attachments = Some(vec!["/no/such.pdf".into()]);
        assert!(create_raw_message(&d)
            .unwrap_err()
            .to_string()
            .contains("File does not exist"));
    }

    #[test]
    fn html_only_body_with_inline_image() {
        let (_d, p) = png_file();
        let mut a = html_args();
        a.body = String::new();
        a.inline_images = Some(vec![img_path("logo1", &p)]);
        let raw = create_raw_message(&a).unwrap();
        assert!(raw.contains("multipart/related") && raw.contains("Content-ID: <logo1>"));
        assert!(!raw.contains("multipart/alternative"));
    }

    #[test]
    fn needs_raw_builder_cases() {
        assert!(!needs_raw_builder(&base()));
        let mut a = base();
        a.attachments = Some(vec!["/a.pdf".into()]);
        assert!(needs_raw_builder(&a));
        let mut b = base();
        b.inline_images = Some(vec![img_path("x", "/a.png")]);
        assert!(needs_raw_builder(&b));
        let mut c = base();
        c.attachments = Some(vec![]);
        c.inline_images = Some(vec![]);
        assert!(!needs_raw_builder(&c));
    }

    #[test]
    fn inline_image_schema_rules() {
        let ok = img_path("logo", "/abs/logo.png");
        assert!(validate_inline_image(&ok).is_ok());
        let content_ok = InlineImage {
            cid: "logo".into(),
            content: Some("AAAA".into()),
            content_type: Some("image/png".into()),
            ..Default::default()
        };
        assert!(validate_inline_image(&content_ok).is_ok());
        let both = InlineImage {
            content: Some("AAAA".into()),
            content_type: Some("image/png".into()),
            ..img_path("logo", "/a.png")
        };
        assert!(validate_inline_image(&both).is_err());
        assert!(validate_inline_image(&InlineImage {
            cid: "logo".into(),
            ..Default::default()
        })
        .is_err());
        let no_type = InlineImage {
            cid: "logo".into(),
            content: Some("AAAA".into()),
            ..Default::default()
        };
        assert!(validate_inline_image(&no_type).is_err());
        assert!(validate_inline_image(&img_path("bad cid", "/a.png")).is_err());
        assert!(validate_inline_image(&img_path("<bad>", "/a.png")).is_err());
        let svg = InlineImage {
            content_type: Some("image/svg+xml".into()),
            ..content_ok.clone()
        };
        assert!(validate_inline_image(&svg).is_err());
    }

    #[test]
    fn non_ascii_attachment_name_uses_rfc2231() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("résumé.txt");
        std::fs::write(&p, b"x").unwrap();
        let mut a = base();
        a.attachments = Some(vec![p.display().to_string()]);
        let raw = create_raw_message(&a).unwrap();
        assert!(raw.contains("filename*=UTF-8''r%C3%A9sum%C3%A9.txt"));
    }

    #[test]
    fn raw_encoding_is_base64url_unpadded() {
        let e = encode_raw("??>>");
        assert!(!e.contains('+') && !e.contains('/') && !e.ends_with('='));
    }
}
