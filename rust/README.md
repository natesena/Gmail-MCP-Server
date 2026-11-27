# gmail-mcp (Rust)

A Rust port of this Gmail MCP server in which **one process serves several Gmail accounts**.
It has the same 30 tools, the same schemas and the same output text as the Node server. In multi-account mode it adds an `account` argument and a `list_accounts` tool.

## Build

```bash
cd rust
cargo build --release        # -> target/release/gmail-mcp
```

## Accounts

Each account is a directory with the two files the Node server already uses:
`gcp-oauth.keys.json` (OAuth client) and `credentials.json` (tokens + scopes).
If you already run one Node instance per account, point at those directories.
No re-authentication is needed.

**With flags:**

```bash
gmail-mcp --account personal=~/.gmail-personal --account work=~/.gmail-work
```

**With an accounts file.** Pass `--config PATH` or set `$GMAIL_MCP_CONFIG`; otherwise the server uses `~/.gmail-mcp/accounts.json` if it exists:

```json
{
  "default": "personal",
  "accounts": {
    "personal": { "dir": "~/.gmail-personal" },
    "work": {
      "oauthPath": "~/.gmail-work/gcp-oauth.keys.json",
      "credentialsPath": "~/.gmail-work/credentials.json"
    }
  }
}
```

**With neither:** you get single-account mode, as before. It reads `$GMAIL_OAUTH_PATH` and `$GMAIL_CREDENTIALS_PATH`, or `~/.gmail-mcp/`. With one account the tool list is byte-for-byte the Node server's.

`--default-account NAME`, or `"default"` in the file, sets the account used when a call leaves out `account`. With two or more accounts and no default, `account` is required.

## How a client uses it

- `list_accounts` returns each account's name, email address, scopes and status.
- Every other tool takes `account` (an enum of the configured names). For example, `search_emails {"query": "is:unread", "account": "work"}`.
- Scopes are checked per account. A tool is listed if at least one account can use it, and its `account` enum lists only the accounts that can. A call is checked against the chosen account's scopes.
- Tokens refresh per account. A refreshed token is written back only to that account's `credentials.json` (mode 0600, same format as before).
- If one account fails to load (missing files, not authorized), the server still serves the others, and `list_accounts` shows the error.

## Authorizing an account

```bash
gmail-mcp --account work=~/.gmail-work auth work --scopes=gmail.modify,gmail.settings.basic
gmail-mcp auth                     # single-account mode, as before
gmail-mcp auth work https://example.com/oauth2callback   # custom callback
```

## Claude Code

This one entry replaces separate `gmail-personal` and `gmail-work` servers:

```bash
claude mcp add gmail -s user -- /path/to/gmail-mcp \
  --account personal=$HOME/.gmail-personal --account work=$HOME/.gmail-work
```

`--tool-prefix` and `$GMAIL_MCP_TOOL_PREFIX` still work the same way.

## Differences from the Node server

- Tool errors set `isError: true`. The text (`Error: ...`) is unchanged.
- `get_or_create_label` reports "created new" when it creates a label. The Node version always said "found existing".
- `reply_all` sends the full `References` chain. The Node version computed it but sent only `In-Reply-To`.
- The OAuth keys file is no longer copied from the current directory into `~/.gmail-mcp`. Point `--account` or `$GMAIL_OAUTH_PATH` at it instead.

## Tests

```bash
cargo test     # unit tests (ported vitest suites), tool-list parity with the
               # Node server, multi-account routing against a mock Gmail API,
               # and a stdio end-to-end run of the binary
cargo clippy --all-targets -- -D warnings
```

`tests/fixtures/ts-tools.json` is the Node server's `tools/list` output. Regenerate it after changing `src/tools.ts`, and update `src/tools.json` to match.
