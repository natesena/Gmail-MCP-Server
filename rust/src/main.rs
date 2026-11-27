use anyhow::{bail, Result};
use gmail_mcp::accounts::{Accounts, AccountsHandle, Endpoints};
use gmail_mcp::config::{self, ConfigInputs};
use gmail_mcp::handlers::Server;
use gmail_mcp::store::Store;
use gmail_mcp::{admin, http, store};
use gmail_mcp::{auth, mcp, scopes, tools};
use std::collections::HashMap;
use std::sync::Arc;

const HELP: &str = "\
gmail-mcp: Gmail MCP server (stdio). One process can serve several accounts.

USAGE:
  gmail-mcp [OPTIONS]                       run the MCP server on stdio (credential files)
  gmail-mcp serve [--http ADDR] [SERVE OPTIONS]
                                            serve accounts from the encrypted store
                                            (stdio, or Streamable HTTP with --http)
  gmail-mcp accounts import ALIAS DIR       add an account from an existing credentials dir
  gmail-mcp accounts add ALIAS [--scopes=a,b]
                                            sign in to a new account (paste-back flow)
  gmail-mcp accounts list | remove ALIAS | default ALIAS
  gmail-mcp store keygen                    print a new store key
  gmail-mcp store set-client FILE           store the OAuth client (gcp-oauth.keys.json)
  gmail-mcp auth [ACCOUNT] [CALLBACK_URL] [--scopes=a,b]
                                            authorize one account in the browser

OPTIONS:
  --account NAME=DIR      add an account whose files live in DIR
                          (gcp-oauth.keys.json + credentials.json); repeatable
  --config PATH           accounts file (default: $GMAIL_MCP_CONFIG, then
                          ~/.gmail-mcp/accounts.json if it exists)
  --default-account NAME  account used when a tool call omits `account`
  --tool-prefix PREFIX    prefix every tool name (also $GMAIL_MCP_TOOL_PREFIX)
  -h, --help              show this help
  -V, --version           show the version

STORE OPTIONS (serve, accounts, store):
  --store PATH            encrypted store (default: $GMAIL_MCP_STORE, else
                          ~/.gmail-mcp/store.json)
  --store-key-file PATH   32-byte key (default: $GMAIL_MCP_STORE_KEY_FILE, else
                          /run/secrets/gmail_store_key)

SERVE OPTIONS:
  --http ADDR             listen address (also $GMAIL_MCP_HTTP_ADDR), e.g. 127.0.0.1:8080
  --allow-login a,b       Tailscale logins allowed to call (also $GMAIL_MCP_ALLOWED_LOGINS)
  --bearer-tokens-file F  file with allowed bearer tokens, one per line
                          (also $GMAIL_MCP_BEARER_TOKENS_FILE)
  --insecure-no-auth      accept any caller (testing only)

With no accounts configured, it serves a single account from
$GMAIL_OAUTH_PATH / $GMAIL_CREDENTIALS_PATH or ~/.gmail-mcp/ (as before).
";

struct Cli {
    inputs: ConfigInputs,
    prefix: String,
    auth: bool,
    positionals: Vec<String>,
    scopes: Option<String>,
}

fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<Option<String>> {
    let a = &args[*i];
    if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
        return Ok(Some(v.to_string()));
    }
    if a == flag {
        *i += 1;
        return match args.get(*i) {
            Some(v) => Ok(Some(v.clone())),
            None => bail!("{flag} needs a value"),
        };
    }
    Ok(None)
}

fn parse_cli(args: Vec<String>) -> Result<Cli> {
    let env: HashMap<String, String> = std::env::vars().collect();
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let prefix =
        tools::resolve_tool_prefix(&args, env.get("GMAIL_MCP_TOOL_PREFIX").map(String::as_str));
    let mut cli = Cli {
        inputs: ConfigInputs {
            env,
            home,
            ..Default::default()
        },
        prefix,
        auth: false,
        positionals: Vec::new(),
        scopes: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        if a == "-h" || a == "--help" {
            print!("{HELP}");
            std::process::exit(0);
        }
        if a == "-V" || a == "--version" {
            println!("gmail-mcp {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        if let Some(v) = take_value(&args, &mut i, "--account")? {
            cli.inputs.account_flags.push(v);
        } else if let Some(v) = take_value(&args, &mut i, "--config")? {
            cli.inputs.config_flag = Some(v);
        } else if let Some(v) = take_value(&args, &mut i, "--default-account")? {
            cli.inputs.default_flag = Some(v);
        } else if take_value(&args, &mut i, "--tool-prefix")?.is_some() {
            // already resolved above
        } else if let Some(v) = a.strip_prefix("--scopes=") {
            cli.scopes = Some(v.to_string());
        } else if i == 0 && a == "auth" {
            cli.auth = true;
        } else if a.starts_with("--") {
            bail!("Unknown option {a}. See --help.");
        } else {
            cli.positionals.push(a);
        }
        i += 1;
    }
    Ok(cli)
}

async fn run_auth(cli: Cli, cfg: config::Config) -> Result<()> {
    let callback = cli
        .positionals
        .iter()
        .find(|p| p.starts_with("http://") || p.starts_with("https://"))
        .cloned()
        .unwrap_or_else(|| auth::DEFAULT_CALLBACK.to_string());
    let name = cli
        .positionals
        .iter()
        .find(|p| !(p.starts_with("http://") || p.starts_with("https://")))
        .cloned()
        .or(cfg.default_account.clone());
    let Some(name) = name else {
        bail!(
            "Several accounts are configured; say which to authorize: gmail-mcp auth <{}>",
            cfg.names().join("|")
        );
    };
    let Some(account) = cfg.get(&name) else {
        bail!(
            "Unknown account {name:?}. Configured accounts: {}",
            cfg.names().join(", ")
        );
    };
    let scope_list = match &cli.scopes {
        Some(s) => {
            let list = scopes::parse_scopes(s);
            let bad = scopes::invalid_scopes(&list);
            if !bad.is_empty() {
                bail!(
                    "Invalid scope(s): {}\nAvailable scopes: {}",
                    bad.join(", "),
                    scopes::available_scope_names().join(", ")
                );
            }
            list
        }
        None => {
            println!(
                "No --scopes flag specified, using defaults: {}",
                scopes::DEFAULT_SCOPES.join(", ")
            );
            println!("Tip: Use --scopes=gmail.readonly for read-only access");
            println!(
                "Available scopes: {}",
                scopes::available_scope_names().join(", ")
            );
            scopes::default_scopes()
        }
    };
    auth::authenticate(
        account,
        &scope_list,
        &callback,
        &Endpoints::from_env().token_url,
    )
    .await?;
    println!("Authentication completed successfully");
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = real_main().await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

struct Opts {
    flags: HashMap<String, String>,
    switches: Vec<String>,
    positionals: Vec<String>,
}

const VALUE_FLAGS: &[&str] = &[
    "--store",
    "--store-key-file",
    "--http",
    "--allow-login",
    "--bearer-tokens-file",
    "--tool-prefix",
    "--scopes",
    "--redirect",
];

fn parse_opts(args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        flags: HashMap::new(),
        switches: Vec::new(),
        positionals: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some((k, v)) = a.split_once('=').filter(|(k, _)| VALUE_FLAGS.contains(k)) {
            o.flags.insert(k.to_string(), v.to_string());
        } else if VALUE_FLAGS.contains(&a.as_str()) {
            i += 1;
            let v = args
                .get(i)
                .ok_or_else(|| anyhow::anyhow!("{a} needs a value"))?;
            o.flags.insert(a.clone(), v.clone());
        } else if a.starts_with("--") {
            o.switches.push(a.clone());
        } else {
            o.positionals.push(a.clone());
        }
        i += 1;
    }
    Ok(o)
}

fn env_or(o: &Opts, flag: &str, env: &str) -> Option<String> {
    o.flags
        .get(flag)
        .cloned()
        .or_else(|| std::env::var(env).ok())
        .filter(|s| !s.is_empty())
}

fn open_store(o: &Opts) -> Result<Store> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let path = env_or(o, "--store", "GMAIL_MCP_STORE")
        .map(|p| config::expand_tilde(&p, &home))
        .unwrap_or_else(|| home.join(".gmail-mcp").join("store.json"));
    let key = env_or(o, "--store-key-file", "GMAIL_MCP_STORE_KEY_FILE")
        .map(|p| config::expand_tilde(&p, &home))
        .unwrap_or_else(|| "/run/secrets/gmail_store_key".into());
    Store::open(path, &key)
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

async fn run_serve(o: Opts) -> Result<()> {
    let store = open_store(&o)?;
    let handle = AccountsHandle::from_store(store, Endpoints::from_env())?;
    let accounts = handle.get();
    if accounts.list.is_empty() {
        eprintln!("gmail-mcp: the store has no accounts yet; add one with `gmail-mcp accounts import` or `accounts add`");
    }
    for a in &accounts.list {
        match &a.load_error {
            Some(e) => eprintln!("gmail-mcp: account {:?} unavailable: {e}", a.name),
            None => eprintln!(
                "gmail-mcp: account {:?} ready (scopes: {})",
                a.name,
                a.scopes.join(", ")
            ),
        }
    }
    let prefix = tools::resolve_tool_prefix(
        &o.flags
            .get("--tool-prefix")
            .map(|p| vec![format!("--tool-prefix={p}")])
            .unwrap_or_default(),
        std::env::var("GMAIL_MCP_TOOL_PREFIX").ok().as_deref(),
    );
    let server = Arc::new(Server {
        accounts: handle,
        prefix,
    });
    match env_or(&o, "--http", "GMAIL_MCP_HTTP_ADDR") {
        Some(addr) => {
            let bearer_tokens =
                match env_or(&o, "--bearer-tokens-file", "GMAIL_MCP_BEARER_TOKENS_FILE") {
                    Some(f) => split_list(
                        &std::fs::read_to_string(&f)
                            .map_err(|e| anyhow::anyhow!("cannot read {f}: {e}"))?,
                    ),
                    None => Vec::new(),
                };
            let auth = http::HttpAuth {
                allowed_logins: env_or(&o, "--allow-login", "GMAIL_MCP_ALLOWED_LOGINS")
                    .map(|s| split_list(&s))
                    .unwrap_or_default(),
                bearer_tokens,
                insecure_no_auth: o.switches.iter().any(|s| s == "--insecure-no-auth"),
            };
            http::serve(server, auth, &addr).await
        }
        None => Ok(mcp::serve(server, tokio::io::stdin(), tokio::io::stdout()).await?),
    }
}

async fn run_accounts(o: Opts) -> Result<()> {
    let store = open_store(&o)?;
    let endpoints = Endpoints::from_env();
    let pos = |i: usize, what: &str| -> Result<String> {
        o.positionals
            .get(i)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing {what}; see --help"))
    };
    match pos(0, "subcommand")?.as_str() {
        "list" => println!("{}", admin::list_text(&store)?),
        "import" => {
            let alias = pos(1, "ALIAS")?;
            let home = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            let dir = config::expand_tilde(&pos(2, "DIR")?, &home);
            let a = admin::import(&store, &alias, &dir, &endpoints).await?;
            println!(
                "Imported {} ({}) with scopes: {}",
                a.alias,
                a.email,
                a.scopes.join(", ")
            );
        }
        "add" => {
            let alias = pos(1, "ALIAS")?;
            let scope_list = o
                .flags
                .get("--scopes")
                .map(|s| scopes::parse_scopes(s))
                .unwrap_or_else(scopes::default_scopes);
            let redirect = o
                .flags
                .get("--redirect")
                .cloned()
                .unwrap_or_else(|| admin::PASTE_REDIRECT.to_string());
            let pending = admin::begin_add(&store, &scope_list, &redirect)?;
            println!("1. Open this link in any browser and approve access for the account to add as {alias:?}:\n\n{}\n", pending.url);
            println!("2. The browser then lands on a page that fails to load (localhost:8765). That's expected.");
            println!("   Copy that page's full address from the address bar and paste it here, then press Enter:");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let a = admin::finish_add(&store, &alias, &pending, &line, &endpoints).await?;
            println!(
                "Added {} ({}) with scopes: {}",
                a.alias,
                a.email,
                a.scopes.join(", ")
            );
        }
        "remove" => {
            let alias = pos(1, "ALIAS")?;
            admin::remove(&store, &alias)?;
            println!("Removed {alias}. (Revoke its access at myaccount.google.com/permissions if you're done with it.)");
        }
        "default" => {
            let alias = pos(1, "ALIAS")?;
            admin::set_default(&store, &alias)?;
            println!("Default account is now {alias}.");
        }
        other => bail!("unknown accounts subcommand {other:?}; see --help"),
    }
    Ok(())
}

async fn run_store(o: Opts) -> Result<()> {
    match o.positionals.first().map(String::as_str) {
        Some("keygen") => println!("{}", store::generate_key()),
        Some("set-client") => {
            let file = o
                .positionals
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("missing FILE"))?;
            let k = admin::set_client(&open_store(&o)?, std::path::Path::new(file))?;
            println!("Stored OAuth client {}", k.client_id);
        }
        _ => bail!("usage: gmail-mcp store keygen | set-client FILE"),
    }
    Ok(())
}

async fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|a| a == "-h" || a == "--help") {
        match args.first().map(String::as_str) {
            Some("serve") => return run_serve(parse_opts(&args[1..])?).await,
            Some("accounts") => return run_accounts(parse_opts(&args[1..])?).await,
            Some("store") => return run_store(parse_opts(&args[1..])?).await,
            _ => {}
        }
    }
    let cli = parse_cli(args)?;
    let cfg = config::resolve(&cli.inputs)?;
    if cli.auth {
        return run_auth(cli, cfg).await;
    }
    let accounts = Accounts::load(&cfg, &Endpoints::from_env());
    for a in &accounts.list {
        match &a.load_error {
            Some(e) => eprintln!("gmail-mcp: account {:?} unavailable: {e}", a.name),
            None => eprintln!(
                "gmail-mcp: account {:?} ready (scopes: {})",
                a.name,
                a.scopes.join(", ")
            ),
        }
    }
    if accounts.list.iter().all(|a| a.load_error.is_some()) {
        bail!(
            "No usable Gmail account ({}). Run `gmail-mcp auth` first.",
            cfg.source
        );
    }
    let server = Arc::new(Server {
        accounts: accounts.into(),
        prefix: cli.prefix,
    });
    mcp::serve(server, tokio::io::stdin(), tokio::io::stdout()).await?;
    Ok(())
}
