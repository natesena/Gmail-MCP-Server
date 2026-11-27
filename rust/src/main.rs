use anyhow::{bail, Result};
use gmail_mcp::accounts::{Accounts, Endpoints};
use gmail_mcp::config::{self, ConfigInputs};
use gmail_mcp::handlers::Server;
use gmail_mcp::{auth, mcp, scopes, tools};
use std::collections::HashMap;
use std::sync::Arc;

const HELP: &str = "\
gmail-mcp: Gmail MCP server (stdio). One process can serve several accounts.

USAGE:
  gmail-mcp [OPTIONS]                       run the MCP server on stdio
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

async fn real_main() -> Result<()> {
    let cli = parse_cli(std::env::args().skip(1).collect())?;
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
        accounts,
        prefix: cli.prefix,
    });
    mcp::serve(server, tokio::io::stdin(), tokio::io::stdout()).await?;
    Ok(())
}
