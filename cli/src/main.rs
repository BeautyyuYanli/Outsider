mod client;
mod config;
mod handoff;
mod proto;
mod redact;

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use crate::client::RelayClient;
use crate::config::{
    default_identity_key_path, expand_tilde, load_config, load_identity_key, save_config,
    save_identity_key, ClientConfig,
};
use crate::handoff::{execute_target, HandoffMode};
use crate::proto::context::{slugify_name, RequestContext};
use crate::proto::identity::IdentityKey;

#[derive(Parser)]
#[command(
    name = "outsider",
    version,
    about = "End-to-end encrypted out-of-band secret handoff CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Ed25519 identity key & config.toml, printing relay.toml snippet
    Init(InitArgs),
    /// Show device Ed25519 public key, fingerprint, and relay.toml snippet
    Id,
    /// Check local config, relay connectivity, and Ed25519 allowlist status
    Doctor,
    /// Request secret approval and execute target command without exposing plaintext
    Run(RunArgs),
}

#[derive(Args)]
struct InitArgs {
    /// Relay base URL (e.g. https://relay.example.com)
    #[arg(long)]
    relay: String,
    /// Human-readable device name for relay.toml & approval page
    #[arg(long)]
    name: String,
    /// Overwrite existing identity key and config
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct RunArgs {
    /// Secret name (also normalized into approval URL path slug for Bitwarden matching)
    #[arg(long)]
    name: String,

    /// Human-readable reason shown on notification and approval page
    #[arg(long, default_value = "")]
    reason: String,

    /// Approval timeout in seconds
    #[arg(long)]
    timeout: Option<u32>,

    /// Inject secret into environment variable (`VAR` or `VAR=prefix_{{secret}}`)
    #[arg(long, group = "handoff")]
    env: Option<String>,

    /// Inject secret into child process stdin via anonymous pipe
    #[arg(long, group = "handoff")]
    stdin: bool,

    /// Custom stdin template containing `{{secret}}` (requires --stdin)
    #[arg(long, requires = "stdin")]
    stdin_template: Option<String>,

    /// Do not append trailing newline when using --stdin
    #[arg(long, requires = "stdin")]
    no_stdin_newline: bool,

    /// Write secret to 0600 memory temp file and replace `{{file}}` in target command
    #[arg(long, group = "handoff")]
    file: bool,

    /// Write secret to 0600 memory temp file and pass its path in the given env var
    #[arg(long, group = "handoff")]
    file_env: Option<String>,

    /// Provide secret via SSH_ASKPASS / GIT_ASKPASS / SUDO_ASKPASS one-shot IPC
    #[arg(long, group = "handoff")]
    askpass: bool,

    /// Replace placeholder in target command arguments (legacy fallback; visible in `ps`)
    #[arg(long, group = "handoff")]
    arg_placeholder: Option<String>,

    /// Disable streaming redaction of child stdout/stderr
    #[arg(long)]
    no_redact: bool,

    /// Target command and arguments (after `--`)
    #[arg(last = true, required = true)]
    target: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Handle self-invocation by ssh/git/sudo when running in --askpass mode.
    handoff::askpass::maybe_run_askpass_helper();

    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Init(args) => cmd_init(args),
        Commands::Id => cmd_id(),
        Commands::Doctor => cmd_doctor().await,
        Commands::Run(args) => cmd_run(args).await,
    };
    ExitCode::from((code & 0xff) as u8)
}

fn print_relay_snippet(device_name: &str, id: &IdentityKey) {
    let fp = id.fingerprint();
    let pk = id.public_key_b64u();
    println!("Device Name : {device_name}");
    println!("Device FP   : {fp}");
    println!("Public Key  : {pk}");
    println!();
    println!("# Paste into relay.toml:");
    println!("[[trusted_clients]]");
    println!("name = {:?}", device_name);
    println!("public_key = {:?}", pk);
}

fn cmd_init(args: InitArgs) -> i32 {
    let relay = args.relay.trim().trim_end_matches('/').to_string();
    let device_name = args.name.trim().to_string();
    if relay.is_empty() || (!relay.starts_with("http://") && !relay.starts_with("https://")) {
        eprintln!("[outsider] Error: --relay must be an http(s):// URL");
        return 100;
    }
    if device_name.is_empty() {
        eprintln!("[outsider] Error: --name cannot be empty");
        return 100;
    }

    let key_path = match default_identity_key_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[outsider] Error: {e}");
            return 100;
        }
    };

    if key_path.exists() && !args.force {
        eprintln!(
            "[outsider] Error: identity key already exists at {} (use --force to overwrite)",
            key_path.display()
        );
        return 100;
    }

    let id = IdentityKey::generate();
    if let Err(e) = save_identity_key(&key_path, &id) {
        eprintln!("[outsider] Error: {e}");
        return 100;
    }

    let cfg = ClientConfig {
        relay_url: relay,
        device_name: device_name.clone(),
        identity_key_path: key_path.to_string_lossy().to_string(),
        default_timeout_secs: 120,
        default_redact: true,
    };
    let cfg_path = match save_config(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[outsider] Error: {e}");
            return 100;
        }
    };

    eprintln!("[outsider] Saved config: {}", cfg_path.display());
    eprintln!("[outsider] Saved identity key (0600): {}", key_path.display());
    print_relay_snippet(&device_name, &id);
    0
}

fn cmd_id() -> i32 {
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[outsider] Error: {e}");
            return 100;
        }
    };
    let key_path = match expand_tilde(&cfg.identity_key_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[outsider] Error: {e}");
            return 100;
        }
    };
    let id = match load_identity_key(&key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[outsider] Error: {e}");
            return 100;
        }
    };

    print_relay_snippet(&cfg.device_name, &id);
    0
}

async fn cmd_doctor() -> i32 {
    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[outsider] Config error: {e}");
            return 100;
        }
    };
    let key_path = match expand_tilde(&cfg.identity_key_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[outsider] Config error: {e}");
            return 100;
        }
    };
    let id = match load_identity_key(&key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[outsider] Identity key error: {e}");
            return 100;
        }
    };

    println!("Config      : OK ({})", cfg.relay_url);
    println!("Identity    : OK (FP: {})", id.fingerprint());

    let client = match RelayClient::new(&cfg.relay_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[outsider] Client init error: {e}");
            return 100;
        }
    };

    if let Err(e) = client.healthz().await {
        eprintln!("[outsider] Relay /healthz failed: {}", e.message());
        return e.exit_code();
    }
    println!("Relay Health: OK");

    match client.doctor(&id).await {
        Ok(res) if res.ok => {
            println!("Relay Auth  : OK (trusted as {:?})", res.client_name);
            0
        }
        Ok(_) => {
            eprintln!("[outsider] Relay auth returned not ok");
            101
        }
        Err(e) => {
            eprintln!("[outsider] Relay auth check failed: {}", e.message());
            e.exit_code()
        }
    }
}

fn summarize_command(argv: &[String]) -> String {
    let joined = argv.join(" ");
    let max_chars = 240;
    if joined.chars().count() <= max_chars {
        joined
    } else {
        let mut s: String = joined.chars().take(max_chars - 1).collect();
        s.push('…');
        s
    }
}

fn resolve_handoff_mode(args: &RunArgs) -> Result<HandoffMode, String> {
    if let Some(spec) = &args.env {
        return Ok(HandoffMode::Env { spec: spec.clone() });
    }
    if args.stdin {
        return Ok(HandoffMode::Stdin {
            template: args.stdin_template.clone(),
            no_newline: args.no_stdin_newline,
        });
    }
    if args.file {
        if !args.target.iter().any(|a| a.contains("{{file}}")) {
            return Err(
                "--file requires `{{file}}` placeholder in target command (or use --file-env VAR)"
                    .to_string(),
            );
        }
        return Ok(HandoffMode::File { env_var: None });
    }
    if let Some(var) = &args.file_env {
        if var.trim().is_empty() {
            return Err("--file-env variable name cannot be empty".to_string());
        }
        return Ok(HandoffMode::File {
            env_var: Some(var.clone()),
        });
    }
    if args.askpass {
        return Ok(HandoffMode::Askpass);
    }
    if let Some(placeholder) = &args.arg_placeholder {
        if !args.target.iter().any(|a| a.contains(placeholder)) {
            return Err(format!(
                "placeholder `{placeholder}` not found in target command arguments"
            ));
        }
        return Ok(HandoffMode::ArgPlaceholder {
            placeholder: placeholder.clone(),
        });
    }
    Err(
        "must specify one handoff mode: --env, --stdin, --file, --file-env, --askpass, or --arg-placeholder"
            .to_string(),
    )
}

async fn cmd_run(args: RunArgs) -> i32 {
    if args.name.trim().is_empty() {
        eprintln!("[outsider] Error: --name cannot be empty");
        return 100;
    }

    let mode = match resolve_handoff_mode(&args) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[outsider] Argument error: {e}");
            return 100;
        }
    };

    let cfg = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[outsider] Config error: {e}");
            return 100;
        }
    };
    let key_path = match expand_tilde(&cfg.identity_key_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[outsider] Config error: {e}");
            return 100;
        }
    };
    let id = match load_identity_key(&key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[outsider] Identity key error: {e}");
            return 100;
        }
    };

    let client = match RelayClient::new(&cfg.relay_url) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[outsider] Error: {e}");
            return 100;
        }
    };

    let ttl = args.timeout.unwrap_or(cfg.default_timeout_secs);
    let redact = if args.no_redact {
        false
    } else {
        cfg.default_redact
    };

    let _slug = slugify_name(&args.name);
    let ctx = RequestContext {
        name: args.name.clone(),
        reason: args.reason.clone(),
        command_summary: summarize_command(&args.target),
    };

    let secret = match client.request_secret(&id, ctx, ttl).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[outsider] {}", e.message());
            return e.exit_code();
        }
    };

    match execute_target(mode, secret, &args.target, redact).await {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("[outsider] Execution error: {e}");
            100
        }
    }
}
