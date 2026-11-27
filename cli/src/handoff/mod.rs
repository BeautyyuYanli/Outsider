pub mod arg;
pub mod askpass;
pub mod env;
pub mod file;
pub mod stdin;

use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

use crate::redact::{build_needles, pump_redacted};

pub enum HandoffMode {
    Env {
        spec: String,
    },
    Stdin {
        template: Option<String>,
        no_newline: bool,
    },
    File {
        env_var: Option<String>,
    },
    Askpass,
    ArgPlaceholder {
        placeholder: String,
    },
}

pub async fn execute_target(
    mode: HandoffMode,
    secret: Zeroizing<String>,
    command_args: &[String],
    redact_output: bool,
) -> Result<i32, String> {
    if command_args.is_empty() {
        return Err("missing target command after `--`".to_string());
    }

    let needles = if redact_output {
        build_needles(&secret)
    } else {
        Vec::new()
    };

    let mut argv = command_args.to_vec();
    let mut extra_envs: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut stdin_payload: Option<Zeroizing<Vec<u8>>> = None;
    let mut _file_guard: Option<file::SecretFileGuard> = None;
    let mut _askpass_guard: Option<askpass::AskpassGuard> = None;

    match mode {
        HandoffMode::Env { spec } => {
            let (k, v) = env::prepare_env(&spec, &secret)?;
            extra_envs.push((k, v));
        }
        HandoffMode::Stdin {
            template,
            no_newline,
        } => {
            stdin_payload = Some(stdin::prepare_stdin(
                &secret,
                template.as_deref(),
                no_newline,
            ));
        }
        HandoffMode::File { env_var } => {
            let guard = file::create_secret_file(&secret)?;
            let path_str = guard.path().to_string_lossy().to_string();
            if let Some(var) = env_var {
                extra_envs.push((var, Zeroizing::new(path_str)));
            } else {
                let replaced = file::replace_file_placeholder(&mut argv, &path_str);
                if !replaced {
                    return Err(
                        "--file requires `{{file}}` placeholder in target command (or use --file-env VAR)"
                            .to_string(),
                    );
                }
            }
            _file_guard = Some(guard);
        }
        HandoffMode::Askpass => {
            let (guard, envs) = askpass::start_askpass_server(secret.clone()).await?;
            for (k, v) in envs {
                extra_envs.push((k, Zeroizing::new(v)));
            }
            _askpass_guard = Some(guard);
        }
        HandoffMode::ArgPlaceholder { placeholder } => {
            arg::apply_arg_placeholder(&mut argv, &placeholder, &secret)?;
        }
    }

    // Secret is now transferred to handoff structures; drop our copy early.
    drop(secret);

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (k, v) in &extra_envs {
        cmd.env(k, &**v);
    }
    drop(extra_envs);

    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::inherit());
    }

    if redact_output {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn target command `{}`: {e}", argv[0]))?;

    if let Some(payload) = stdin_payload {
        if let Some(mut child_stdin) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = child_stdin.write_all(&payload).await;
                let _ = child_stdin.shutdown().await;
            });
        }
    }

    let stdout_task = if redact_output {
        let out_needles = needles.clone();
        child.stdout.take().map(|child_out| {
            tokio::spawn(async move {
                let _ = pump_redacted(child_out, tokio::io::stdout(), out_needles).await;
            })
        })
    } else {
        None
    };

    let stderr_task = if redact_output {
        let err_needles = needles;
        child.stderr.take().map(|child_err| {
            tokio::spawn(async move {
                let _ = pump_redacted(child_err, tokio::io::stderr(), err_needles).await;
            })
        })
    } else {
        None
    };

    let status = tokio::select! {
        res = child.wait() => res.map_err(|e| format!("failed waiting on target process: {e}"))?,
        _ = tokio::signal::ctrl_c() => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Ok(130);
        }
    };

    if let Some(t) = stdout_task {
        let _ = t.await;
    }
    if let Some(t) = stderr_task {
        let _ = t.await;
    }

    // Explicitly drop guards before returning so temp files & sockets are scrubbed immediately.
    drop(_file_guard);
    drop(_askpass_guard);

    Ok(status.code().unwrap_or(1))
}
