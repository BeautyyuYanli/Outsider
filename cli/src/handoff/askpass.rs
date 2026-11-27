use std::io::Write;
use zeroize::Zeroizing;

const ENV_SOCK: &str = "_OUTSIDER_ASKPASS_SOCK";
const ENV_TOKEN: &str = "_OUTSIDER_ASKPASS_TOKEN";

/// If invoked by `ssh` / `git` / `sudo` as an ASKPASS program, fetch the secret over the private
/// Unix socket, print it to stdout for the calling tool, and exit immediately.
pub fn maybe_run_askpass_helper() {
    let (Some(sock_path), Some(token)) = (std::env::var_os(ENV_SOCK), std::env::var_os(ENV_TOKEN))
    else {
        return;
    };

    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let token_str = token.to_string_lossy();
        let mut stream = match UnixStream::connect(&sock_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[outsider-askpass] connect failed: {e}");
                std::process::exit(1);
            }
        };
        if stream
            .write_all(format!("{token_str}\n").as_bytes())
            .and_then(|_| stream.flush())
            .is_err()
        {
            std::process::exit(1);
        }
        let mut buf = Zeroizing::new(Vec::new());
        if stream.read_to_end(&mut buf).is_err() {
            std::process::exit(1);
        }
        let mut stdout = std::io::stdout().lock();
        if stdout.write_all(&buf).and_then(|_| stdout.flush()).is_err() {
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    #[cfg(not(unix))]
    {
        let _ = (sock_path, token);
        eprintln!("[outsider-askpass] --askpass is only supported on Unix platforms");
        std::process::exit(1);
    }
}

pub struct AskpassGuard {
    #[cfg(unix)]
    dir: std::path::PathBuf,
    #[cfg(unix)]
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for AskpassGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            self.handle.abort();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(unix)]
pub async fn start_askpass_server(
    secret: Zeroizing<String>,
) -> Result<(AskpassGuard, Vec<(String, String)>), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rand::RngCore;
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot locate current outsider binary for --askpass: {e}"))?;

    let mut dir_rnd = [0u8; 12];
    let mut tok_rnd = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dir_rnd);
    rand::rngs::OsRng.fill_bytes(&mut tok_rnd);

    let base_dir = {
        #[cfg(target_os = "linux")]
        {
            let shm = std::path::Path::new("/dev/shm");
            if shm.is_dir() {
                shm.to_path_buf()
            } else {
                std::env::temp_dir()
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::env::temp_dir()
        }
    };

    let dir = base_dir.join(format!("outsider-askpass-{}", URL_SAFE_NO_PAD.encode(dir_rnd)));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create askpass dir: {e}"))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod askpass dir: {e}"))?;

    let sock_path = dir.join("askpass.sock");
    let listener =
        UnixListener::bind(&sock_path).map_err(|e| format!("bind askpass socket: {e}"))?;
    std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod askpass socket: {e}"))?;

    let expected_token = Zeroizing::new(URL_SAFE_NO_PAD.encode(tok_rnd));
    let server_token = expected_token.clone();

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (reader, mut writer) = stream.into_split();
            let mut line = Zeroizing::new(String::new());
            let mut buf_reader = BufReader::new(reader);
            if buf_reader.read_line(&mut line).await.is_ok() {
                let got = line.trim_end_matches(&['\r', '\n'][..]);
                if constant_time_eq(got.as_bytes(), server_token.as_bytes()) {
                    let _ = writer.write_all(secret.as_bytes()).await;
                    let _ = writer.shutdown().await;
                }
            }
        }
    });

    let exe_str = exe.to_string_lossy().to_string();
    let mut envs = vec![
        ("SSH_ASKPASS".to_string(), exe_str.clone()),
        ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
        ("GIT_ASKPASS".to_string(), exe_str.clone()),
        ("SUDO_ASKPASS".to_string(), exe_str),
        (ENV_SOCK.to_string(), sock_path.to_string_lossy().to_string()),
        (ENV_TOKEN.to_string(), (*expected_token).clone()),
    ];
    if std::env::var_os("DISPLAY").is_none() {
        envs.push(("DISPLAY".to_string(), "outsider:0".to_string()));
    }

    Ok((AskpassGuard { dir, handle }, envs))
}

#[cfg(not(unix))]
pub async fn start_askpass_server(
    _secret: Zeroizing<String>,
) -> Result<(AskpassGuard, Vec<(String, String)>), String> {
    Err("--askpass is only supported on Unix platforms".to_string())
}

#[cfg(unix)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
