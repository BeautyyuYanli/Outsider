use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;

pub struct SecretFileGuard {
    path: PathBuf,
    len: usize,
}

impl SecretFileGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        // Best-effort overwrite with zeros before unlinking.
        if let Ok(mut f) = OpenOptions::new().write(true).open(&self.path) {
            let zeros = vec![0u8; self.len.max(64)];
            let _ = f.write_all(&zeros);
            let _ = f.sync_all();
        }
        let _ = fs::remove_file(&self.path);
    }
}

fn preferred_temp_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let shm = Path::new("/dev/shm");
        if shm.is_dir() {
            if let Ok(meta) = fs::metadata(shm) {
                if !meta.permissions().readonly() {
                    return shm.to_path_buf();
                }
            }
        }
    }
    std::env::temp_dir()
}

pub fn create_secret_file(secret: &str) -> Result<SecretFileGuard, String> {
    let base_dir = preferred_temp_dir();
    let mut rnd = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let filename = format!("outsider-{}.key", URL_SAFE_NO_PAD.encode(rnd));
    let path = base_dir.join(filename);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts
        .open(&path)
        .map_err(|e| format!("create temp secret file {}: {e}", path.display()))?;
    f.write_all(secret.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| {
            let _ = fs::remove_file(&path);
            format!("write temp secret file {}: {e}", path.display())
        })?;

    Ok(SecretFileGuard {
        path,
        len: secret.len(),
    })
}

pub fn replace_file_placeholder(argv: &mut [String], file_path: &str) -> bool {
    let mut replaced = false;
    for arg in argv.iter_mut() {
        if arg.contains("{{file}}") {
            *arg = arg.replace("{{file}}", file_path);
            replaced = true;
        }
    }
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_file_created_and_cleaned_on_drop() {
        let path_copy;
        {
            let guard = create_secret_file("top-secret-pem").unwrap();
            path_copy = guard.path().to_path_buf();
            let content = fs::read_to_string(&path_copy).unwrap();
            assert_eq!(content, "top-secret-pem");
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let mode = fs::metadata(&path_copy).unwrap().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
        assert!(!path_copy.exists(), "temp file must be deleted on Drop");
    }
}
