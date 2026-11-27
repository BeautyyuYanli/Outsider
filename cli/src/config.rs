use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::proto::identity::IdentityKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub relay_url: String,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    pub identity_key_path: String,
    #[serde(default = "default_timeout_secs")]
    pub default_timeout_secs: u32,
    #[serde(default = "default_redact")]
    pub default_redact: bool,
}

fn default_device_name() -> String {
    "outsider-client".to_string()
}

fn default_timeout_secs() -> u32 {
    120
}

fn default_redact() -> bool {
    true
}

pub fn config_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("OUTSIDER_CONFIG_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed).join("outsider"));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "cannot determine home directory (HOME/USERPROFILE unset)".to_string())?;
    Ok(PathBuf::from(home).join(".config").join("outsider"))
}

pub fn config_file_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn default_identity_key_path() -> Result<PathBuf, String> {
    Ok(config_dir()?.join("identity.key"))
}

pub fn expand_tilde(path: &str) -> Result<PathBuf, String> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| "cannot expand ~: HOME unset".to_string())?;
        return Ok(PathBuf::from(home).join(rest));
    }
    Ok(PathBuf::from(path))
}

pub fn load_config() -> Result<ClientConfig, String> {
    let path = config_file_path()?;
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e} (run `outsider init` first)", path.display()))?;
    let mut cfg: ClientConfig =
        toml::from_str(&raw).map_err(|e| format!("invalid config {}: {e}", path.display()))?;

    if let Ok(url) = std::env::var("OUTSIDER_RELAY_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            cfg.relay_url = trimmed.to_string();
        }
    }
    if let Ok(key_path) = std::env::var("OUTSIDER_IDENTITY_KEY") {
        let trimmed = key_path.trim();
        if !trimmed.is_empty() {
            cfg.identity_key_path = trimmed.to_string();
        }
    }

    cfg.relay_url = cfg.relay_url.trim_end_matches('/').to_string();
    if cfg.relay_url.is_empty() {
        return Err("relay_url is empty".to_string());
    }
    Ok(cfg)
}

pub fn save_config(cfg: &ClientConfig) -> Result<PathBuf, String> {
    let dir = config_dir()?;
    ensure_private_dir(&dir)?;
    let path = dir.join("config.toml");
    let content = toml::to_string_pretty(cfg).map_err(|e| format!("serialize config: {e}"))?;
    fs::write(&path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

pub fn save_identity_key(path: &Path, key: &IdentityKey) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let encoded = key.to_b64u();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        f.write_all(encoded.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        f.write_all(encoded.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    Ok(())
}

pub fn load_identity_key(path: &Path) -> Result<IdentityKey, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)
            .map_err(|e| format!("stat identity key {}: {e}", path.display()))?;
        let mode = meta.mode() & 0o777;
        if (mode & 0o077) != 0 {
            return Err(format!(
                "identity key {} has insecure permissions {:04o}; run `chmod 600 {}`",
                path.display(),
                mode,
                path.display()
            ));
        }
    }

    let raw = zeroize::Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| format!("read identity key {}: {e}", path.display()))?,
    );
    IdentityKey::from_b64u(&raw)
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 {}: {e}", dir.display()))?;
    }
    Ok(())
}
