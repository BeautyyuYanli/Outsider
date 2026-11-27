use zeroize::Zeroizing;

/// Parses `--env VAR` or `--env VAR="prefix_{{secret}}"` and builds the key/value pair.
pub fn prepare_env(spec: &str, secret: &str) -> Result<(String, Zeroizing<String>), String> {
    if let Some((var, tmpl)) = spec.split_once('=') {
        let key = var.trim();
        if key.is_empty() {
            return Err("environment variable name cannot be empty".to_string());
        }
        if !tmpl.contains("{{secret}}") {
            return Err(format!(
                "--env template `{spec}` must contain `{{{{secret}}}}` placeholder"
            ));
        }
        let rendered = tmpl.replace("{{secret}}", secret);
        Ok((key.to_string(), Zeroizing::new(rendered)))
    } else {
        let key = spec.trim();
        if key.is_empty() {
            return Err("environment variable name cannot be empty".to_string());
        }
        Ok((key.to_string(), Zeroizing::new(secret.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_plain_and_template() {
        let (k, v) = prepare_env("PGPASSWORD", "s3cr3t").unwrap();
        assert_eq!(k, "PGPASSWORD");
        assert_eq!(*v, "s3cr3t");

        let (k2, v2) = prepare_env("AUTH=Bearer {{secret}}", "tok123").unwrap();
        assert_eq!(k2, "AUTH");
        assert_eq!(*v2, "Bearer tok123");

        assert!(prepare_env("AUTH=no_placeholder", "tok").is_err());
    }
}
