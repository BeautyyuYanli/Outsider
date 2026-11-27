use zeroize::Zeroizing;

pub fn prepare_stdin(
    secret: &str,
    template: Option<&str>,
    no_newline: bool,
) -> Zeroizing<Vec<u8>> {
    let text = if let Some(tmpl) = template {
        tmpl.replace("\\n", "\n").replace("{{secret}}", secret)
    } else if no_newline || secret.ends_with('\n') {
        secret.to_string()
    } else {
        format!("{secret}\n")
    };
    Zeroizing::new(text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_variants() {
        assert_eq!(&*prepare_stdin("pw", None, false), b"pw\n");
        assert_eq!(&*prepare_stdin("pw", None, true), b"pw");
        assert_eq!(
            &*prepare_stdin("pw", Some("user\n{{secret}}\\n"), false),
            b"user\npw\n"
        );
    }
}
