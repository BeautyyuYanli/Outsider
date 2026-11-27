pub fn apply_arg_placeholder(
    argv: &mut [String],
    placeholder: &str,
    secret: &str,
) -> Result<(), String> {
    if placeholder.is_empty() {
        return Err("--arg-placeholder cannot be empty".to_string());
    }
    let mut replaced = false;
    for arg in argv.iter_mut() {
        if arg.contains(placeholder) {
            *arg = arg.replace(placeholder, secret);
            replaced = true;
        }
    }
    if !replaced {
        return Err(format!(
            "placeholder `{placeholder}` not found in target command arguments"
        ));
    }
    eprintln!(
        "[outsider] Warning: passing secret via command-line arguments may be visible in process listings (ps)."
    );
    Ok(())
}
