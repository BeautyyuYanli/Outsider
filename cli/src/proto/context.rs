use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CONTEXT_DOMAIN: &[u8] = b"outsider-ctx-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestContext {
    pub name: String,
    pub reason: String,
    pub command_summary: String,
}

fn push_encoded_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

pub fn encode_context_bytes(ctx: &RequestContext) -> Vec<u8> {
    let cap = CONTEXT_DOMAIN.len()
        + 1
        + 12
        + ctx.name.len()
        + ctx.reason.len()
        + ctx.command_summary.len();
    let mut buf = Vec::with_capacity(cap);
    buf.extend_from_slice(CONTEXT_DOMAIN);
    buf.push(0x00);
    push_encoded_str(&mut buf, &ctx.name);
    push_encoded_str(&mut buf, &ctx.reason);
    push_encoded_str(&mut buf, &ctx.command_summary);
    buf
}

pub fn compute_context_hash(ctx: &RequestContext) -> [u8; 32] {
    let bytes = encode_context_bytes(ctx);
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

pub fn slugify_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    let truncated = if trimmed.len() > 64 {
        trimmed[..64].trim_end_matches('-')
    } else {
        trimmed
    };
    if truncated.is_empty() {
        "secret".to_string()
    } else {
        truncated.to_string()
    }
}
