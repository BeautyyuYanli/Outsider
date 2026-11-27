use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const REPLACEMENT: &[u8] = b"[REDACTED:OUTSIDER]";
const MIN_NEEDLE_LEN: usize = 3;

/// Builds raw, trimmed, Base64, Base64URL, and URL-encoded needles to redact from child output.
pub fn build_needles(secret: &str) -> Vec<Vec<u8>> {
    let mut raw_variants = Vec::new();
    raw_variants.push(secret.to_string());
    let trimmed = secret.trim();
    if !trimmed.is_empty() && trimmed != secret {
        raw_variants.push(trimmed.to_string());
    }

    let mut needles: Vec<Vec<u8>> = Vec::new();
    let mut push_unique = |bytes: Vec<u8>| {
        if bytes.len() >= MIN_NEEDLE_LEN && !needles.contains(&bytes) {
            needles.push(bytes);
        }
    };

    for v in &raw_variants {
        push_unique(v.as_bytes().to_vec());
        push_unique(STANDARD.encode(v.as_bytes()).into_bytes());
        push_unique(URL_SAFE_NO_PAD.encode(v.as_bytes()).into_bytes());
        let url_upper = url_encode(v.as_bytes(), true);
        push_unique(url_upper);
        let url_lower = url_encode(v.as_bytes(), false);
        push_unique(url_lower);
    }

    // Match longest needles first so encoded/full forms take precedence over shorter substrings.
    needles.sort_by(|a, b| b.len().cmp(&a.len()));
    needles
}

fn url_encode(bytes: &[u8], uppercase: bool) -> Vec<u8> {
    let hex_chars = if uppercase {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex_chars[(b >> 4) as usize]);
            out.push(hex_chars[(b & 0x0f) as usize]);
        }
    }
    out
}

/// Streams bytes from `reader` to `writer`, replacing any occurrence of `needles` even across chunk boundaries.
pub async fn pump_redacted<R, W>(
    mut reader: R,
    mut writer: W,
    needles: Vec<Vec<u8>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_len = needles.iter().map(|n| n.len()).max().unwrap_or(0);
    let mut read_buf = [0u8; 4096];
    let mut pending: Vec<u8> = Vec::new();

    loop {
        let n = reader.read(&mut read_buf).await?;
        if n == 0 {
            break;
        }
        if max_len == 0 {
            writer.write_all(&read_buf[..n]).await?;
            writer.flush().await?;
            continue;
        }

        pending.extend_from_slice(&read_buf[..n]);
        let keep_tail = max_len.saturating_sub(1);
        let (out, rem) = redact_slice(&pending, &needles, keep_tail);
        if !out.is_empty() {
            writer.write_all(&out).await?;
            writer.flush().await?;
        }
        pending = rem;
    }

    if !pending.is_empty() {
        let (out, _) = redact_slice(&pending, &needles, 0);
        if !out.is_empty() {
            writer.write_all(&out).await?;
            writer.flush().await?;
        }
    }
    Ok(())
}

fn redact_slice(buf: &[u8], needles: &[Vec<u8>], keep_tail: usize) -> (Vec<u8>, Vec<u8>) {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    let safe_limit = buf.len().saturating_sub(keep_tail);

    while i < safe_limit {
        let mut matched_len = 0;
        for needle in needles {
            if buf[i..].starts_with(needle) {
                matched_len = needle.len();
                break;
            }
        }
        if matched_len > 0 {
            out.extend_from_slice(REPLACEMENT);
            i += matched_len;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }

    (out, buf[i..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        idx: usize,
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.idx >= self.chunks.len() {
                return Poll::Ready(Ok(()));
            }
            let idx = self.idx;
            self.idx += 1;
            buf.put_slice(&self.chunks[idx]);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn redacts_raw_base64_and_split_chunks() {
        let secret = "s3cr3t/p@ss+1";
        let needles = build_needles(secret);
        let b64 = STANDARD.encode(secret.as_bytes());
        let full = format!("start {secret} middle {b64} end");

        // Split into tiny 4-byte chunks to force boundary crossings.
        let chunks: Vec<Vec<u8>> = full.as_bytes().chunks(4).map(|c| c.to_vec()).collect();
        let reader = ChunkedReader { chunks, idx: 0 };
        let mut output = Vec::new();
        pump_redacted(reader, &mut output, needles).await.unwrap();

        let text = String::from_utf8(output).unwrap();
        assert_eq!(text, "start [REDACTED:OUTSIDER] middle [REDACTED:OUTSIDER] end");
    }
}
