use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const REQUEST_DOMAIN: &[u8] = b"outsider-req-v1";
const FINGERPRINT_DOMAIN: &[u8] = b"outsider-id-fp-v1";
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub struct IdentityKey {
    signing: SigningKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_b64u(encoded: &str) -> Result<Self, String> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.trim())
                .map_err(|e| format!("invalid identity key encoding: {e}"))?,
        );
        if bytes.len() != 32 {
            return Err(format!(
                "identity key must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(*seed))
    }

    pub fn to_b64u(&self) -> Zeroizing<String> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        Zeroizing::new(URL_SAFE_NO_PAD.encode(&*seed))
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_key_b64u(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key_bytes())
    }

    pub fn fingerprint(&self) -> String {
        compute_fingerprint(&self.public_key_bytes())
    }

    pub fn sign_request(
        &self,
        pk_req: &[u8; 32],
        context_hash: &[u8; 32],
        request_ts: u64,
        ttl_secs: u32,
        request_nonce: &[u8; 16],
    ) -> [u8; 64] {
        let input = build_sign_input(
            &self.public_key_bytes(),
            pk_req,
            context_hash,
            request_ts,
            ttl_secs,
            request_nonce,
        );
        self.signing.sign(&input).to_bytes()
    }
}

pub fn build_sign_input(
    id_pk: &[u8; 32],
    pk_req: &[u8; 32],
    context_hash: &[u8; 32],
    request_ts: u64,
    ttl_secs: u32,
    request_nonce: &[u8; 16],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(REQUEST_DOMAIN.len() + 1 + 32 + 32 + 32 + 8 + 4 + 16);
    buf.extend_from_slice(REQUEST_DOMAIN);
    buf.push(0x00);
    buf.extend_from_slice(id_pk);
    buf.extend_from_slice(pk_req);
    buf.extend_from_slice(context_hash);
    buf.extend_from_slice(&request_ts.to_be_bytes());
    buf.extend_from_slice(&ttl_secs.to_be_bytes());
    buf.extend_from_slice(request_nonce);
    buf
}

#[allow(dead_code)]
pub fn verify_signature(
    id_pk: &[u8; 32],
    sign_input: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(id_pk).map_err(|e| format!("invalid id_pk: {e}"))?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(sign_input, &sig)
        .map_err(|e| format!("signature verification failed: {e}"))
}

pub fn compute_fingerprint(id_pk: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(id_pk);
    let digest = hasher.finalize();

    // First 5 bytes = 40 bits = 8 Base32 characters.
    let head = &digest[..5];
    let mut bits: u32 = 0;
    let mut value: u32 = 0;
    let mut chars = Vec::with_capacity(8);
    for &b in head {
        value = (value << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            let idx = ((value >> (bits - 5)) & 31) as usize;
            chars.push(BASE32_ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    let s: String = chars.into_iter().collect();
    format!("{}-{}", &s[..4], &s[4..8])
}
