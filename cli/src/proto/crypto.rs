use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::proto::api::Envelope;

const HKDF_INFO_PREFIX: &[u8] = b"outsider-v1-aead-key";
const AAD_PREFIX: &[u8] = b"outsider-v1";

pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn public_b64u(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public.as_bytes())
    }

    /// Consumes the ephemeral secret key (zeroized on Drop) and decrypts the envelope.
    pub fn decrypt_envelope(
        self,
        envelope: &Envelope,
        session_id: &str,
        context_hash: &[u8; 32],
    ) -> Result<Zeroizing<String>, String> {
        if envelope.v != 1 {
            return Err(format!("unsupported envelope version: {}", envelope.v));
        }
        let epk_vec = URL_SAFE_NO_PAD
            .decode(&envelope.epk)
            .map_err(|e| format!("invalid epk encoding: {e}"))?;
        if epk_vec.len() != 32 {
            return Err(format!("epk must be 32 bytes, got {}", epk_vec.len()));
        }
        let mut epk_arr = [0u8; 32];
        epk_arr.copy_from_slice(&epk_vec);

        let nonce_vec = URL_SAFE_NO_PAD
            .decode(&envelope.nonce)
            .map_err(|e| format!("invalid nonce encoding: {e}"))?;
        if nonce_vec.len() != 12 {
            return Err(format!("nonce must be 12 bytes, got {}", nonce_vec.len()));
        }

        let ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|e| format!("invalid ciphertext encoding: {e}"))?;

        let epk = PublicKey::from(epk_arr);
        let shared = self.secret.diffie_hellman(&epk);
        if !shared.was_contributory() {
            return Err("non-contributory X25519 shared secret".to_string());
        }

        let aead_key = derive_aead_key(
            shared.as_bytes(),
            session_id,
            self.public.as_bytes(),
            &epk_arr,
        )?;
        let aad = build_aad(session_id, context_hash);

        let cipher = Aes256Gcm::new_from_slice(&*aead_key)
            .map_err(|e| format!("failed to initialize AES-256-GCM: {e}"))?;
        let nonce = Nonce::from_slice(&nonce_vec);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| "AEAD decryption or AAD authentication failed".to_string())?,
        );

        let parsed: PlaintextPayload = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("invalid decrypted JSON payload: {e}"))?;
        if parsed.v != 1 {
            return Err(format!("unsupported plaintext version: {}", parsed.v));
        }
        Ok(Zeroizing::new(parsed.secret))
    }
}

#[derive(Deserialize)]
struct PlaintextPayload {
    v: u32,
    secret: String,
}

pub fn derive_aead_key(
    shared_secret: &[u8; 32],
    session_id: &str,
    pk_req: &[u8; 32],
    epk: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret);
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 64);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(pk_req);
    info.extend_from_slice(epk);

    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *out)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;
    Ok(out)
}

pub fn build_aad(session_id: &str, context_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 1 + session_id.len() + 1 + 32);
    aad.extend_from_slice(AAD_PREFIX);
    aad.push(0x00);
    aad.extend_from_slice(session_id.as_bytes());
    aad.push(0x00);
    aad.extend_from_slice(context_hash);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::context::{
        compute_context_hash, encode_context_bytes, slugify_name, RequestContext,
    };
    use crate::proto::identity::{
        build_sign_input, compute_fingerprint, verify_signature, IdentityKey,
    };
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    struct TestVectors {
        slug_cases: Vec<SlugCase>,
        identity: IdentityVec,
        context_vectors: Vec<ContextVec>,
        request_signature: ReqSigVec,
        e2ee: E2eeVec,
    }

    #[derive(Deserialize)]
    struct SlugCase {
        input: String,
        expected: String,
    }

    #[derive(Deserialize)]
    struct IdentityVec {
        seed_hex: String,
        id_pk_b64u: String,
        id_fp: String,
    }

    #[derive(Deserialize)]
    struct ContextVec {
        label: String,
        name: String,
        reason: String,
        command_summary: String,
        context_bytes_hex: String,
        context_hash_hex: String,
        context_hash_b64u: String,
    }

    #[derive(Deserialize)]
    struct ReqSigVec {
        context_label: String,
        id_pk_b64u: String,
        pk_req_b64u: String,
        request_ts: u64,
        ttl_secs: u32,
        request_nonce_b64u: String,
        sign_input_hex: String,
        sig_b64u: String,
    }

    #[derive(Deserialize)]
    struct E2eeVec {
        context_label: String,
        session_id: String,
        sk_req_hex: String,
        pk_req_b64u: String,
        epk_b64u: String,
        aead_key_hex: String,
        aad_hex: String,
        nonce_b64u: String,
        plaintext_json: String,
        ciphertext_b64u: String,
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn protocol_test_vectors_match() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("protocol")
            .join("test-vectors.json");
        let raw = std::fs::read_to_string(path).expect("read protocol/test-vectors.json");
        let v: TestVectors = serde_json::from_str(&raw).expect("parse test vectors");

        for sc in &v.slug_cases {
            assert_eq!(slugify_name(&sc.input), sc.expected, "slug {:?}", sc.input);
        }

        let seed: [u8; 32] = hex_decode(&v.identity.seed_hex).try_into().unwrap();
        let id = IdentityKey::from_seed(seed);
        assert_eq!(id.public_key_b64u(), v.identity.id_pk_b64u);
        assert_eq!(v.request_signature.id_pk_b64u, v.identity.id_pk_b64u);
        assert_eq!(v.e2ee.context_label, v.request_signature.context_label);
        assert_eq!(id.fingerprint(), v.identity.id_fp);
        assert_eq!(compute_fingerprint(&id.public_key_bytes()), v.identity.id_fp);

        let mut first_ctx_hash = [0u8; 32];
        for cv in &v.context_vectors {
            let ctx = RequestContext {
                name: cv.name.clone(),
                reason: cv.reason.clone(),
                command_summary: cv.command_summary.clone(),
            };
            assert_eq!(hex_encode(&encode_context_bytes(&ctx)), cv.context_bytes_hex);
            let h = compute_context_hash(&ctx);
            assert_eq!(hex_encode(&h), cv.context_hash_hex);
            assert_eq!(URL_SAFE_NO_PAD.encode(h), cv.context_hash_b64u);
            if cv.label == v.request_signature.context_label {
                first_ctx_hash = h;
            }
        }

        let pk_req: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&v.request_signature.pk_req_b64u)
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = URL_SAFE_NO_PAD
            .decode(&v.request_signature.request_nonce_b64u)
            .unwrap()
            .try_into()
            .unwrap();
        let sign_input = build_sign_input(
            &id.public_key_bytes(),
            &pk_req,
            &first_ctx_hash,
            v.request_signature.request_ts,
            v.request_signature.ttl_secs,
            &nonce,
        );
        assert_eq!(hex_encode(&sign_input), v.request_signature.sign_input_hex);

        let sig = id.sign_request(
            &pk_req,
            &first_ctx_hash,
            v.request_signature.request_ts,
            v.request_signature.ttl_secs,
            &nonce,
        );
        assert_eq!(URL_SAFE_NO_PAD.encode(sig), v.request_signature.sig_b64u);
        verify_signature(&id.public_key_bytes(), &sign_input, &sig).unwrap();

        // E2EE decryption vector.
        let sk_req: [u8; 32] = hex_decode(&v.e2ee.sk_req_hex).try_into().unwrap();
        let kp = EphemeralKeypair::from_bytes(sk_req);
        assert_eq!(kp.public_b64u(), v.e2ee.pk_req_b64u);
        assert_eq!(
            hex_encode(&build_aad(&v.e2ee.session_id, &first_ctx_hash)),
            v.e2ee.aad_hex
        );

        let epk_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&v.e2ee.epk_b64u)
            .unwrap()
            .try_into()
            .unwrap();
        let shared = kp.secret.diffie_hellman(&PublicKey::from(epk_bytes));
        let key = derive_aead_key(
            shared.as_bytes(),
            &v.e2ee.session_id,
            kp.public.as_bytes(),
            &epk_bytes,
        )
        .unwrap();
        assert_eq!(hex_encode(&*key), v.e2ee.aead_key_hex);

        let env = Envelope {
            v: 1,
            epk: v.e2ee.epk_b64u.clone(),
            nonce: v.e2ee.nonce_b64u.clone(),
            ciphertext: v.e2ee.ciphertext_b64u.clone(),
        };
        let secret = kp
            .decrypt_envelope(&env, &v.e2ee.session_id, &first_ctx_hash)
            .expect("decrypt test vector");
        let expected: PlaintextPayload = serde_json::from_str(&v.e2ee.plaintext_json).unwrap();
        assert_eq!(*secret, expected.secret);

        // Tampered AAD context hash must fail decryption.
        let mut wrong_hash = first_ctx_hash;
        wrong_hash[0] ^= 0xff;
        let kp2 = EphemeralKeypair::from_bytes(sk_req);
        assert!(kp2
            .decrypt_envelope(&env, &v.e2ee.session_id, &wrong_hash)
            .is_err());
    }
}
