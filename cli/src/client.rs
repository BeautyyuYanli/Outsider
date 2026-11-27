use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::StatusCode;
use zeroize::Zeroizing;

use crate::proto::api::{
    CreateRequestBody, CreateRequestResponse, DoctorResponse, ErrorBody, WaitResponse,
};
use crate::proto::context::{compute_context_hash, RequestContext};
use crate::proto::crypto::EphemeralKeypair;
use crate::proto::identity::IdentityKey;

#[derive(Debug)]
pub enum ClientError {
    RelayAuthOrNetwork(String), // exit 101
    ExpiredOrCancelled(String), // exit 102
    CryptoFailed(String),       // exit 103
}

impl ClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ClientError::RelayAuthOrNetwork(_) => 101,
            ClientError::ExpiredOrCancelled(_) => 102,
            ClientError::CryptoFailed(_) => 103,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            ClientError::RelayAuthOrNetwork(m)
            | ClientError::ExpiredOrCancelled(m)
            | ClientError::CryptoFailed(m) => m,
        }
    }
}

pub struct RelayClient {
    base_url: String,
    http: reqwest::Client,
}

impl RelayClient {
    pub fn new(base_url: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(40))
            .user_agent(concat!("outsider/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http,
        })
    }

    pub async fn healthz(&self) -> Result<(), ClientError> {
        let url = format!("{}/healthz", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::RelayAuthOrNetwork(format!("GET /healthz failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(ClientError::RelayAuthOrNetwork(format!(
                "GET /healthz returned HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn doctor(&self, id: &IdentityKey) -> Result<DoctorResponse, ClientError> {
        let kp = EphemeralKeypair::generate();
        let ctx = RequestContext {
            name: "__doctor__".to_string(),
            reason: "connectivity and signature check".to_string(),
            command_summary: String::new(),
        };
        let body = build_signed_body(id, &kp, ctx, 60)?;
        let url = format!("{}/v1/doctor", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClientError::RelayAuthOrNetwork(format!("POST /v1/doctor failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = extract_error(resp).await;
            return Err(ClientError::RelayAuthOrNetwork(format!(
                "POST /v1/doctor returned HTTP {status}: {detail}"
            )));
        }
        resp.json::<DoctorResponse>()
            .await
            .map_err(|e| ClientError::RelayAuthOrNetwork(format!("invalid /v1/doctor JSON: {e}")))
    }

    pub async fn request_secret(
        &self,
        id: &IdentityKey,
        ctx: RequestContext,
        ttl_secs: u32,
    ) -> Result<Zeroizing<String>, ClientError> {
        let kp = EphemeralKeypair::generate();
        let context_hash = compute_context_hash(&ctx);
        let body = build_signed_body(id, &kp, ctx.clone(), ttl_secs)?;

        let create_url = format!("{}/v1/requests", self.base_url);
        let resp = self
            .http
            .post(&create_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                ClientError::RelayAuthOrNetwork(format!("failed to reach relay {create_url}: {e}"))
            })?;

        if resp.status() != StatusCode::CREATED {
            let status = resp.status();
            let detail = extract_error(resp).await;
            return Err(ClientError::RelayAuthOrNetwork(format!(
                "relay rejected request (HTTP {status}): {detail}"
            )));
        }

        let created = resp.json::<CreateRequestResponse>().await.map_err(|e| {
            ClientError::RelayAuthOrNetwork(format!("invalid create response JSON: {e}"))
        })?;

        eprintln!(
            "[outsider] Waiting for approval: {} ({}s) | Device FP: {}",
            ctx.name,
            ttl_secs,
            id.fingerprint()
        );

        let wait_url = format!(
            "{}/v1/requests/{}/wait?timeout=25",
            self.base_url, created.session_id
        );

        loop {
            let poll_fut = self
                .http
                .get(&wait_url)
                .bearer_auth(&created.wait_token)
                .send();

            let resp = tokio::select! {
                res = poll_fut => res.map_err(|e| ClientError::RelayAuthOrNetwork(format!("wait request failed: {e}")))?,
                _ = shutdown_signal() => {
                    eprintln!("[outsider] Interrupted, cancelling request...");
                    self.cancel_best_effort(&created.session_id, &created.wait_token).await;
                    return Err(ClientError::ExpiredOrCancelled("request cancelled by signal".to_string()));
                }
            };

            match resp.status() {
                StatusCode::ACCEPTED => {
                    // 25s long-poll chunk expired while still pending; seamlessly loop.
                    continue;
                }
                StatusCode::OK => {
                    let wait_res = resp.json::<WaitResponse>().await.map_err(|e| {
                        ClientError::RelayAuthOrNetwork(format!("invalid wait response JSON: {e}"))
                    })?;
                    let envelope = wait_res.envelope.ok_or_else(|| {
                        ClientError::CryptoFailed("approved response missing envelope".to_string())
                    })?;
                    return kp
                        .decrypt_envelope(&envelope, &created.session_id, &context_hash)
                        .map_err(ClientError::CryptoFailed);
                }
                StatusCode::GONE => {
                    let status_msg = resp
                        .json::<WaitResponse>()
                        .await
                        .map(|w| w.status)
                        .unwrap_or_else(|_| "expired".to_string());
                    return Err(ClientError::ExpiredOrCancelled(format!(
                        "approval request ended with status: {status_msg}"
                    )));
                }
                other => {
                    let detail = extract_error(resp).await;
                    return Err(ClientError::RelayAuthOrNetwork(format!(
                        "unexpected wait response HTTP {other}: {detail}"
                    )));
                }
            }
        }
    }

    async fn cancel_best_effort(&self, session_id: &str, wait_token: &str) {
        let url = format!("{}/v1/requests/{}", self.base_url, session_id);
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            self.http.delete(&url).bearer_auth(wait_token).send(),
        )
        .await;
    }
}

fn build_signed_body(
    id: &IdentityKey,
    kp: &EphemeralKeypair,
    ctx: RequestContext,
    ttl_secs: u32,
) -> Result<CreateRequestBody, ClientError> {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ClientError::RelayAuthOrNetwork(format!("system clock error: {e}")))?
        .as_secs();

    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ctx_hash = compute_context_hash(&ctx);
    let pk_req = kp.public_bytes();
    let sig = id.sign_request(&pk_req, &ctx_hash, now_secs, ttl_secs, &nonce);

    Ok(CreateRequestBody {
        v: 1,
        id_pk: id.public_key_b64u(),
        pk_req: kp.public_b64u(),
        request_ts: now_secs,
        ttl_secs,
        request_nonce: URL_SAFE_NO_PAD.encode(nonce),
        context: ctx,
        sig: URL_SAFE_NO_PAD.encode(sig),
    })
}

async fn extract_error(resp: reqwest::Response) -> String {
    resp.json::<ErrorBody>()
        .await
        .map(|b| b.error)
        .unwrap_or_else(|_| "no error details".to_string())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
