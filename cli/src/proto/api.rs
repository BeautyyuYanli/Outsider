use serde::{Deserialize, Serialize};

use crate::proto::context::RequestContext;

#[derive(Debug, Serialize)]
pub struct CreateRequestBody {
    pub v: u32,
    pub id_pk: String,
    pub pk_req: String,
    pub request_ts: u64,
    pub ttl_secs: u32,
    pub request_nonce: String,
    pub context: RequestContext,
    pub sig: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateRequestResponse {
    pub session_id: String,
    pub wait_token: String,
    #[allow(dead_code)]
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct WaitResponse {
    pub status: String,
    #[allow(dead_code)]
    pub remaining_secs: Option<i64>,
    pub envelope: Option<Envelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    pub epk: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct DoctorResponse {
    pub ok: bool,
    pub client_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}
