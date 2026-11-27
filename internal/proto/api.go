package proto

// CreateRequestBody is the signed JSON body for POST /v1/requests and POST /v1/doctor.
type CreateRequestBody struct {
	V            int     `json:"v"`
	IDPk         string  `json:"id_pk"`
	PkReq        string  `json:"pk_req"`
	RequestTs    int64   `json:"request_ts"`
	TTLSecs      uint32  `json:"ttl_secs"`
	RequestNonce string  `json:"request_nonce"`
	Context      Context `json:"context"`
	Sig          string  `json:"sig"`
}

// CreateRequestResponse is returned by POST /v1/requests.
type CreateRequestResponse struct {
	SessionID string `json:"session_id"`
	WaitToken string `json:"wait_token"`
	ExpiresAt string `json:"expires_at"`
}

// Envelope is the opaque end-to-end encrypted payload submitted by the approver.
type Envelope struct {
	V          int    `json:"v"`
	EPK        string `json:"epk"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// WaitResponse is returned by GET /v1/requests/{id}/wait.
type WaitResponse struct {
	Status        string    `json:"status"`
	RemainingSecs *int64    `json:"remaining_secs,omitempty"`
	Envelope      *Envelope `json:"envelope,omitempty"`
}

// DoctorResponse is returned by POST /v1/doctor.
type DoctorResponse struct {
	OK         bool   `json:"ok"`
	ClientName string `json:"client_name"`
}

// ErrorBody is the JSON error payload returned by the relay.
type ErrorBody struct {
	Error string `json:"error"`
}
