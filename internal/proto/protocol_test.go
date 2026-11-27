package proto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type testVectors struct {
	ProtocolVersion int `json:"protocol_version"`
	SlugCases       []struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"slug_cases"`
	Identity struct {
		SeedHex  string `json:"seed_hex"`
		IDPkB64u string `json:"id_pk_b64u"`
		IDFp     string `json:"id_fp"`
	} `json:"identity"`
	ContextVectors []struct {
		Label           string `json:"label"`
		Name            string `json:"name"`
		Reason          string `json:"reason"`
		CommandSummary  string `json:"command_summary"`
		ContextBytesHex string `json:"context_bytes_hex"`
		ContextHashHex  string `json:"context_hash_hex"`
		ContextHashB64u string `json:"context_hash_b64u"`
	} `json:"context_vectors"`
	RequestSignature struct {
		ContextLabel     string `json:"context_label"`
		IDPkB64u         string `json:"id_pk_b64u"`
		PkReqB64u        string `json:"pk_req_b64u"`
		RequestTs        int64  `json:"request_ts"`
		TTLSecs          uint32 `json:"ttl_secs"`
		RequestNonceB64u string `json:"request_nonce_b64u"`
		SignInputHex     string `json:"sign_input_hex"`
		SigB64u          string `json:"sig_b64u"`
	} `json:"request_signature"`
	E2EE struct {
		ContextLabel    string `json:"context_label"`
		SessionID       string `json:"session_id"`
		SkReqHex        string `json:"sk_req_hex"`
		PkReqB64u       string `json:"pk_req_b64u"`
		SkEpkHex        string `json:"sk_epk_hex"`
		EpkB64u         string `json:"epk_b64u"`
		SharedSecretHex string `json:"shared_secret_hex"`
		AEADKeyHex      string `json:"aead_key_hex"`
		AADHex          string `json:"aad_hex"`
		NonceB64u       string `json:"nonce_b64u"`
		PlaintextJSON   string `json:"plaintext_json"`
		CiphertextB64u  string `json:"ciphertext_b64u"`
	} `json:"e2ee"`
}

func loadVectors(t *testing.T) testVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "protocol", "test-vectors.json"))
	if err != nil {
		t.Fatalf("read test-vectors.json: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal test-vectors.json: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestProtocolVectors(t *testing.T) {
	v := loadVectors(t)

	for _, sc := range v.SlugCases {
		if got := SlugifyName(sc.Input); got != sc.Expected {
			t.Errorf("SlugifyName(%q) = %q, want %q", sc.Input, got, sc.Expected)
		}
	}

	seed := mustHex(t, v.Identity.SeedHex)
	id, err := IdentityKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("IdentityKeyFromSeed: %v", err)
	}
	defer id.Wipe()
	if got := id.PublicKeyB64u(); got != v.Identity.IDPkB64u {
		t.Fatalf("PublicKeyB64u = %q, want %q", got, v.Identity.IDPkB64u)
	}
	if got := id.Fingerprint(); got != v.Identity.IDFp {
		t.Fatalf("Fingerprint = %q, want %q", got, v.Identity.IDFp)
	}
	if id2, err := IdentityKeyFromB64u(string(id.SeedB64u())); err != nil || id2.PublicKeyB64u() != id.PublicKeyB64u() {
		t.Fatalf("IdentityKeyFromB64u roundtrip failed: %v", err)
	}

	var firstCtx Context
	var firstCtxHash [32]byte
	for _, cv := range v.ContextVectors {
		ctx := Context{Name: cv.Name, Reason: cv.Reason, CommandSummary: cv.CommandSummary}
		if got := hex.EncodeToString(EncodeContextBytes(ctx)); got != cv.ContextBytesHex {
			t.Errorf("EncodeContextBytes(%s) = %s, want %s", cv.Label, got, cv.ContextBytesHex)
		}
		hash := ComputeContextHash(ctx)
		if got := hex.EncodeToString(hash[:]); got != cv.ContextHashHex {
			t.Errorf("ComputeContextHash(%s) = %s, want %s", cv.Label, got, cv.ContextHashHex)
		}
		if got := base64.RawURLEncoding.EncodeToString(hash[:]); got != cv.ContextHashB64u {
			t.Errorf("ComputeContextHash b64u(%s) = %s, want %s", cv.Label, got, cv.ContextHashB64u)
		}
		if cv.Label == v.RequestSignature.ContextLabel {
			firstCtx = ctx
			firstCtxHash = hash
		}
	}

	rs := v.RequestSignature
	pkReq, _ := base64.RawURLEncoding.DecodeString(rs.PkReqB64u)
	nonce, _ := base64.RawURLEncoding.DecodeString(rs.RequestNonceB64u)
	signInput, err := BuildSignInput(id.PublicKeyBytes(), pkReq, firstCtxHash[:], rs.RequestTs, rs.TTLSecs, nonce)
	if err != nil {
		t.Fatalf("BuildSignInput: %v", err)
	}
	if got := hex.EncodeToString(signInput); got != rs.SignInputHex {
		t.Errorf("BuildSignInput = %s, want %s", got, rs.SignInputHex)
	}

	sig, err := id.SignRequest(pkReq, firstCtxHash[:], rs.RequestTs, rs.TTLSecs, nonce)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if got := base64.RawURLEncoding.EncodeToString(sig); got != rs.SigB64u {
		t.Errorf("SignRequest = %q, want %q", got, rs.SigB64u)
	}
	if err := VerifyRequestSignature(rs.IDPkB64u, rs.PkReqB64u, firstCtx, rs.RequestTs, rs.TTLSecs, rs.RequestNonceB64u, rs.SigB64u); err != nil {
		t.Errorf("VerifyRequestSignature valid failed: %v", err)
	}
	tampered := firstCtx
	tampered.Reason = "tampered"
	if err := VerifyRequestSignature(rs.IDPkB64u, rs.PkReqB64u, tampered, rs.RequestTs, rs.TTLSecs, rs.RequestNonceB64u, rs.SigB64u); err == nil {
		t.Errorf("VerifyRequestSignature should fail on tampered context")
	}

	// E2EE vector validation (both decryption and deterministic encryption).
	ev := v.E2EE
	kp, err := EphemeralKeypairFromBytes(mustHex(t, ev.SkReqHex))
	if err != nil {
		t.Fatalf("EphemeralKeypairFromBytes: %v", err)
	}
	if got := kp.PublicB64u(); got != ev.PkReqB64u {
		t.Fatalf("kp.PublicB64u = %q, want %q", got, ev.PkReqB64u)
	}
	if got := hex.EncodeToString(BuildAAD(ev.SessionID, firstCtxHash[:])); got != ev.AADHex {
		t.Fatalf("BuildAAD = %s, want %s", got, ev.AADHex)
	}
	epkBytes, _ := base64.RawURLEncoding.DecodeString(ev.EpkB64u)
	aeadKey, err := DeriveAEADKey(mustHex(t, ev.SharedSecretHex), ev.SessionID, kp.PublicBytes(), epkBytes)
	if err != nil {
		t.Fatalf("DeriveAEADKey: %v", err)
	}
	if got := hex.EncodeToString(aeadKey); got != ev.AEADKeyHex {
		t.Fatalf("DeriveAEADKey = %s, want %s", got, ev.AEADKeyHex)
	}

	env := Envelope{
		V:          1,
		EPK:        ev.EpkB64u,
		Nonce:      ev.NonceB64u,
		Ciphertext: ev.CiphertextB64u,
	}
	secret, err := kp.DecryptEnvelope(env, ev.SessionID, firstCtxHash[:])
	if err != nil {
		t.Fatalf("DecryptEnvelope: %v", err)
	}
	defer clear(secret)
	var expected plaintextPayload
	if err := json.Unmarshal([]byte(ev.PlaintextJSON), &expected); err != nil {
		t.Fatalf("unmarshal expected plaintext: %v", err)
	}
	if string(secret) != expected.Secret {
		t.Fatalf("DecryptEnvelope secret = %q, want %q", string(secret), expected.Secret)
	}

	// Tampered AAD context_hash must fail decryption.
	wrongHash := firstCtxHash
	wrongHash[0] ^= 0xff
	if _, err := kp.DecryptEnvelope(env, ev.SessionID, wrongHash[:]); err == nil {
		t.Fatalf("DecryptEnvelope should fail on tampered context_hash")
	}

	// Deterministic encryption must match test vector byte-for-byte.
	nonceBytes, _ := base64.RawURLEncoding.DecodeString(ev.NonceB64u)
	reEnc, err := EncryptEnvelope(
		[]byte(expected.Secret),
		ev.SessionID,
		kp.PublicBytes(),
		firstCtxHash[:],
		mustHex(t, ev.SkEpkHex),
		nonceBytes,
	)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	if reEnc != env {
		t.Fatalf("EncryptEnvelope = %+v, want %+v", reEnc, env)
	}
}
