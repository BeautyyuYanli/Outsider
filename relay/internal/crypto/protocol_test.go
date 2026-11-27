package crypto

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
}

func loadVectors(t *testing.T) testVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "test-vectors.json"))
	if err != nil {
		t.Fatalf("read test-vectors.json: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal test-vectors.json: %v", err)
	}
	return v
}

func TestProtocolVectors(t *testing.T) {
	v := loadVectors(t)

	for _, sc := range v.SlugCases {
		if got := SlugifyName(sc.Input); got != sc.Expected {
			t.Errorf("SlugifyName(%q) = %q, want %q", sc.Input, got, sc.Expected)
		}
	}

	idPk, err := base64.RawURLEncoding.DecodeString(v.Identity.IDPkB64u)
	if err != nil {
		t.Fatalf("decode id_pk: %v", err)
	}
	fp, err := ComputeFingerprint(idPk)
	if err != nil {
		t.Fatalf("ComputeFingerprint: %v", err)
	}
	if fp != v.Identity.IDFp {
		t.Errorf("ComputeFingerprint = %q, want %q", fp, v.Identity.IDFp)
	}

	var firstCtx Context
	for _, cv := range v.ContextVectors {
		ctx := Context{Name: cv.Name, Reason: cv.Reason, CommandSummary: cv.CommandSummary}
		if cv.Label == v.RequestSignature.ContextLabel {
			firstCtx = ctx
		}
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
	}

	rs := v.RequestSignature
	pkReq, _ := base64.RawURLEncoding.DecodeString(rs.PkReqB64u)
	nonce, _ := base64.RawURLEncoding.DecodeString(rs.RequestNonceB64u)
	h0 := ComputeContextHash(firstCtx)
	signInput, err := BuildSignInput(idPk, pkReq, h0[:], rs.RequestTs, rs.TTLSecs, nonce)
	if err != nil {
		t.Fatalf("BuildSignInput: %v", err)
	}
	if got := hex.EncodeToString(signInput); got != rs.SignInputHex {
		t.Errorf("BuildSignInput = %s, want %s", got, rs.SignInputHex)
	}

	if err := VerifyRequestSignature(rs.IDPkB64u, rs.PkReqB64u, firstCtx, rs.RequestTs, rs.TTLSecs, rs.RequestNonceB64u, rs.SigB64u); err != nil {
		t.Errorf("VerifyRequestSignature valid failed: %v", err)
	}

	tampered := firstCtx
	tampered.Reason = "tampered"
	if err := VerifyRequestSignature(rs.IDPkB64u, rs.PkReqB64u, tampered, rs.RequestTs, rs.TTLSecs, rs.RequestNonceB64u, rs.SigB64u); err == nil {
		t.Errorf("VerifyRequestSignature should fail on tampered context")
	}
}
