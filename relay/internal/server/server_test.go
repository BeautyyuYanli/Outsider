package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"outsider/relay/internal/config"
	"outsider/relay/internal/crypto"
	"outsider/relay/internal/notifier"
	"outsider/relay/internal/session"
)

type captureNotifier struct {
	mu       sync.Mutex
	payloads []notifier.NotifyPayload
	ch       chan notifier.NotifyPayload
}

func newCaptureNotifier() *captureNotifier {
	return &captureNotifier{ch: make(chan notifier.NotifyPayload, 4)}
}

func (c *captureNotifier) NotifyRequest(_ context.Context, p notifier.NotifyPayload) error {
	c.mu.Lock()
	c.payloads = append(c.payloads, p)
	c.mu.Unlock()
	c.ch <- p
	return nil
}

func makeSignedRequest(t *testing.T, priv ed25519.PrivateKey, ctx crypto.Context, ts int64, ttl int) []byte {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	pkReq := make([]byte, 32)
	for i := range pkReq {
		pkReq[i] = byte(i + 10)
	}
	nonceStr, err := crypto.RandomToken(16)
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes, _ := base64.RawURLEncoding.DecodeString(nonceStr)
	ctxHash := crypto.ComputeContextHash(ctx)
	signInput, err := crypto.BuildSignInput(pub, pkReq, ctxHash[:], ts, uint32(ttl), nonceBytes)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, signInput)

	req := map[string]any{
		"v":             1,
		"id_pk":         base64.RawURLEncoding.EncodeToString(pub),
		"pk_req":        base64.RawURLEncoding.EncodeToString(pkReq),
		"request_ts":    ts,
		"ttl_secs":      ttl,
		"request_nonce": nonceStr,
		"context":       ctx,
		"sig":           base64.RawURLEncoding.EncodeToString(sig),
	}
	b, _ := json.Marshal(req)
	return b
}

func TestRelayEndToEndFlowAndSecurityHeaders(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)

	cfgTOML := `
public_base_url = "https://relay.example.com"
max_pending_per_client = 2
rate_limit_per_min = 5

[[trusted_clients]]
name = "test-laptop"
public_key = "` + pubB64 + `"
`
	cfg, err := config.Parse([]byte(cfgTOML))
	if err != nil {
		t.Fatalf("config.Parse: %v", err)
	}

	store := session.NewStore()
	notif := newCaptureNotifier()
	srv := New(cfg, store, notif, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Verify /v1/doctor succeeds for trusted client.
	ctx := crypto.Context{Name: "DOCKER_PAT", Reason: "Push release", CommandSummary: "docker push app:v1"}
	doctorBody := makeSignedRequest(t, priv, ctx, time.Now().Unix(), 120)
	resp, err := http.Post(ts.URL+"/v1/doctor", "application/json", bytes.NewReader(doctorBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/doctor status = %d, want 200", resp.StatusCode)
	}

	// 2. Create unlock request.
	createBody := makeSignedRequest(t, priv, ctx, time.Now().Unix(), 120)
	resp, err = http.Post(ts.URL+"/v1/requests", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/requests status = %d, want 201", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("missing Cache-Control: no-store")
	}
	var created struct {
		SessionID string `json:"session_id"`
		WaitToken string `json:"wait_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 3. Replay exact same signed request -> must be rejected with 409 Conflict.
	replayResp, err := http.Post(ts.URL+"/v1/requests", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusConflict {
		t.Fatalf("replayed POST /v1/requests status = %d, want 409", replayResp.StatusCode)
	}

	// 4. Receive notification with /approve/docker-pat/<approve_token>.
	var notified notifier.NotifyPayload
	select {
	case notified = <-notif.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notifier")
	}
	const prefix = "https://relay.example.com/approve/docker-pat/"
	if !strings.HasPrefix(notified.URL, prefix) {
		t.Fatalf("unexpected approval URL: %s", notified.URL)
	}
	approveToken := strings.TrimPrefix(notified.URL, prefix)

	// 5. Fetch embedded HTML approval page & verify strict CSP header.
	pageResp, err := http.Get(ts.URL + "/approve/docker-pat/" + approveToken)
	if err != nil {
		t.Fatal(err)
	}
	pageResp.Body.Close()
	if pageResp.StatusCode != http.StatusOK {
		t.Fatalf("GET approval page status = %d, want 200", pageResp.StatusCode)
	}
	csp := pageResp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'none'") || !strings.Contains(csp, "style-src 'self'") {
		t.Errorf("unexpected CSP: %q", csp)
	}

	// 6. Fetch /v1/approve/{token} metadata.
	metaResp, err := http.Get(ts.URL + "/v1/approve/" + approveToken)
	if err != nil {
		t.Fatal(err)
	}
	var snap session.SessionSnapshot
	if err := json.NewDecoder(metaResp.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	metaResp.Body.Close()
	if snap.SessionID != created.SessionID || snap.ClientName != "test-laptop" || snap.Status != session.StatusPending {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	// 7. Start long-poll wait in background, then approve to verify immediate wakeup.
	waitDone := make(chan struct {
		status   int
		envelope *session.Envelope
	}, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/requests/"+created.SessionID+"/wait?timeout=10", nil)
		req.Header.Set("Authorization", "Bearer "+created.WaitToken)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("wait request error: %v", err)
			return
		}
		defer r.Body.Close()
		var body struct {
			Status   string            `json:"status"`
			Envelope *session.Envelope `json:"envelope"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		waitDone <- struct {
			status   int
			envelope *session.Envelope
		}{r.StatusCode, body.Envelope}
	}()

	time.Sleep(50 * time.Millisecond)

	epk := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 12))
	ct := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	envBody, _ := json.Marshal(session.Envelope{V: 1, EPK: epk, Nonce: nonce, Ciphertext: ct})

	approveResp, err := http.Post(ts.URL+"/v1/approve/"+approveToken, "application/json", bytes.NewReader(envBody))
	if err != nil {
		t.Fatal(err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/approve status = %d, want 200", approveResp.StatusCode)
	}

	// Duplicate approval must fail with 409.
	dupApprove, _ := http.Post(ts.URL+"/v1/approve/"+approveToken, "application/json", bytes.NewReader(envBody))
	dupApprove.Body.Close()
	if dupApprove.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate approve status = %d, want 409", dupApprove.StatusCode)
	}

	select {
	case got := <-waitDone:
		if got.status != http.StatusOK || got.envelope == nil || got.envelope.Ciphertext != ct {
			t.Fatalf("unexpected wait result: status=%d env=%+v", got.status, got.envelope)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wait did not wake up immediately after approval")
	}

	// 8. Second wait after consumption must return 410 Gone (burn-after-reading!).
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/requests/"+created.SessionID+"/wait?timeout=1", nil)
	req2.Header.Set("Authorization", "Bearer "+created.WaitToken)
	r2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusGone {
		t.Fatalf("second wait after consumption status = %d, want 410", r2.StatusCode)
	}
}
