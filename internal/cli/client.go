package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"outsider/internal/proto"
)

// Version is overridden at build time via -ldflags if desired.
var Version = "0.1.0"

// RelayClient communicates with the Outsider Relay over HTTPS.
type RelayClient struct {
	baseURL string
	http    *http.Client
}

// NewRelayClient constructs a RelayClient with sensible timeouts for 25s long-polling chunks.
func NewRelayClient(baseURL string) *RelayClient {
	return &RelayClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		http: &http.Client{
			Timeout: 40 * time.Second,
		},
	}
}

func (c *RelayClient) doJSON(ctx context.Context, method, url string, bearer string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "outsider/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.http.Do(req)
}

func extractRelayError(r io.Reader) string {
	var eb proto.ErrorBody
	if err := json.NewDecoder(io.LimitReader(r, 16*1024)).Decode(&eb); err == nil && eb.Error != "" {
		return eb.Error
	}
	return "no error details"
}

// Healthz checks GET /healthz on the relay.
func (c *RelayClient) Healthz(ctx context.Context) error {
	url := c.baseURL + "/healthz"
	resp, err := c.doJSON(ctx, http.MethodGet, url, "", nil)
	if err != nil {
		return errRelay("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errRelay("GET /healthz returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Doctor checks signed Ed25519 authentication against POST /v1/doctor.
func (c *RelayClient) Doctor(ctx context.Context, id *proto.IdentityKey) (*proto.DoctorResponse, error) {
	kp, err := proto.GenerateEphemeralKeypair()
	if err != nil {
		return nil, errCrypto("generate ephemeral keypair: %v", err)
	}
	reqCtx := proto.Context{
		Name:           "__doctor__",
		Reason:         "connectivity and signature check",
		CommandSummary: "",
	}
	body, err := buildSignedBody(id, kp, reqCtx, 60)
	if err != nil {
		return nil, err
	}
	resp, err := c.doJSON(ctx, http.MethodPost, c.baseURL+"/v1/doctor", "", body)
	if err != nil {
		return nil, errRelay("POST /v1/doctor failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := extractRelayError(resp.Body)
		return nil, errRelay("POST /v1/doctor returned HTTP %d: %s", resp.StatusCode, detail)
	}
	var out proto.DoctorResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, errRelay("invalid /v1/doctor JSON: %v", err)
	}
	return &out, nil
}

// RequestSecret submits a signed approval request, waits via 25s long-poll chunks (cancelling on SIGINT/SIGTERM),
// and returns the decrypted plaintext bytes. Callers must clear() the returned slice.
func (c *RelayClient) RequestSecret(ctx context.Context, id *proto.IdentityKey, reqCtx proto.Context, ttlSecs uint32) ([]byte, error) {
	kp, err := proto.GenerateEphemeralKeypair()
	if err != nil {
		return nil, errCrypto("generate ephemeral keypair: %v", err)
	}
	ctxHash := proto.ComputeContextHash(reqCtx)
	body, err := buildSignedBody(id, kp, reqCtx, ttlSecs)
	if err != nil {
		return nil, err
	}

	createURL := c.baseURL + "/v1/requests"
	resp, err := c.doJSON(ctx, http.MethodPost, createURL, "", body)
	if err != nil {
		return nil, errRelay("failed to reach relay %s: %v", createURL, err)
	}
	if resp.StatusCode != http.StatusCreated {
		detail := extractRelayError(resp.Body)
		resp.Body.Close()
		return nil, errRelay("relay rejected request (HTTP %d): %s", resp.StatusCode, detail)
	}
	var created proto.CreateRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		resp.Body.Close()
		return nil, errRelay("invalid create response JSON: %v", err)
	}
	resp.Body.Close()

	fmt.Fprintf(os.Stderr, "[outsider] Waiting for approval: %s (%ds) | Device FP: %s\n", reqCtx.Name, ttlSecs, id.Fingerprint())

	waitCtx, stopSig := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSig()

	waitURL := fmt.Sprintf("%s/v1/requests/%s/wait?timeout=25", c.baseURL, created.SessionID)
	for {
		wResp, err := c.doJSON(waitCtx, http.MethodGet, waitURL, created.WaitToken, nil)
		if err != nil {
			if waitCtx.Err() != nil {
				fmt.Fprintln(os.Stderr, "[outsider] Interrupted, cancelling request...")
				c.cancelBestEffort(created.SessionID, created.WaitToken)
				return nil, errExpired("request cancelled by signal")
			}
			return nil, errRelay("wait request failed: %v", err)
		}

		switch wResp.StatusCode {
		case http.StatusAccepted:
			_, _ = io.Copy(io.Discard, wResp.Body)
			wResp.Body.Close()
			continue
		case http.StatusOK:
			var wr proto.WaitResponse
			decErr := json.NewDecoder(wResp.Body).Decode(&wr)
			wResp.Body.Close()
			if decErr != nil {
				return nil, errRelay("invalid wait response JSON: %v", decErr)
			}
			if wr.Envelope == nil {
				return nil, errCrypto("approved response missing envelope")
			}
			secret, err := kp.DecryptEnvelope(*wr.Envelope, created.SessionID, ctxHash[:])
			if err != nil {
				return nil, errCrypto("%v", err)
			}
			return secret, nil
		case http.StatusGone:
			var wr proto.WaitResponse
			_ = json.NewDecoder(wResp.Body).Decode(&wr)
			wResp.Body.Close()
			st := wr.Status
			if st == "" {
				st = "expired"
			}
			return nil, errExpired("approval request ended with status: %s", st)
		default:
			detail := extractRelayError(wResp.Body)
			wResp.Body.Close()
			return nil, errRelay("unexpected wait response HTTP %d: %s", wResp.StatusCode, detail)
		}
	}
}

func (c *RelayClient) cancelBestEffort(sessionID, waitToken string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/v1/requests/%s", c.baseURL, sessionID)
	if resp, err := c.doJSON(ctx, http.MethodDelete, url, waitToken, nil); err == nil {
		resp.Body.Close()
	}
}

func buildSignedBody(id *proto.IdentityKey, kp *proto.EphemeralKeypair, reqCtx proto.Context, ttlSecs uint32) (*proto.CreateRequestBody, error) {
	nowSecs := time.Now().Unix()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errCrypto("generate nonce: %v", err)
	}
	ctxHash := proto.ComputeContextHash(reqCtx)
	sig, err := id.SignRequest(kp.PublicBytes(), ctxHash[:], nowSecs, ttlSecs, nonce)
	if err != nil {
		return nil, errCrypto("sign request: %v", err)
	}
	return &proto.CreateRequestBody{
		V:            1,
		IDPk:         id.PublicKeyB64u(),
		PkReq:        kp.PublicB64u(),
		RequestTs:    nowSecs,
		TTLSecs:      ttlSecs,
		RequestNonce: base64.RawURLEncoding.EncodeToString(nonce),
		Context:      reqCtx,
		Sig:          base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}
