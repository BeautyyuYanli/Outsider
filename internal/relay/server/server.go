package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"outsider/internal/relay/config"
	"outsider/internal/proto"
	"outsider/internal/relay/notifier"
	"outsider/internal/relay/session"
	"outsider/web"
)

const (
	cspHeaderValue      = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
	maxRequestBodyBytes = 64 * 1024
	maxApproveBodyBytes = 256 * 1024
	clockSkewTolerance  = 30 * time.Second
)

// Server serves the Outsider Relay HTTP API and embedded static approval UI.
type Server struct {
	mu       sync.RWMutex
	cfg      *config.Config
	notifier notifier.Notifier

	store  *session.Store
	logger *slog.Logger
	mux    *http.ServeMux
	now    func() time.Time
}

// New constructs a Server wired with the given config, session store, and notifier.
func New(cfg *config.Config, store *session.Store, n notifier.Notifier, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		cfg:      cfg,
		notifier: n,
		store:    store,
		logger:   logger,
		mux:      http.NewServeMux(),
		now:      time.Now,
	}
	s.registerRoutes()
	return s
}

// UpdateConfig atomically swaps live config and notifier (used on SIGHUP reload).
func (s *Server) UpdateConfig(cfg *config.Config, n notifier.Notifier) {
	s.mu.Lock()
	s.cfg = cfg
	s.notifier = n
	s.mu.Unlock()
}

func (s *Server) currentConfig() (*config.Config, notifier.Notifier) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg, s.notifier
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("POST /v1/doctor", s.handleDoctor)
	s.mux.HandleFunc("POST /v1/requests", s.handleCreateRequest)
	s.mux.HandleFunc("GET /v1/requests/{id}/wait", s.handleWaitRequest)
	s.mux.HandleFunc("DELETE /v1/requests/{id}", s.handleCancelRequest)
	s.mux.HandleFunc("GET /v1/approve/{approve_token}", s.handleGetApprove)
	s.mux.HandleFunc("POST /v1/approve/{approve_token}", s.handlePostApprove)
	s.mux.HandleFunc("GET /approve/{name_slug}/{approve_token}", s.handleApprovePage)
	s.mux.HandleFunc("GET /assets/{file}", s.handleAsset)
}

// Handler returns the root http.Handler with security headers and redacted access logging.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		s.mux.ServeHTTP(rec, r)

		s.logger.Info("http_request",
			"method", r.Method,
			"path", redactLogPath(r.URL.Path),
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func redactLogPath(p string) string {
	switch {
	case strings.HasPrefix(p, "/v1/approve/"):
		return "/v1/approve/[REDACTED]"
	case strings.HasPrefix(p, "/approve/"):
		parts := strings.Split(strings.TrimPrefix(p, "/approve/"), "/")
		if len(parts) >= 2 && parts[1] != "" {
			return "/approve/" + parts[0] + "/[REDACTED]"
		}
		return "/approve/[REDACTED]"
	case strings.HasPrefix(p, "/v1/requests/"):
		rest := strings.TrimPrefix(p, "/v1/requests/")
		if strings.HasSuffix(rest, "/wait") {
			return "/v1/requests/[REDACTED]/wait"
		}
		return "/v1/requests/[REDACTED]"
	default:
		return p
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type createRequestBody struct {
	V            int            `json:"v"`
	IDPk         string         `json:"id_pk"`
	PkReq        string         `json:"pk_req"`
	RequestTs    int64          `json:"request_ts"`
	TTLSecs      int            `json:"ttl_secs"`
	RequestNonce string         `json:"request_nonce"`
	Context      proto.Context `json:"context"`
	Sig          string         `json:"sig"`
}

func (s *Server) authenticateSignedRequest(r *http.Request, cfg *config.Config) (createRequestBody, config.TrustedClient, int, string) {
	var body createRequestBody
	limited := io.LimitReader(r.Body, maxRequestBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return body, config.TrustedClient{}, http.StatusBadRequest, "failed to read body"
	}
	if len(raw) > maxRequestBodyBytes {
		return body, config.TrustedClient{}, http.StatusRequestEntityTooLarge, "request body too large"
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return body, config.TrustedClient{}, http.StatusBadRequest, "invalid JSON body"
	}
	if body.V != 1 {
		return body, config.TrustedClient{}, http.StatusBadRequest, "unsupported protocol version"
	}
	if strings.TrimSpace(body.Context.Name) == "" {
		return body, config.TrustedClient{}, http.StatusBadRequest, "context.name is required"
	}
	if body.TTLSecs <= 0 {
		body.TTLSecs = cfg.DefaultTTLSecs
	}
	if body.TTLSecs > cfg.MaxTTLSecs {
		return body, config.TrustedClient{}, http.StatusBadRequest, fmt.Sprintf("ttl_secs exceeds max (%d)", cfg.MaxTTLSecs)
	}

	now := s.now()
	reqTime := time.Unix(body.RequestTs, 0)
	skew := now.Sub(reqTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > clockSkewTolerance {
		return body, config.TrustedClient{}, http.StatusUnauthorized, "request timestamp outside allowed window"
	}

	client, ok := cfg.LookupClient(body.IDPk)
	if !ok {
		return body, config.TrustedClient{}, http.StatusUnauthorized, "untrusted client public key"
	}

	if err := proto.VerifyRequestSignature(
		body.IDPk,
		body.PkReq,
		body.Context,
		body.RequestTs,
		uint32(body.TTLSecs),
		body.RequestNonce,
		body.Sig,
	); err != nil {
		return body, config.TrustedClient{}, http.StatusUnauthorized, "invalid signature"
	}

	return body, client, http.StatusOK, ""
}

// handleDoctor verifies Ed25519 signature and trusted_clients allowlist without creating a session or notifying.
func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	cfg, _ := s.currentConfig()
	_, client, status, errMsg := s.authenticateSignedRequest(r, cfg)
	if errMsg != "" {
		writeError(w, status, errMsg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"client_name": client.Name,
	})
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	cfg, notif := s.currentConfig()
	body, client, status, errMsg := s.authenticateSignedRequest(r, cfg)
	if errMsg != "" {
		writeError(w, status, errMsg)
		return
	}

	created, err := s.store.Create(session.CreateParams{
		Version:             body.V,
		IDPk:                body.IDPk,
		ClientName:          client.Name,
		PkReq:               body.PkReq,
		Context:             body.Context,
		RequestTs:           body.RequestTs,
		TTLSecs:             body.TTLSecs,
		RequestNonce:        body.RequestNonce,
		Sig:                 body.Sig,
		GraceTTLSecs:        cfg.GraceTTLSecs,
		MaxPendingPerClient: cfg.MaxPendingPerClient,
		RateLimitPerMin:     cfg.RateLimitPerMin,
	})
	if err != nil {
		switch {
		case errors.Is(err, session.ErrReplayNonce):
			writeError(w, http.StatusConflict, "replay request nonce detected")
		case errors.Is(err, session.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		case errors.Is(err, session.ErrTooManyPending):
			writeError(w, http.StatusTooManyRequests, "too many concurrent pending requests")
		default:
			writeError(w, http.StatusInternalServerError, "failed to create session")
		}
		return
	}

	approveURL := fmt.Sprintf("%s/approve/%s/%s", cfg.PublicBaseURL, created.NameSlug, created.ApproveToken)
	if notif != nil {
		payload := notifier.NotifyPayload{
			URL:            approveURL,
			Device:         client.Name,
			SecretName:     body.Context.Name,
			Reason:         body.Context.Reason,
			Command:        body.Context.CommandSummary,
			TTLSecs:        body.TTLSecs,
			RedactMetadata: cfg.RedactNotificationMetadata,
		}
		// Dispatch notifications asynchronously so requester immediately gets session_id and starts waiting.
		go func(p notifier.NotifyPayload) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := notif.NotifyRequest(ctx, p); err != nil {
				s.logger.Warn("all notifiers failed", "error", err)
			}
		}(payload)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id": created.SessionID,
		"wait_token": created.WaitToken,
		"expires_at": created.ExpiresAt.Format(time.RFC3339),
	})
}

func extractBearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}

func (s *Server) handleWaitRequest(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	waitToken := extractBearerToken(r)
	if sessionID == "" || waitToken == "" {
		writeError(w, http.StatusUnauthorized, "missing wait token")
		return
	}

	timeoutSecs := 25
	if raw := r.URL.Query().Get("timeout"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 && parsed <= 30 {
			timeoutSecs = parsed
		}
	}

	res, err := s.store.Wait(r.Context(), sessionID, waitToken, time.Duration(timeoutSecs)*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrNotFound):
			writeError(w, http.StatusNotFound, "session not found")
		case errors.Is(err, session.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "invalid wait token")
		case errors.Is(err, context.Canceled):
			return
		default:
			writeError(w, http.StatusInternalServerError, "wait failed")
		}
		return
	}

	switch res.Status {
	case session.StatusPending:
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":         "pending",
			"remaining_secs": res.RemainingSecs,
		})
	case session.StatusApproved:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "approved",
			"envelope": res.Envelope,
		})
	case session.StatusExpired:
		writeJSON(w, http.StatusGone, map[string]any{
			"status": "expired",
		})
	case session.StatusCancelled:
		writeJSON(w, http.StatusGone, map[string]any{
			"status": "cancelled",
		})
	case session.StatusConsumed:
		writeJSON(w, http.StatusGone, map[string]any{
			"status": "consumed",
		})
	default:
		writeError(w, http.StatusInternalServerError, "unexpected session status")
	}
}

func (s *Server) handleCancelRequest(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	waitToken := extractBearerToken(r)
	if sessionID == "" || waitToken == "" {
		writeError(w, http.StatusUnauthorized, "missing wait token")
		return
	}

	if err := s.store.Cancel(sessionID, waitToken); err != nil {
		switch {
		case errors.Is(err, session.ErrNotFound):
			writeError(w, http.StatusNotFound, "session not found")
		case errors.Is(err, session.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "invalid wait token")
		default:
			writeError(w, http.StatusInternalServerError, "cancel failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetApprove(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("approve_token")
	snap, ok := s.store.GetByApproveToken(token)
	if !ok {
		writeError(w, http.StatusNotFound, "approval session not found or expired")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handlePostApprove(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("approve_token")
	limited := io.LimitReader(r.Body, maxApproveBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if len(raw) > maxApproveBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "envelope too large")
		return
	}

	var env session.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON envelope")
		return
	}
	if env.V != 1 {
		writeError(w, http.StatusBadRequest, "unsupported envelope version")
		return
	}
	if epkBytes, err := base64.RawURLEncoding.DecodeString(env.EPK); err != nil || len(epkBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid epk")
		return
	}
	if nonceBytes, err := base64.RawURLEncoding.DecodeString(env.Nonce); err != nil || len(nonceBytes) != 12 {
		writeError(w, http.StatusBadRequest, "invalid nonce")
		return
	}
	if ctBytes, err := base64.RawURLEncoding.DecodeString(env.Ciphertext); err != nil || len(ctBytes) < 16 {
		writeError(w, http.StatusBadRequest, "invalid ciphertext")
		return
	}

	if err := s.store.Approve(token, env); err != nil {
		switch {
		case errors.Is(err, session.ErrNotFound):
			writeError(w, http.StatusNotFound, "approval session not found")
		case errors.Is(err, session.ErrExpired):
			writeError(w, http.StatusGone, "approval session expired")
		case errors.Is(err, session.ErrAlreadyResolved):
			writeError(w, http.StatusConflict, "approval session already resolved")
		default:
			writeError(w, http.StatusInternalServerError, "failed to store approval")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleApprovePage(w http.ResponseWriter, _ *http.Request) {
	data, err := fs.ReadFile(web.FS, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "approval page unavailable")
		return
	}
	w.Header().Set("Content-Security-Policy", cspHeaderValue)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	var contentType string
	switch file {
	case "app.js":
		contentType = "application/javascript; charset=utf-8"
	case "style.css":
		contentType = "text/css; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(web.FS, file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", cspHeaderValue)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
