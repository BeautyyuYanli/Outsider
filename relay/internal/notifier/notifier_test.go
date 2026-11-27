package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"outsider/relay/internal/config"
)

func TestWebhookNotifierTemplateAndJSONEscaping(t *testing.T) {
	var gotBody []byte
	var gotHeader string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	multi, err := BuildFromConfig([]config.NotifierConfig{
		{
			Type: "webhook",
			URL:  ts.URL,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"X-Custom":     "outsider-test",
			},
			BodyTemplate: `{"msg":"[Outsider] {{device}} {{secret_name}} {{reason}} {{command}} {{url}} ({{ttl_secs}}s)"}`,
		},
	}, nil)
	if err != nil {
		t.Fatalf("BuildFromConfig: %v", err)
	}

	err = multi.NotifyRequest(context.Background(), NotifyPayload{
		URL:        "https://relay.example.com/approve/prod-db/tok123",
		Device:     "macbook",
		SecretName: "prod-db",
		Reason:     `Run "quoted" migration`,
		Command:    "psql -c \"SELECT 1\"\nnext",
		TTLSecs:    120,
	})
	if err != nil {
		t.Fatalf("NotifyRequest: %v", err)
	}
	if gotHeader != "outsider-test" {
		t.Errorf("X-Custom = %q, want outsider-test", gotHeader)
	}

	var parsed map[string]string
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("rendered webhook body is not valid JSON: %v (body=%s)", err, string(gotBody))
	}
	if !strings.Contains(parsed["msg"], `Run "quoted" migration`) {
		t.Errorf("unexpected rendered msg: %q", parsed["msg"])
	}
}

func TestWebhookNotifierRedactMetadata(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	multi, err := BuildFromConfig([]config.NotifierConfig{
		{Type: "webhook", URL: ts.URL},
	}, nil)
	if err != nil {
		t.Fatalf("BuildFromConfig: %v", err)
	}

	err = multi.NotifyRequest(context.Background(), NotifyPayload{
		URL:            "https://relay.example.com/approve/secret/tok",
		Device:         "macbook",
		SecretName:     "TOP_SECRET_NAME",
		Reason:         "sensitive reason",
		Command:        "sensitive cmd",
		TTLSecs:        120,
		RedactMetadata: true,
	})
	if err != nil {
		t.Fatalf("NotifyRequest: %v", err)
	}
	bodyStr := string(gotBody)
	if strings.Contains(bodyStr, "TOP_SECRET_NAME") || strings.Contains(bodyStr, "sensitive") {
		t.Errorf("redacted notification leaked metadata: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "https://relay.example.com/approve/secret/tok") {
		t.Errorf("redacted notification missing URL: %s", bodyStr)
	}
}
