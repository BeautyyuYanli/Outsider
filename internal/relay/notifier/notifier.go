package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nicholas-fedor/shoutrrr"
	"outsider/internal/relay/config"
)

// NotifyPayload contains the fields passed to one-way notification channels.
type NotifyPayload struct {
	URL            string
	Device         string
	SecretName     string
	Reason         string
	Command        string
	TTLSecs        int
	RedactMetadata bool
}

// Notifier is the minimal one-way push interface.
type Notifier interface {
	NotifyRequest(ctx context.Context, payload NotifyPayload) error
}

// MultiNotifier dispatches to all configured notifiers in parallel.
type MultiNotifier struct {
	notifiers []Notifier
	logger    *slog.Logger
}

// BuildFromConfig constructs a MultiNotifier from relay.toml notifier definitions.
func BuildFromConfig(cfgs []config.NotifierConfig, logger *slog.Logger) (*MultiNotifier, error) {
	if logger == nil {
		logger = slog.Default()
	}
	list := make([]Notifier, 0, len(cfgs))
	for i, nc := range cfgs {
		switch strings.ToLower(strings.TrimSpace(nc.Type)) {
		case "shoutrrr":
			if _, err := shoutrrr.CreateSender(nc.URL); err != nil {
				return nil, fmt.Errorf("notifiers[%d] invalid shoutrrr url: %w", i, err)
			}
			list = append(list, &ShoutrrrNotifier{rawURL: nc.URL})
		case "webhook":
			method := strings.ToUpper(strings.TrimSpace(nc.Method))
			if method == "" {
				method = http.MethodPost
			}
			headers := make(map[string]string, len(nc.Headers))
			for k, v := range nc.Headers {
				headers[k] = v
			}
			list = append(list, &WebhookNotifier{
				url:          nc.URL,
				method:       method,
				headers:      headers,
				bodyTemplate: nc.BodyTemplate,
				client:       &http.Client{Timeout: 10 * time.Second},
			})
		default:
			return nil, fmt.Errorf("notifiers[%d] unsupported type %q", i, nc.Type)
		}
	}
	return &MultiNotifier{notifiers: list, logger: logger}, nil
}

// NotifyRequest sends notifications to all configured channels concurrently.
func (m *MultiNotifier) NotifyRequest(ctx context.Context, payload NotifyPayload) error {
	if len(m.notifiers) == 0 {
		return nil
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for idx, n := range m.notifiers {
		wg.Add(1)
		go func(i int, target Notifier) {
			defer wg.Done()
			sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := target.NotifyRequest(sendCtx, payload); err != nil {
				m.logger.Warn("notifier delivery failed", "index", i, "error", err)
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(idx, n)
	}
	wg.Wait()
	if len(errs) == len(m.notifiers) {
		return errors.Join(errs...)
	}
	return nil
}

// ShoutrrrNotifier sends plain-text approval alerts using the official Go shoutrrr library.
type ShoutrrrNotifier struct {
	rawURL string
}

func formatMessage(p NotifyPayload) string {
	if p.RedactMetadata {
		return fmt.Sprintf("[Outsider] Approval requested (%ds)\n%s", p.TTLSecs, p.URL)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Outsider] %s requested %s (%ds)", p.Device, p.SecretName, p.TTLSecs)
	if p.Reason != "" {
		fmt.Fprintf(&b, "\nReason: %s", p.Reason)
	}
	if p.Command != "" {
		fmt.Fprintf(&b, "\nCommand: %s", p.Command)
	}
	fmt.Fprintf(&b, "\nApprove: %s", p.URL)
	return b.String()
}

func (s *ShoutrrrNotifier) NotifyRequest(ctx context.Context, payload NotifyPayload) error {
	return shoutrrr.SendContext(ctx, s.rawURL, formatMessage(payload), nil)
}

// WebhookNotifier sends templated HTTP webhook requests.
type WebhookNotifier struct {
	url          string
	method       string
	headers      map[string]string
	bodyTemplate string
	client       *http.Client
}

func jsonEscapeInner(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1])
}

func (w *WebhookNotifier) isJSON() bool {
	for k, v := range w.headers {
		if strings.EqualFold(k, "Content-Type") && strings.Contains(strings.ToLower(v), "json") {
			return true
		}
	}
	return false
}

func (w *WebhookNotifier) renderBody(p NotifyPayload) []byte {
	device := p.Device
	secretName := p.SecretName
	reason := p.Reason
	command := p.Command
	if p.RedactMetadata {
		device = ""
		secretName = ""
		reason = ""
		command = ""
	}

	if w.bodyTemplate == "" {
		defaultPayload := map[string]any{
			"url":      p.URL,
			"ttl_secs": p.TTLSecs,
		}
		if !p.RedactMetadata {
			defaultPayload["device"] = device
			defaultPayload["secret_name"] = secretName
			defaultPayload["reason"] = reason
			defaultPayload["command"] = command
		}
		b, _ := json.Marshal(defaultPayload)
		return b
	}

	esc := func(s string) string { return s }
	if w.isJSON() {
		esc = jsonEscapeInner
	}

	replacer := strings.NewReplacer(
		"{{url}}", esc(p.URL),
		"{{device}}", esc(device),
		"{{secret_name}}", esc(secretName),
		"{{reason}}", esc(reason),
		"{{command}}", esc(command),
		"{{ttl_secs}}", strconv.Itoa(p.TTLSecs),
	)
	return []byte(replacer.Replace(w.bodyTemplate))
}

func (w *WebhookNotifier) NotifyRequest(ctx context.Context, payload NotifyPayload) error {
	body := w.renderBody(payload)
	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hasCT := false
	for k, v := range w.headers {
		req.Header.Set(k, v)
		if strings.EqualFold(k, "Content-Type") {
			hasCT = true
		}
	}
	if !hasCT && w.bodyTemplate == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
