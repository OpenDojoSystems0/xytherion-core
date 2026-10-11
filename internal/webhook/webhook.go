package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/xytherion/core/pkg/metrics"
	"github.com/xytherion/core/pkg/safenet"
)

type WebhookType string

const (
	TypeDiscord WebhookType = "discord"
	TypeSlack   WebhookType = "slack"
	TypeGeneric WebhookType = "generic"
)

type Webhook struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	URL     string      `json:"url"`
	Type    WebhookType `json:"type"`
	Enabled bool        `json:"enabled"`
}

type Manager struct {
	mu       sync.RWMutex
	webhooks []Webhook
	client   *http.Client
}

func NewManager() *Manager {
	return &Manager{
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: safenet.Transport(),
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("redirects disabled for security")
			},
		},
	}
}

func (m *Manager) Add(w Webhook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.webhooks {
		if existing.ID == w.ID {
			m.webhooks[i] = w
			return
		}
	}
	m.webhooks = append(m.webhooks, w)
}

// TryAdd adds the webhook only if the count is below max. Updates in place if ID already exists.
func (m *Manager) TryAdd(w Webhook, max int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.webhooks {
		if existing.ID == w.ID {
			m.webhooks[i] = w
			return true
		}
	}
	if len(m.webhooks) >= max {
		return false
	}
	m.webhooks = append(m.webhooks, w)
	return true
}

func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, w := range m.webhooks {
		if w.ID == id {
			m.webhooks = append(m.webhooks[:i], m.webhooks[i+1:]...)
			return
		}
	}
}

func (m *Manager) List() []Webhook {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Webhook, len(m.webhooks))
	copy(out, m.webhooks)
	return out
}

func (m *Manager) NotifyAlert(hostname string, a metrics.Alert) {
	m.mu.RLock()
	list := make([]Webhook, len(m.webhooks))
	copy(list, m.webhooks)
	m.mu.RUnlock()

	for _, w := range list {
		if !w.Enabled {
			continue
		}
		go m.send(w, hostname, a)
	}
}

func (m *Manager) send(w Webhook, hostname string, a metrics.Alert) {
	var body []byte
	var err error

	status := "ALERTE"
	emoji := "🔴"
	if !a.Active {
		status = "RÉSOLU"
		emoji = "✅"
	}

	switch w.Type {
	case TypeDiscord:
		msg := fmt.Sprintf("%s **[%s] %s** — %s\n> Valeur : **%.1f%%** (seuil : %.1f%%)\n> Serveur : `%s`",
			emoji, status, a.Metric, a.Message, a.Value, a.Threshold, hostname)
		payload := map[string]any{"content": msg}
		body, err = json.Marshal(payload)

	case TypeSlack:
		text := fmt.Sprintf("%s *[%s] %s* — %s\n*Valeur :* `%.1f%%` (seuil : `%.1f%%`) | *Serveur :* `%s`",
			emoji, status, a.Metric, a.Message, a.Value, a.Threshold, hostname)
		payload := map[string]any{"text": text}
		body, err = json.Marshal(payload)

	default: // generic JSON
		payload := map[string]any{
			"hostname":  hostname,
			"status":    status,
			"alert":     a,
			"timestamp": time.Now().UTC(),
		}
		body, err = json.Marshal(payload)
	}

	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", w.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) //nolint:errcheck
	resp.Body.Close()
}
