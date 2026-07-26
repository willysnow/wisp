package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Webhook posts alerts as JSON. It also backs the Slack, Teams, and Discord
// notifiers, which are the same mechanism with a different body shape.
type Webhook struct {
	name   string
	url    string
	format Format
	client *http.Client
}

// Format selects the request body shape.
type Format string

const (
	// FormatJSON sends wisp's own event structure. Use this for your own
	// endpoint or an automation platform.
	FormatJSON Format = "json"
	// FormatSlack sends Slack's incoming-webhook shape, which Mattermost also
	// accepts.
	FormatSlack Format = "slack"
	// FormatTeams sends a MessageCard, which Microsoft Teams renders.
	FormatTeams Format = "teams"
	// FormatDiscord sends Discord's webhook shape.
	FormatDiscord Format = "discord"
)

func NewWebhook(name, url string, format Format) *Webhook {
	if format == "" {
		format = FormatJSON
	}
	return &Webhook{
		name:   name,
		url:    url,
		format: format,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (w *Webhook) Name() string { return w.name }

func (w *Webhook) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal(w.body(a))
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", w.name, resp.Status)
	}
	return nil
}

func (w *Webhook) body(a Alert) any {
	switch w.format {
	case FormatSlack:
		return map[string]any{
			"text": ":rotating_light: *wisp alert* — " + a.Summary(),
			"attachments": []map[string]any{{
				"color": "danger",
				"text":  "```" + strings.Join(detailLines(a), "\n") + "```",
			}},
		}

	case FormatTeams:
		return map[string]any{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"themeColor": "D93F0B",
			"summary":    "wisp alert",
			"title":      "wisp alert — " + a.Summary(),
			"text":       "<pre>" + strings.Join(detailLines(a), "\n") + "</pre>",
		}

	case FormatDiscord:
		return map[string]any{
			"content": "**wisp alert** — " + a.Summary(),
			"embeds": []map[string]any{{
				"color":       0xD93F0B,
				"description": "```" + strings.Join(detailLines(a), "\n") + "```",
			}},
		}
	}

	return map[string]any{
		"summary":  a.Summary(),
		"repeated": a.Repeated,
		"event":    a.Event,
	}
}

// detailLines renders an event's fields in a stable order for the message body.
func detailLines(a Alert) []string {
	e := a.Event
	lines := []string{
		"time    " + e.Time.Format(time.RFC3339),
		"sensor  " + e.Node,
		"service " + e.Service,
		"kind    " + e.Kind,
		fmt.Sprintf("source  %s:%d -> :%d", e.SrcIP, e.SrcPort, e.DstPort),
	}

	keys := make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := fmt.Sprint(e.Data[k])
		if len(v) > 300 {
			v = v[:300] + "..."
		}
		lines = append(lines, fmt.Sprintf("%-7s %s", k, v))
	}
	return lines
}
