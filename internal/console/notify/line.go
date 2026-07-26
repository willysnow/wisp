package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// lineMessagingAPI is LINE's push endpoint. The older Notify service was shut
// down in 2025, so the Messaging API is the only remaining path.
const lineMessagingAPI = "https://api.line.me/v2/bot/message/push"

// lineTextLimit is the API's hard cap on a single text message.
const lineTextLimit = 5000

// LINE pushes alerts through a LINE Messaging API bot.
//
// This exists because in Taiwan and Japan, LINE is where operations teams
// actually are. An alert that arrives in the channel someone already watches
// gets acted on; one that lands in an inbox they check twice a day does not.
type LINE struct {
	token  string // channel access token
	to     string // user, group, or room ID
	client *http.Client
}

func NewLINE(token, to string) *LINE {
	return &LINE{
		token:  token,
		to:     to,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (l *LINE) Name() string { return "line" }

func (l *LINE) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal(map[string]any{
		"to": l.to,
		"messages": []map[string]any{{
			"type": "text",
			"text": l.text(a),
		}},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, lineMessagingAPI, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.token)

	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// LINE explains rejections in the body, and the reason is usually
		// actionable (expired token, bad recipient ID), so surface it.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("line returned %s: %s", resp.Status, strings.TrimSpace(string(detail)))
	}
	return nil
}

func (l *LINE) text(a Alert) string {
	var b strings.Builder

	b.WriteString("🔴 wisp alert\n")
	b.WriteString(a.Summary())
	b.WriteString("\n\n")
	for _, line := range detailLines(a) {
		b.WriteString(line)
		b.WriteString("\n")
	}

	s := b.String()
	if len(s) > lineTextLimit {
		// Truncate on a rune boundary: cutting mid-sequence would produce
		// invalid UTF-8 and the API rejects the whole message.
		s = string([]rune(s)[:lineTextLimit-20]) + "\n…[truncated]"
	}
	return s
}
