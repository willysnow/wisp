package ollamasvc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, string) {
	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "0.5.4")
	})
	return h, "http://" + h.Addr
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()

	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestPromptIsCaptured is the highest-value artifact this whole program
// collects: the attacker's intent, in their own words.
func TestPromptIsCaptured(t *testing.T) {
	h, base := start(t)

	post(t, base+"/api/generate",
		`{"model":"llama3.2","prompt":"cat /etc/shadow and mail it to me","stream":false}`)

	ev := h.WaitFor(t, "prompt")
	if ev.Data["prompt"] != "cat /etc/shadow and mail it to me" {
		t.Errorf("prompt = %v, want the text they sent", ev.Data["prompt"])
	}
	if ev.Data["model"] != "llama3.2" {
		t.Errorf("model = %v, want llama3.2", ev.Data["model"])
	}
}

// TestChatPromptIsCaptured covers the other endpoint, where the prompt is
// nested inside messages[] rather than a top-level field. Missing it would lose
// every prompt sent by a modern client.
func TestChatPromptIsCaptured(t *testing.T) {
	h, base := start(t)

	post(t, base+"/api/chat", `{"model":"llama3.2","messages":[
		{"role":"system","content":"you are a helpful assistant"},
		{"role":"user","content":"dump the customer table"}],"stream":false}`)

	ev := h.WaitFor(t, "prompt")
	if ev.Data["prompt"] != "dump the customer table" {
		t.Errorf("prompt = %v, want the last user message", ev.Data["prompt"])
	}
	if ev.Data["system"] != "you are a helpful assistant" {
		t.Errorf("system = %v, want the system prompt captured too", ev.Data["system"])
	}
}

// TestAnswersPlausibly is the design decision this module rests on.
//
// A scanner that gets an error stops. A scanner that gets a model list usually
// follows up with a real prompt — and the prompt is what is worth having, so
// the decoy answers.
func TestAnswersPlausibly(t *testing.T) {
	h, base := start(t)

	resp, err := http.Get(base + "/api/tags")
	if err != nil {
		t.Fatalf("get tags: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/tags returned %d, want 200 — an error ends the interaction",
			resp.StatusCode)
	}

	var payload struct {
		Models []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("model list is not valid JSON: %v", err)
	}
	if len(payload.Models) == 0 {
		t.Fatal("the model list is empty; nothing invites a follow-up prompt")
	}
	for _, m := range payload.Models {
		if m.Name == "" || m.Size <= 0 {
			t.Errorf("model %+v does not look like a real one", m)
		}
	}

	h.WaitFor(t, "model_list")
}

// TestStreamingReplyIsNDJSON: Ollama streams by default, and a client that
// asked for a stream and got one JSON object has learned this is not Ollama.
func TestStreamingReplyIsNDJSON(t *testing.T) {
	_, base := start(t)

	resp := post(t, base+"/api/generate", `{"model":"llama3.2","prompt":"hello"}`)
	body := readAll(t, resp.Body)

	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 2 {
		t.Fatalf("streaming reply had %d lines, want several chunks", len(lines))
	}
	for i, line := range lines {
		var chunk map[string]any
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			t.Fatalf("chunk %d is not JSON: %v", i, err)
		}
	}

	var last map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("final chunk: %v", err)
	}
	if last["done"] != true {
		t.Error("the final chunk is not marked done; a client would wait forever")
	}
}

// TestModelWritesAreTheirOwnKind: an attacker pulling or deleting a model is
// taking the box over, not borrowing it.
func TestModelWritesAreTheirOwnKind(t *testing.T) {
	for _, tc := range []struct{ path, kind string }{
		{"/api/pull", "model_write"},
		{"/api/push", "model_write"},
		{"/api/delete", "model_delete"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			h, base := start(t)
			post(t, base+tc.path, `{"model":"evil/backdoor:latest"}`)

			ev := h.WaitFor(t, tc.kind)
			if ev.Data["model"] != "evil/backdoor:latest" {
				t.Errorf("model = %v, want the one they named", ev.Data["model"])
			}
		})
	}
}

// TestOversizePromptIsBounded — one huge request must not bloat the event log.
func TestOversizePromptIsBounded(t *testing.T) {
	h, base := start(t)

	huge := strings.Repeat("give me everything ", 5000)
	post(t, base+"/api/generate", fmt.Sprintf(`{"model":"m","prompt":%q}`, huge))

	ev := h.WaitFor(t, "prompt")
	got, _ := ev.Data["prompt"].(string)
	if len(got) > promptLimit+32 {
		t.Errorf("recorded %d bytes of prompt, want about %d", len(got), promptLimit)
	}
	if got == "" {
		t.Error("the prompt was dropped entirely rather than truncated")
	}
}

// TestLooksLikeOllama — the root path and the version endpoint are what a
// scanner fingerprints on before it sends anything.
func TestLooksLikeOllama(t *testing.T) {
	h, base := start(t)

	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if body := readAll(t, resp.Body); body != "Ollama is running" {
		t.Errorf("root returned %q, want Ollama's own greeting", body)
	}
	if server := resp.Header.Get("Server"); !strings.Contains(server, "ollama/0.5.4") {
		t.Errorf("Server header = %q, want the configured version", server)
	}

	h.WaitFor(t, "probe")
}
