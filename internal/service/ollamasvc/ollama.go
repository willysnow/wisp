// Package ollamasvc emulates an unauthenticated Ollama inference server.
//
// This is the service OpenCanary has no analogue for. Internal LLM
// infrastructure is deployed widely and authenticated rarely: an exposed
// Ollama endpoint is a free GPU, a pivot point, and — when it is wired to
// internal RAG — a data-exfiltration surface.
//
// The emulation deliberately answers rather than erroring. A scanner that gets
// a plausible model list will usually follow up with an actual prompt, and the
// prompt is the highest-value artifact this whole program collects: it tells
// you what the attacker wanted, in their own words.
package ollamasvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

const name = "ollama"

// maxBody caps request bodies. Prompts are small; multi-megabyte posts are an
// attack on us, not a prompt.
const maxBody = 256 << 10

// promptLimit bounds how much prompt text we copy into an event, so one huge
// request cannot bloat the event log.
const promptLimit = 4000

type Service struct {
	addr    string
	version string
}

func New(addr, version string) *Service {
	return &Service{addr: addr, version: version}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	_, dstPort := event.SplitAddr(ln.Addr())

	srv := &http.Server{
		Handler:           s.handler(dstPort, emit),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Service) handler(dstPort int, emit event.Emitter) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ev := s.baseEvent(r, dstPort, "probe")
		emit.Emit(ev)

		if r.URL.Path == "/" {
			s.header(w)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("Ollama is running"))
			return
		}
		s.jsonResponse(w, http.StatusNotFound, map[string]any{"error": "not found"})
	})

	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		emit.Emit(s.baseEvent(r, dstPort, "probe"))
		s.jsonResponse(w, http.StatusOK, map[string]any{"version": s.version})
	})

	// /api/tags is the reconnaissance call — "what models does this box have?"
	mux.HandleFunc("/api/tags", func(w http.ResponseWriter, r *http.Request) {
		emit.Emit(s.baseEvent(r, dstPort, "model_list"))
		s.jsonResponse(w, http.StatusOK, map[string]any{"models": fakeModels})
	})

	mux.HandleFunc("/api/ps", func(w http.ResponseWriter, r *http.Request) {
		emit.Emit(s.baseEvent(r, dstPort, "probe"))
		s.jsonResponse(w, http.StatusOK, map[string]any{"models": []any{}})
	})

	mux.HandleFunc("/api/show", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(w, r)
		ev := s.baseEvent(r, dstPort, "model_show")
		if m := stringField(body, "model", "name"); m != "" {
			ev.Data["model"] = m
		}
		emit.Emit(ev)
		s.jsonResponse(w, http.StatusOK, showResponse)
	})

	// The two endpoints that carry an actual prompt.
	mux.HandleFunc("/api/generate", func(w http.ResponseWriter, r *http.Request) {
		s.handlePrompt(w, r, dstPort, emit, false)
	})
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		s.handlePrompt(w, r, dstPort, emit, true)
	})

	// Model management. An attacker pulling or deleting models is trying to
	// take the box over, not just borrow it — worth its own event kind.
	for _, p := range []string{"/api/pull", "/api/push", "/api/create", "/api/copy"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			body := readBody(w, r)
			ev := s.baseEvent(r, dstPort, "model_write")
			if m := stringField(body, "model", "name"); m != "" {
				ev.Data["model"] = m
			}
			emit.Emit(ev)
			s.jsonResponse(w, http.StatusOK, map[string]any{"status": "success"})
		})
	}
	mux.HandleFunc("/api/delete", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(w, r)
		ev := s.baseEvent(r, dstPort, "model_delete")
		if m := stringField(body, "model", "name"); m != "" {
			ev.Data["model"] = m
		}
		emit.Emit(ev)
		s.jsonResponse(w, http.StatusOK, map[string]any{"status": "success"})
	})

	return mux
}

func (s *Service) handlePrompt(w http.ResponseWriter, r *http.Request, dstPort int, emit event.Emitter, chat bool) {
	body := readBody(w, r)

	ev := s.baseEvent(r, dstPort, "prompt")
	ev.Data["model"] = stringField(body, "model", "name")

	prompt := stringField(body, "prompt")
	sys := stringField(body, "system")
	if chat {
		// /api/chat carries both the prompt and the system prompt inside
		// messages[], not as top-level fields.
		prompt = lastChatMessage(body)
		if s := chatMessageByRole(body, "system"); s != "" {
			sys = s
		}
	}
	if prompt != "" {
		ev.Data["prompt"] = truncate(prompt, promptLimit)
	}
	if sys != "" {
		ev.Data["system"] = truncate(sys, promptLimit)
	}
	emit.Emit(ev)

	// Answer plausibly. A refusal or a 500 ends the interaction; a reply keeps
	// them talking, and every further prompt is more intelligence.
	reply := "I'm sorry, I can't help with that request."
	model := stringField(body, "model", "name")
	if model == "" {
		model = "llama3.2:latest"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	s.header(w)
	w.Header().Set("Content-Type", "application/x-ndjson")

	if streaming(body) {
		// Ollama streams newline-delimited JSON when "stream" is absent or true.
		enc := json.NewEncoder(w)
		flusher, _ := w.(http.Flusher)
		for _, chunk := range strings.SplitAfter(reply, " ") {
			_ = enc.Encode(streamChunk(model, now, chunk, false, chat))
			if flusher != nil {
				flusher.Flush()
			}
		}
		_ = enc.Encode(streamChunk(model, now, "", true, chat))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(streamChunk(model, now, reply, true, chat))
}

// streamChunk builds one NDJSON frame in Ollama's shape. /api/chat nests the
// text under "message"; /api/generate puts it in "response".
func streamChunk(model, created, text string, done, chat bool) map[string]any {
	m := map[string]any{
		"model":      model,
		"created_at": created,
		"done":       done,
	}
	if chat {
		m["message"] = map[string]any{"role": "assistant", "content": text}
	} else {
		m["response"] = text
	}
	if done {
		m["done_reason"] = "stop"
		m["total_duration"] = 1183246917
		m["load_duration"] = 21334084
		m["prompt_eval_count"] = 26
		m["eval_count"] = 12
	}
	return m
}

func (s *Service) baseEvent(r *http.Request, dstPort int, kind string) event.Event {
	srcIP, srcPort := event.SplitHostPortString(r.RemoteAddr)
	ev := event.NewRaw(name, kind, srcIP, srcPort, dstPort)
	ev.Data["method"] = r.Method
	ev.Data["path"] = r.URL.RequestURI()
	ev.Data["user_agent"] = r.UserAgent()
	return ev
}

func (s *Service) header(w http.ResponseWriter) {
	w.Header().Set("Server", fmt.Sprintf("ollama/%s", s.version))
}

func (s *Service) jsonResponse(w http.ResponseWriter, code int, v any) {
	s.header(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readBody decodes the JSON body, returning nil on any problem. A malformed
// body is still a recorded interaction — we just have less to say about it.
func readBody(w http.ResponseWriter, r *http.Request) map[string]any {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		return nil
	}
	return m
}

// stringField returns the first key present as a non-empty string.
func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// lastChatMessage pulls the newest non-system message content out of an
// /api/chat body. System messages are skipped because chatMessageByRole
// records them separately.
func lastChatMessage(m map[string]any) string {
	msgs, ok := m["messages"].([]any)
	if !ok {
		return ""
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		msg, ok := msgs[i].(map[string]any)
		if !ok {
			continue
		}
		if r, _ := msg["role"].(string); r == "system" {
			continue
		}
		if c, ok := msg["content"].(string); ok && c != "" {
			return c
		}
	}
	return ""
}

// chatMessageByRole returns the first message with the given role. An
// attacker-supplied system prompt is worth its own field — it is where
// jailbreak framing and assumed-capability claims show up.
func chatMessageByRole(m map[string]any, role string) string {
	msgs, ok := m["messages"].([]any)
	if !ok {
		return ""
	}
	for _, raw := range msgs {
		msg, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if r, _ := msg["role"].(string); r != role {
			continue
		}
		if c, ok := msg["content"].(string); ok && c != "" {
			return c
		}
	}
	return ""
}

// streaming reports whether the client wants NDJSON. Ollama streams by default,
// so an absent "stream" key means yes.
func streaming(m map[string]any) bool {
	v, ok := m["stream"].(bool)
	return !ok || v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// fakeModels is the inventory reported by /api/tags. Sizes and digests are
// shaped like real ones so a cursory look does not give the game away.
//
// The sizes are int64 rather than untyped constants: a 7B model is larger than
// a 32-bit int can hold, and leaving them untyped stops the whole sensor from
// compiling for 32-bit targets — which is most of the small hardware anyone
// would leave a honeypot running on.
var fakeModels = []map[string]any{
	{
		"name":        "llama3.2:latest",
		"model":       "llama3.2:latest",
		"modified_at": "2026-05-14T09:12:44.281735Z",
		"size":        int64(2019393189),
		"digest":      "a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72",
		"details": map[string]any{
			"parent_model":       "",
			"format":             "gguf",
			"family":             "llama",
			"families":           []string{"llama"},
			"parameter_size":     "3.2B",
			"quantization_level": "Q4_K_M",
		},
	},
	{
		"name":        "nomic-embed-text:latest",
		"model":       "nomic-embed-text:latest",
		"modified_at": "2026-04-02T17:03:11.904812Z",
		"size":        int64(274302450),
		"digest":      "0a109f422b47e3a30ba2b10eca18548e944e8a23073ee3f3e947efcf3c45e59f",
		"details": map[string]any{
			"parent_model":       "",
			"format":             "gguf",
			"family":             "nomic-bert",
			"families":           []string{"nomic-bert"},
			"parameter_size":     "137M",
			"quantization_level": "F16",
		},
	},
	{
		"name":        "qwen2.5-coder:7b",
		"model":       "qwen2.5-coder:7b",
		"modified_at": "2026-06-21T22:41:07.556219Z",
		"size":        int64(4683087519),
		"digest":      "2b0496514337a3d1f0bf5b1e2b1a9d8a26a1a3f9b9a4c2e6d0f8b7c5a3e1d9f7",
		"details": map[string]any{
			"parent_model":       "",
			"format":             "gguf",
			"family":             "qwen2",
			"families":           []string{"qwen2"},
			"parameter_size":     "7.6B",
			"quantization_level": "Q4_K_M",
		},
	},
}

var showResponse = map[string]any{
	"license":    "Apache License\nVersion 2.0, January 2004\n",
	"modelfile":  "# Modelfile generated by \"ollama show\"\nFROM llama3.2:latest\n",
	"parameters": "stop \"<|start_header_id|>\"\nstop \"<|end_header_id|>\"\nstop \"<|eot_id|>\"",
	"template":   "{{ .System }}\n{{ .Prompt }}",
	"details": map[string]any{
		"parent_model":       "",
		"format":             "gguf",
		"family":             "llama",
		"families":           []string{"llama"},
		"parameter_size":     "3.2B",
		"quantization_level": "Q4_K_M",
	},
}
