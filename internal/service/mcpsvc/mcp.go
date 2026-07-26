// Package mcpsvc emulates an unauthenticated MCP (Model Context Protocol)
// server.
//
// MCP servers are proliferating inside company networks faster than anyone is
// securing them: they are usually stood up by a developer, bound to 0.0.0.0,
// and given no authentication at all - while being wired to exactly the systems
// worth stealing from (databases, document stores, mail, ticketing).
//
// Two things make this decoy unusually informative:
//
//   - `initialize` carries clientInfo, which names the agent on the other end
//     (Claude Desktop, Cursor, a custom script). That is a far stronger
//     identifier than a user-agent string.
//   - `tools/call` carries the tool name and its arguments. Like the prompt in
//     the Ollama decoy, this is the attacker stating their intent in their own
//     words - "query_customer_db with SELECT * FROM customers" is not ambiguous.
//
// The advertised tools are deliberately tempting. Nothing executes and no data
// exists; every call returns an empty or denied result, which keeps the caller
// working through the tool list where we can watch.
package mcpsvc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/willysnow/wisp/internal/event"
)

const name = "mcp"

// maxBody caps a request. JSON-RPC calls are small.
const maxBody = 256 << 10

// argLogLimit bounds how much of a tool's arguments reaches the event log.
const argLogLimit = 4000

// JSON-RPC 2.0 error codes used here.
const (
	errMethodNotFound = -32601
	errParseError     = -32700
)

type Service struct {
	addr       string
	serverName string
	version    string
}

func New(addr, serverName, version string) *Service {
	return &Service{addr: addr, serverName: serverName, version: version}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	_, dstPort := event.SplitAddr(ln.Addr())

	srv := &http.Server{
		Handler:           s.handler(dstPort, emit),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
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

// request is the subset of JSON-RPC 2.0 this decoy needs. A missing ID means a
// notification, which by spec gets no response.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (s *Service) handler(dstPort int, emit event.Emitter) http.Handler {
	mux := http.NewServeMux()

	// Everything is handled at the root: MCP has no standardised path, so
	// logging whatever path was probed is itself useful.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// GET is the Streamable HTTP transport's SSE channel. Answering it
			// keeps a client that opens the stream first from bailing out.
			emit.Emit(s.baseEvent(r, dstPort, "probe"))
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ev := s.baseEvent(r, dstPort, "malformed")
			emit.Emit(ev)
			writeJSON(w, errorResponse(nil, errParseError, "Parse error"))
			return
		}

		ev := s.baseEvent(r, dstPort, "request")
		ev.Data["rpc_method"] = req.Method

		result, rpcErr, respond := s.dispatch(req, &ev)
		emit.Emit(ev)

		// Notifications carry no ID and must not be answered.
		if !respond || len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if rpcErr != nil {
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": rpcErr})
			return
		}
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})

	return mux
}

// dispatch produces the result for a method and enriches ev with whatever that
// method revealed. It returns respond=false for notifications, and a non-nil
// rpcErr for methods a real server would reject.
func (s *Service) dispatch(req request, ev *event.Event) (result any, rpcErr map[string]any, respond bool) {
	switch req.Method {
	case "initialize":
		// clientInfo names the agent on the other end.
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		_ = json.Unmarshal(req.Params, &p)

		ev.Kind = "initialize"
		if p.ClientInfo.Name != "" {
			ev.Data["client_name"] = p.ClientInfo.Name
			ev.Data["client_version"] = p.ClientInfo.Version
		}
		ev.Data["protocol_version"] = p.ProtocolVersion

		return map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
			"serverInfo": map[string]any{"name": s.serverName, "version": s.version},
		}, nil, true

	case "tools/list":
		ev.Kind = "tools_list"
		return map[string]any{"tools": fakeTools}, nil, true

	case "tools/call":
		// The payload. Tool name plus arguments is the attacker's intent,
		// stated explicitly.
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)

		ev.Kind = "tool_call"
		ev.Data["tool"] = p.Name
		if len(p.Arguments) > 0 {
			ev.Data["arguments"] = truncate(string(p.Arguments), argLogLimit)
		}

		return map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": "No results. The connected backend returned an empty response.",
			}},
			"isError": false,
		}, nil, true

	case "resources/list":
		ev.Kind = "resources_list"
		return map[string]any{"resources": fakeResources}, nil, true

	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(req.Params, &p)

		ev.Kind = "resource_read"
		ev.Data["uri"] = p.URI

		return map[string]any{
			"contents": []map[string]any{{
				"uri":      p.URI,
				"mimeType": "text/plain",
				"text":     "",
			}},
		}, nil, true

	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil, true

	case "ping":
		return map[string]any{}, nil, true

	case "notifications/initialized", "notifications/cancelled":
		ev.Kind = "notification"
		return nil, nil, false
	}

	// A real server rejects unknown methods rather than returning an empty
	// result, and a client that gets a bare {} may decide the server is broken
	// and disconnect.
	return nil, map[string]any{
		"code":    errMethodNotFound,
		"message": "Method not found: " + req.Method,
	}, true
}

func (s *Service) baseEvent(r *http.Request, dstPort int, kind string) event.Event {
	srcIP, srcPort := event.SplitHostPortString(r.RemoteAddr)
	ev := event.NewRaw(name, kind, srcIP, srcPort, dstPort)
	ev.Data["method"] = r.Method
	ev.Data["path"] = r.URL.RequestURI()
	ev.Data["user_agent"] = r.UserAgent()
	return ev
}

// fakeTools is the advertised inventory. These are chosen to be exactly what an
// attacker who stumbles onto an open MCP server would want to call, so that the
// tool they pick tells you what they were after.
var fakeTools = []map[string]any{
	{
		"name":        "query_customer_db",
		"description": "Run a read-only SQL query against the customer database.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string", "description": "SQL SELECT statement"},
			},
			"required": []string{"query"},
		},
	},
	{
		"name":        "read_document",
		"description": "Read a document from the internal knowledge base by path.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string", "description": "Document path"},
			},
			"required": []string{"path"},
		},
	},
	{
		"name":        "list_employees",
		"description": "List employee records, including contact details and department.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"department": map[string]any{"type": "string"}},
		},
	},
	{
		"name":        "send_email",
		"description": "Send an email from the company support address.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"to":      map[string]any{"type": "string"},
				"subject": map[string]any{"type": "string"},
				"body":    map[string]any{"type": "string"},
			},
			"required": []string{"to", "subject", "body"},
		},
	},
}

var fakeResources = []map[string]any{
	{
		"uri":         "file:///srv/knowledge/employee-handbook.md",
		"name":        "Employee Handbook",
		"mimeType":    "text/markdown",
		"description": "Internal policies and procedures.",
	},
	{
		"uri":         "file:///srv/knowledge/integration-credentials.md",
		"name":        "Integration Credentials",
		"mimeType":    "text/markdown",
		"description": "API keys and connection strings for connected services.",
	},
}

func errorResponse(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
