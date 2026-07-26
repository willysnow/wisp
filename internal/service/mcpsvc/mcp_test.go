package mcpsvc

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, func(string) map[string]any) {
	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "internal-tools", "1.4.2")
	})
	base := "http://" + h.Addr

	call := func(body string) map[string]any {
		t.Helper()

		resp, err := http.Post(base, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()

		var out map[string]any
		if resp.StatusCode == http.StatusAccepted {
			return nil // a notification, which gets no body by spec
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode reply to %s: %v", body, err)
		}
		return out
	}
	return h, call
}

// TestInitializeIdentifiesTheAgent.
//
// clientInfo is a much stronger identifier than a user-agent: it is the agent
// naming itself, and an attacker's tooling rarely bothers to lie about it.
func TestInitializeIdentifiesTheAgent(t *testing.T) {
	h, call := start(t)

	reply := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
		"protocolVersion":"2025-06-18",
		"clientInfo":{"name":"exfil-agent","version":"0.9"},
		"capabilities":{}}}`)

	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("initialize was refused: %v", reply)
	}
	serverInfo, _ := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "internal-tools" {
		t.Errorf("serverInfo = %v, want the configured name", serverInfo)
	}

	ev := h.WaitFor(t, "initialize")
	if ev.Data["client_name"] != "exfil-agent" && ev.Data["client"] != "exfil-agent" {
		t.Errorf("the agent's own name was not recorded: %v", ev.Data)
	}
}

// TestToolCallRecordsArguments is what the decoy is for.
//
// The advertised tools are deliberately tempting, so which one they reach for
// says what they were after — and the arguments say it in their own words.
func TestToolCallRecordsArguments(t *testing.T) {
	h, call := start(t)

	call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
		"name":"query_customer_db",
		"arguments":{"query":"SELECT email, credit_card FROM customers LIMIT 5000"}}}`)

	ev := h.WaitFor(t, "tool_call")
	if ev.Data["tool"] != "query_customer_db" {
		t.Errorf("tool = %v, want the one they chose", ev.Data["tool"])
	}
	args, _ := ev.Data["arguments"].(string)
	if !strings.Contains(args, "credit_card") {
		t.Errorf("arguments = %q, want the query they sent", args)
	}
}

// TestToolsAreTempting: a list of dull tools produces no second request, and
// the whole point is the follow-up.
func TestToolsAreTempting(t *testing.T) {
	h, call := start(t)

	reply := call(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list was refused: %v", reply)
	}

	tools, _ := result["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("no tools advertised; nothing invites a call")
	}
	for _, entry := range tools {
		tool, _ := entry.(map[string]any)
		if tool["name"] == "" || tool["description"] == "" {
			t.Errorf("tool %v is missing a name or description", tool)
		}
		if tool["inputSchema"] == nil {
			t.Errorf("tool %v has no input schema; a real client would skip it", tool["name"])
		}
	}

	h.WaitFor(t, "tools_list")
}

// TestResourceReadIsRecorded — reading a resource is the other way an agent
// takes data, and it carries the path they asked for.
func TestResourceReadIsRecorded(t *testing.T) {
	h, call := start(t)

	call(`{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{
		"uri":"file:///etc/shadow"}}`)

	ev := h.WaitFor(t, "resource_read")
	if uri, _ := ev.Data["uri"].(string); !strings.Contains(uri, "/etc/shadow") {
		t.Errorf("uri = %v, want what they asked for", ev.Data["uri"])
	}
}

// TestNotificationsGetNoReply: the JSON-RPC spec forbids answering a request
// with no id, and a client that gets one learns this is not a real server.
func TestNotificationsGetNoReply(t *testing.T) {
	h, _ := start(t)

	resp, err := http.Post("http://"+h.Addr, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("a notification returned %d, want 202 with no body", resp.StatusCode)
	}
}

// TestMalformedRequestIsRecorded: a parse failure is still someone talking to
// a port nothing legitimate talks to.
func TestMalformedRequestIsRecorded(t *testing.T) {
	h, _ := start(t)

	resp, err := http.Post("http://"+h.Addr, "application/json",
		strings.NewReader(`{"jsonrpc": "2.0", this is not json`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	ev := h.WaitFor(t, "malformed")
	if ev.Service != "mcp" {
		t.Errorf("Service = %q, want mcp", ev.Service)
	}

	var reply map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		t.Fatalf("the error reply is not JSON: %v", err)
	}
	if reply["error"] == nil {
		t.Error("a parse failure was not answered with a JSON-RPC error")
	}
}

// TestStreamChannelIsAnswered: the Streamable HTTP transport opens with a GET,
// and a client that gets a 404 there bails out before saying anything.
func TestStreamChannelIsAnswered(t *testing.T) {
	h, _ := start(t)

	resp, err := http.Get("http://" + h.Addr + "/mcp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET returned %d, want 200 so the client stays", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "event-stream") {
		t.Errorf("Content-Type = %q, want an SSE stream", ct)
	}

	ev := h.WaitFor(t, "probe")
	if path, _ := ev.Data["path"].(string); path != "/mcp" {
		t.Errorf("path = %v, want the path they probed recorded", ev.Data["path"])
	}
}
