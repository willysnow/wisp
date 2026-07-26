// Package elasticsvc emulates an unauthenticated Elasticsearch cluster on 9200.
//
// Open Elasticsearch is how a large share of the last decade's "unsecured
// database exposed N million records" stories start. Before 8.x, security was a
// paid feature and then an opt-in one, so an enormous installed base answers
// port 9200 to anyone who asks — and the two things that happen to it are data
// theft and ransom: wipe every index, write one back called `read_me`, wait.
//
// So this decoy is open. That is a deliberate departure from the reasoning
// behind the Kubernetes and MongoDB decoys, which demand credentials precisely
// so that credentials get offered. Here the credential is not the prize:
//
//	elasticsearch  search_query  index=customers
//	               query={"query":{"match_all":{}},"_source":["email","card_last4"],"size":10000}
//
// That is the intruder writing down what they came for, field by field. A
// cluster that asked for a password would have got a 401 in their scanner's log
// and nothing else. When a request does carry credentials they are captured
// too, and the request is still answered — an open cluster does not start
// checking passwords because someone sent one.
//
// Nothing is stored, nothing is deleted, and every index is fictional.
package elasticsvc

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "elasticsearch"

// queryLimit bounds how much of a submitted query reaches the log. Real ones
// are a few hundred bytes; a very large one is a generated payload, and its
// beginning says what it is.
const queryLimit = 8000

type Service struct {
	addr        string
	version     string
	clusterName string
	nodeName    string
	clusterUUID string
}

// New builds the decoy. version matters more than it looks: 8.x has security on
// by default, so a wide-open 8.x cluster is slightly implausible, while a 7.x
// one is the single most common thing on the internet's port 9200.
func New(addr, version, clusterName string) *Service {
	if version == "" {
		version = "7.17.9"
	}
	if clusterName == "" {
		clusterName = "elasticsearch"
	}
	return &Service{
		addr:        addr,
		version:     version,
		clusterName: clusterName,
		nodeName:    "es-data-01",
		clusterUUID: base64ish(clusterName + version),
	}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	rec := httpdecoy.NewRecorder(name, ln, emit)
	return httpdecoy.Serve(ctx, ln, s.handler(rec), nil)
}

func (s *Service) handler(rec *httpdecoy.Recorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")

		seg := segments(r.URL.Path)
		if len(seg) == 0 {
			// The cluster info document. This is what Shodan indexes, what
			// every scanner reads first, and the only endpoint some of them
			// ever call.
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusOK, s.clusterInfo())
			return
		}

		switch seg[0] {
		case "_cat":
			s.cat(w, r, rec, seg[1:])

		case "_search", "_msearch", "_count", "_sql", "_async_search", "_field_caps":
			s.search(w, r, rec, "_all", seg[0])

		case "_bulk":
			s.write(w, r, rec, "_all")

		case "_cluster", "_nodes", "_alias", "_aliases", "_mapping", "_settings",
			"_stats", "_tasks", "_template", "_index_template", "_resolve", "_remote":
			rec.Emit(rec.Event(r, "discovery"))
			httpdecoy.WriteJSON(w, http.StatusOK, s.clusterDetail(seg))

		// The user store. Asking for it is a credential hunt, and on a cluster
		// without security installed the answer is a 400 rather than a 403 —
		// which itself confirms the cluster is open.
		case "_security", "_xpack", "_license", "_ssl":
			rec.Emit(rec.Event(r, "resource_read"))
			httpdecoy.WriteJSON(w, http.StatusOK, s.securityDetail(seg))

		// Snapshot repositories are the tidy way to take a copy of everything:
		// register a repository the intruder controls, snapshot into it, walk
		// away with the whole cluster.
		case "_snapshot":
			kind := "resource_access"
			if r.Method == http.MethodPut || r.Method == http.MethodPost {
				kind = "write_request"
			}
			ev := rec.Event(r, kind)
			ev.Data["repository"] = strings.Join(seg[1:], "/")
			if body := httpdecoy.Body(w, r); len(body) > 0 {
				ev.Data["body"] = httpdecoy.Truncate(string(body), queryLimit)
			}
			rec.Emit(ev)
			httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"acknowledged": true})

		default:
			s.index(w, r, rec, seg)
		}
	})
	return mux
}

// index handles everything scoped to one index or index pattern, which is where
// the search, the wipe, and the ransom note all live.
func (s *Service) index(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, seg []string) {
	target := seg[0]
	action := ""
	if len(seg) > 1 {
		action = seg[1]
	}

	switch {
	case action == "_search", action == "_count", action == "_msearch",
		action == "_async_search", action == "_field_caps", action == "_terms_enum":
		s.search(w, r, rec, target, action)

	case action == "_doc", action == "_source", action == "_mget":
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			s.write(w, r, rec, target)
			return
		}
		ev := rec.Event(r, "resource_read")
		ev.Data["index"] = target
		if len(seg) > 2 {
			ev.Data["document"] = seg[2]
		}
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, s.document(target, 0))

	case action == "_bulk", action == "_update", action == "_update_by_query", action == "_create":
		s.write(w, r, rec, target)

	case action == "_delete_by_query":
		s.delete(w, r, rec, target)

	case r.Method == http.MethodDelete:
		// The wipe. On a real cluster `DELETE /*` empties it in one request,
		// which is the first half of every Elasticsearch ransom.
		s.delete(w, r, rec, target)

	case r.Method == http.MethodPut, r.Method == http.MethodPost:
		s.write(w, r, rec, target)

	default:
		ev := rec.Event(r, "resource_access")
		ev.Data["index"] = target
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, s.mapping(target))
	}
}

// search records the query and answers with a small fabricated result set.
func (s *Service) search(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, target, action string) {
	body := strings.TrimSpace(string(httpdecoy.Body(w, r)))

	ev := rec.Event(r, "search_query")
	ev.Data["index"] = target

	// A query arrives in the body for POST, in `q` for a URI search, and in
	// `source` for clients that cannot send a body at all — which includes
	// every request forged through someone else's application.
	query := body
	if query == "" {
		query = r.URL.Query().Get("source")
	}
	if query == "" {
		query = r.URL.Query().Get("q")
	}
	if query != "" {
		ev.Data["query"] = httpdecoy.Truncate(query, queryLimit)
	}
	// How much they asked for separates a look from an extraction.
	if size := r.URL.Query().Get("size"); size != "" {
		ev.Data["size"] = size
	}
	if fields := r.URL.Query().Get("_source"); fields != "" {
		ev.Data["fields"] = httpdecoy.Truncate(fields, httpdecoy.FieldLimit)
	}
	rec.Emit(ev)

	if action == "_count" {
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"count":   docCount(target),
			"_shards": shards(),
		})
		return
	}
	httpdecoy.WriteJSON(w, http.StatusOK, s.searchResult(target))
}

func (s *Service) write(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, target string) {
	ev := rec.Event(r, "write_request")
	ev.Data["index"] = target
	if body := httpdecoy.Body(w, r); len(body) > 0 {
		// The body of a write to a cluster the intruder has just emptied is the
		// ransom note, and it carries the wallet address.
		ev.Data["body"] = httpdecoy.Truncate(string(body), queryLimit)
	}
	rec.Emit(ev)

	httpdecoy.WriteJSON(w, http.StatusCreated, map[string]any{
		"_index":        target,
		"_id":           httpdecoy.StableID(target, 20),
		"_version":      1,
		"result":        "created",
		"_shards":       shards(),
		"_seq_no":       0,
		"_primary_term": 1,
	})
}

func (s *Service) delete(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, target string) {
	ev := rec.Event(r, "delete_request")
	ev.Data["index"] = target
	if target == "*" || target == "_all" {
		// One request that would have emptied the cluster. Worth saying so in
		// the event rather than leaving it implied by an asterisk.
		ev.Data["scope"] = "every index"
	}
	rec.Emit(ev)

	httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"acknowledged": true})
}

// cat serves the `_cat` API, which is the one humans use. `_cat/indices` is the
// call that turns "there is an Elasticsearch here" into "there is an index
// called customers here".
func (s *Service) cat(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, seg []string) {
	rec.Emit(rec.Event(r, "discovery"))

	what := ""
	if len(seg) > 0 {
		what = seg[0]
	}
	verbose := r.URL.Query().Has("v")

	if r.URL.Query().Get("format") == "json" {
		httpdecoy.WriteJSON(w, http.StatusOK, catJSON(what))
		return
	}
	httpdecoy.WriteText(w, http.StatusOK, catText(what, verbose))
}

func segments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}
