package elasticsvc

import (
	"fmt"
	"strings"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

// The cluster's fabricated contents.
//
// The index list is the bait: `_cat/indices` is what turns "there is an
// Elasticsearch here" into "there is an index called customers here", and an
// intruder who sees only `.kibana_1` closes the tab.
//
// The documents behind it are a deliberately small corpus. Three per index,
// invented, pointing at a company that does not exist. Fabricating a convincing
// million-record dataset is a project of its own, and it would buy very little:
// the query is the artifact worth having, and it is captured on the request
// that asks for the first page. What the documents have to do is be plausible
// enough that the request after the first one still happens.

// indices is what the cluster claims to hold. The counts and sizes are what
// `_cat/indices` reports and what `_search` says its total is, so the two never
// contradict each other.
var indices = []struct {
	name    string
	docs    int
	sizeMB  int
	deleted int
}{
	{"customers", 1284219, 1126, 4188},
	{"orders-2026.07", 418822, 402, 0},
	{"payments-audit", 2891044, 3140, 217},
	{"app-logs-2026.07.26", 9114882, 8830, 0},
	{"filebeat-7.17.9-2026.07.26", 4218804, 4092, 0},
	{".kibana_1", 214, 1, 12},
}

func (s *Service) clusterInfo() map[string]any {
	return map[string]any{
		"name":         s.nodeName,
		"cluster_name": s.clusterName,
		"cluster_uuid": s.clusterUUID,
		"version": map[string]any{
			"number":                              s.version,
			"build_flavor":                        "default",
			"build_type":                          "docker",
			"build_hash":                          "ef48222227ee6b9e70e502f0f0daa52435ee634d",
			"build_date":                          "2026-02-08T10:12:31.318267Z",
			"build_snapshot":                      false,
			"lucene_version":                      "8.11.1",
			"minimum_wire_compatibility_version":  "6.8.0",
			"minimum_index_compatibility_version": "6.0.0-beta1",
		},
		"tagline": "You Know, for Search",
	}
}

// clusterDetail answers the enumeration endpoints. Each one has to return the
// shape its client expects — a client that cannot parse the answer stops asking
// questions, and the questions are the product.
func (s *Service) clusterDetail(seg []string) any {
	what := ""
	if len(seg) > 1 {
		what = seg[1]
	}

	switch {
	case seg[0] == "_cluster" && what == "health":
		return map[string]any{
			"cluster_name":                     s.clusterName,
			"status":                           "yellow",
			"timed_out":                        false,
			"number_of_nodes":                  1,
			"number_of_data_nodes":             1,
			"active_primary_shards":            len(indices),
			"active_shards":                    len(indices),
			"relocating_shards":                0,
			"initializing_shards":              0,
			"unassigned_shards":                len(indices),
			"delayed_unassigned_shards":        0,
			"number_of_pending_tasks":          0,
			"number_of_in_flight_fetch":        0,
			"task_max_waiting_in_queue_millis": 0,
			"active_shards_percent_as_number":  50.0,
		}

	case seg[0] == "_nodes":
		return map[string]any{
			"_nodes":       map[string]any{"total": 1, "successful": 1, "failed": 0},
			"cluster_name": s.clusterName,
			"nodes": map[string]any{
				httpdecoy.StableID(s.nodeName, 22): map[string]any{
					"name":              s.nodeName,
					"transport_address": "10.0.4.42:9300",
					"host":              "10.0.4.42",
					"ip":                "10.0.4.42",
					"version":           s.version,
					"build_flavor":      "default",
					"build_type":        "docker",
					"roles":             []string{"data", "ingest", "master", "remote_cluster_client"},
					"os": map[string]any{
						"name": "Linux", "arch": "amd64", "version": "5.15.0-113-generic",
						"available_processors": 8,
					},
					"jvm": map[string]any{"version": "19.0.2", "vm_name": "OpenJDK 64-Bit Server VM"},
				},
			},
		}

	case seg[0] == "_mapping", seg[0] == "_settings":
		out := map[string]any{}
		for _, idx := range indices {
			out[idx.name] = s.mapping(idx.name)[idx.name]
		}
		return out

	case seg[0] == "_alias", seg[0] == "_aliases":
		out := map[string]any{}
		for _, idx := range indices {
			out[idx.name] = map[string]any{"aliases": map[string]any{}}
		}
		return out

	case seg[0] == "_stats":
		return map[string]any{
			"_shards": shards(),
			"_all": map[string]any{
				"primaries": map[string]any{"docs": map[string]any{"count": totalDocs()}},
				"total":     map[string]any{"docs": map[string]any{"count": totalDocs()}},
			},
		}

	default:
		return map[string]any{"acknowledged": true}
	}
}

// securityDetail answers the endpoints an intruder uses to find out whether the
// cluster has any access control at all. A cluster without the security feature
// installed refuses these in a particular way, and reproducing that refusal is
// how the decoy stays consistent with being wide open.
func (s *Service) securityDetail(seg []string) any {
	switch seg[0] {
	case "_xpack":
		return map[string]any{
			"build":    map[string]any{"hash": "ef48222", "date": "2026-02-08T10:12:31.318267Z"},
			"license":  map[string]any{"uid": httpdecoy.StableID("license", 36), "type": "basic", "mode": "basic", "status": "active"},
			"features": map[string]any{"security": map[string]any{"available": true, "enabled": false}},
			"tagline":  "You know, for X",
		}
	case "_license":
		return map[string]any{
			"license": map[string]any{
				"status": "active", "uid": httpdecoy.StableID("license", 36),
				"type": "basic", "issue_date": "2025-11-02T00:00:00.000Z",
				"max_nodes": 1000, "issued_to": s.clusterName, "issuer": "elasticsearch",
				"start_date_in_millis": -1,
			},
		}
	default:
		// `_security/user` on a cluster with security disabled.
		return map[string]any{
			"error": map[string]any{
				"root_cause": []map[string]any{{
					"type":   "exception",
					"reason": "Security must be explicitly enabled when using a [basic] license. Enable security by setting [xpack.security.enabled] to [true] in the elasticsearch.yml file and restart the node.",
				}},
				"type":   "exception",
				"reason": "Security must be explicitly enabled when using a [basic] license.",
			},
			"status": 405,
		}
	}
}

func (s *Service) mapping(index string) map[string]any {
	properties := map[string]any{
		"@timestamp": map[string]any{"type": "date"},
		"message":    map[string]any{"type": "text"},
	}
	if isRecordIndex(index) {
		properties = map[string]any{
			"id":         map[string]any{"type": "keyword"},
			"name":       map[string]any{"type": "text"},
			"email":      map[string]any{"type": "keyword"},
			"phone":      map[string]any{"type": "keyword"},
			"card_last4": map[string]any{"type": "keyword"},
			"plan":       map[string]any{"type": "keyword"},
			"created":    map[string]any{"type": "date"},
		}
	}

	return map[string]any{
		index: map[string]any{
			"aliases":  map[string]any{},
			"mappings": map[string]any{"properties": properties},
			"settings": map[string]any{
				"index": map[string]any{
					"routing":            map[string]any{"allocation": map[string]any{"include": map[string]any{"_tier_preference": "data_content"}}},
					"number_of_shards":   "1",
					"provided_name":      index,
					"creation_date":      "1767225600000",
					"number_of_replicas": "1",
					"uuid":               httpdecoy.StableID(index, 22),
					"version":            map[string]any{"created": "7170999"},
				},
			},
		},
	}
}

func (s *Service) searchResult(index string) map[string]any {
	hits := make([]map[string]any, 0, 3)
	for i := 0; i < 3; i++ {
		hits = append(hits, s.document(index, i))
	}

	return map[string]any{
		"took":      13,
		"timed_out": false,
		"_shards":   shards(),
		"hits": map[string]any{
			"total":     map[string]any{"value": docCount(index), "relation": "eq"},
			"max_score": 1.0,
			"hits":      hits,
		},
	}
}

func (s *Service) document(index string, i int) map[string]any {
	source := map[string]any{
		"@timestamp": "2026-07-26T09:14:0" + fmt.Sprint(i) + ".118Z",
		"level":      "INFO",
		"service":    "payments-api",
		"message":    "200 GET /v1/charges 12.4ms",
	}
	if isRecordIndex(index) {
		source = records[i%len(records)]
	}

	return map[string]any{
		"_index":  index,
		"_id":     httpdecoy.StableID(index+fmt.Sprint(i), 20),
		"_score":  1.0,
		"_source": source,
	}
}

// isRecordIndex decides which corpus a hit comes from. An index called
// `app-logs-…` full of customer records would be as much of a tell as a
// `customers` index full of HTTP status lines.
func isRecordIndex(index string) bool {
	for _, name := range []string{"customer", "order", "payment", "user", "account", "invoice"} {
		if strings.Contains(strings.ToLower(index), name) {
			return true
		}
	}
	return false
}

// records is the whole fabricated corpus: three people who do not exist, at a
// company that does not exist. See the note at the top of this file for why it
// is three and not three million.
var records = []map[string]any{
	{
		"id": "cus_8H2kQ1vRt", "name": "Marcus Webb", "email": "m.webb@brightline-logistics.example",
		"phone": "+1-206-555-0164", "card_last4": "4417", "plan": "enterprise",
		"created": "2024-03-11T14:02:19Z",
	},
	{
		"id": "cus_3Yq7Lp9Wd", "name": "Priya Raghunathan", "email": "praghunathan@northaxis-supply.example",
		"phone": "+44-20-7946-0288", "card_last4": "9052", "plan": "growth",
		"created": "2025-01-27T08:41:53Z",
	},
	{
		"id": "cus_5Nb4Fz2Kx", "name": "Tomás Ferreira", "email": "t.ferreira@vellum-analytics.example",
		"phone": "+351-21-000-0193", "card_last4": "1188", "plan": "starter",
		"created": "2025-09-04T19:23:07Z",
	},
}

func docCount(index string) int {
	for _, idx := range indices {
		if idx.name == index {
			return idx.docs
		}
	}
	if index == "_all" || index == "*" || index == "" {
		return totalDocs()
	}
	// An index the decoy has never heard of still has to answer with something
	// consistent, or a second query to the same name would contradict the first.
	return 1 + int(httpdecoy.StableID(index, 4)[0])*137
}

func totalDocs() int {
	total := 0
	for _, idx := range indices {
		total += idx.docs
	}
	return total
}

func shards() map[string]any {
	return map[string]any{"total": len(indices), "successful": len(indices), "skipped": 0, "failed": 0}
}

// catText renders the `_cat` tables. The column widths are not the real ones —
// Elasticsearch pads to content — but the columns and their order are, and that
// is what anything parsing this output reads.
func catText(what string, verbose bool) string {
	var b strings.Builder

	switch what {
	case "indices":
		if verbose {
			b.WriteString("health status index                          uuid                   pri rep docs.count docs.deleted store.size pri.store.size\n")
		}
		for _, idx := range indices {
			health := "yellow"
			if strings.HasPrefix(idx.name, ".") {
				health = "green"
			}
			fmt.Fprintf(&b, "%-6s open   %-30s %-22s   1   1 %10d %12d %9s %14s\n",
				health, idx.name, httpdecoy.StableID(idx.name, 22), idx.docs, idx.deleted,
				size(idx.sizeMB), size(idx.sizeMB/2))
		}

	case "nodes":
		if verbose {
			b.WriteString("ip         heap.percent ram.percent cpu load_1m load_5m load_15m node.role   master name\n")
		}
		b.WriteString("10.0.4.42            41          92   3    0.31    0.44     0.39 cdfhilmrstw *      es-data-01\n")

	case "health":
		if verbose {
			b.WriteString("epoch      timestamp cluster       status node.total node.data shards pri relo init unassign pending_tasks max_task_wait_time active_shards_percent\n")
		}
		fmt.Fprintf(&b, "1784511240 09:14:00  elasticsearch yellow          1         1      %d   %d    0    0        %d             0                  -                 50.0%%\n",
			len(indices), len(indices), len(indices))

	case "aliases", "shards", "allocation", "master", "count", "":
		// `_cat` with no argument lists the endpoints, which is a fingerprint of
		// its own — nothing else answers a bare GET with a menu like this.
		b.WriteString(catIndex)

	default:
		b.WriteString("\n")
	}

	return b.String()
}

func catJSON(what string) any {
	if what != "indices" {
		return []any{}
	}

	out := make([]map[string]any, 0, len(indices))
	for _, idx := range indices {
		health := "yellow"
		if strings.HasPrefix(idx.name, ".") {
			health = "green"
		}
		out = append(out, map[string]any{
			"health": health, "status": "open", "index": idx.name,
			"uuid": httpdecoy.StableID(idx.name, 22), "pri": "1", "rep": "1",
			"docs.count": fmt.Sprint(idx.docs), "docs.deleted": fmt.Sprint(idx.deleted),
			"store.size": size(idx.sizeMB), "pri.store.size": size(idx.sizeMB / 2),
		})
	}
	return out
}

func size(mb int) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fgb", float64(mb)/1024)
	}
	return fmt.Sprintf("%dmb", mb)
}

const catIndex = `=^.^=
/_cat/allocation
/_cat/shards
/_cat/shards/{index}
/_cat/master
/_cat/nodes
/_cat/tasks
/_cat/indices
/_cat/indices/{index}
/_cat/segments
/_cat/count
/_cat/count/{index}
/_cat/health
/_cat/aliases
/_cat/thread_pool
`

// base64ish renders a stable identifier in the alphabet Elasticsearch uses for
// cluster and index UUIDs, so it looks like one rather than like plain hex.
func base64ish(seed string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	hex := httpdecoy.StableID(seed, 22)
	out := make([]byte, 0, 22)
	for i := 0; i < len(hex); i++ {
		out = append(out, alphabet[(int(hex[i])*17+i*3)%len(alphabet)])
	}
	return string(out)
}
