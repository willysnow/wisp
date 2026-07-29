package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// examplePath is the file shipped for operators to copy. It is the only
// documentation most of them will read.
const examplePath = "../../wisp.example.yaml"

// TestExampleConfigHasNoUnknownKeys.
//
// yaml.v3 ignores keys it does not recognise, so a typo in the example file —
// or a key documented for a field that was later renamed — silently does
// nothing. The operator sets `docker.api_version`, restarts, and the decoy
// keeps whatever it had. Strict decoding here is the only thing that catches
// that before they do.
func TestExampleConfigHasNoUnknownKeys(t *testing.T) {
	b, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}

	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("%s: %v", filepath.Base(examplePath), err)
	}
}

// TestExampleConfigDocumentsEveryService.
//
// A service that exists in the code but not in the example file is one nobody
// knows they are running — and, when they want to turn it off or move its port,
// one they cannot find. This has already been wrong once: `k8s` and `mcp` were
// shipped enabled by default and documented nowhere.
func TestExampleConfigDocumentsEveryService(t *testing.T) {
	b, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}

	var raw struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse example: %v", err)
	}

	// The yaml tags on Services are the list of everything wisp can run.
	for _, key := range serviceKeys(t) {
		if _, ok := raw.Services[key]; !ok {
			t.Errorf("service %q is not documented in %s", key, filepath.Base(examplePath))
		}
	}
}

// TestPortscanEnabledAndDocumented. Portscan is a detector, not a service, so it
// lives outside the Services block and the loop above cannot catch it. It is on
// by default — a quiet internal segment is exactly where a sweep should alert —
// so guard both the default and its documentation here.
func TestPortscanEnabledAndDocumented(t *testing.T) {
	if !Default().Portscan.Enabled {
		t.Error("portscan is off by default; a quiet segment should flag a sweep")
	}
	if Default().Portscan.Threshold <= 0 {
		t.Error("portscan threshold default is not positive")
	}

	b, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	var raw struct {
		Portscan map[string]any `yaml:"portscan"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse example: %v", err)
	}
	if raw.Portscan == nil {
		t.Errorf("portscan is not documented in %s", filepath.Base(examplePath))
	}
}

// TestDefaultsBindDistinctPorts. Every service is enabled out of the box, so a
// duplicated default address means one of them silently fails to bind on every
// fresh install.
func TestDefaultsBindDistinctPorts(t *testing.T) {
	cfg := Default()

	seen := map[string]string{}
	check := func(name, addr string, enabled bool) {
		if !enabled || addr == "" || strings.HasSuffix(addr, ":0") {
			return
		}
		if other, clash := seen[addr]; clash {
			t.Errorf("%s and %s both default to %s", other, name, addr)
		}
		seen[addr] = name
	}

	s := cfg.Services
	check("ssh", s.SSH.Addr, s.SSH.Enabled)
	check("http", s.HTTP.Addr, s.HTTP.Enabled)
	check("https", s.HTTPS.Addr, s.HTTPS.Enabled)
	check("ollama", s.Ollama.Addr, s.Ollama.Enabled)
	check("telnet", s.Telnet.Addr, s.Telnet.Enabled)
	check("ftp", s.FTP.Addr, s.FTP.Enabled)
	check("redis", s.Redis.Addr, s.Redis.Enabled)
	check("k8s", s.K8s.Addr, s.K8s.Enabled)
	check("kubelet", s.Kubelet.Addr, s.Kubelet.Enabled)
	check("docker", s.Docker.Addr, s.Docker.Enabled)
	check("imds", s.IMDS.Addr, s.IMDS.Enabled)
	check("elasticsearch", s.Elasticsearch.Addr, s.Elasticsearch.Enabled)
	check("jenkins", s.Jenkins.Addr, s.Jenkins.Enabled)
	check("gitlab", s.GitLab.Addr, s.GitLab.Enabled)
	check("mcp", s.MCP.Addr, s.MCP.Enabled)
	check("git", s.Git.Addr, s.Git.Enabled)
	check("mongodb", s.MongoDB.Addr, s.MongoDB.Enabled)
	check("mysql", s.MySQL.Addr, s.MySQL.Enabled)
	check("mssql", s.MSSQL.Addr, s.MSSQL.Enabled)
	check("smb", s.SMB.Addr, s.SMB.Enabled)
	check("vnc", s.VNC.Addr, s.VNC.Enabled)
	check("http_proxy", s.HTTPProxy.Addr, s.HTTPProxy.Enabled)
	for _, b := range s.Banners {
		check("banner "+b.Name, b.Addr, b.Enabled)
	}

	// UDP is a separate space, so these only have to differ from each other.
	udp := map[string]string{}
	for name, addr := range map[string]string{"tftp": s.TFTP.Addr, "ntp": s.NTP.Addr, "sip": s.SIP.Addr, "snmp": s.SNMP.Addr} {
		if other, clash := udp[addr]; clash {
			t.Errorf("%s and %s both default to %s", other, name, addr)
		}
		udp[addr] = name
	}
}

// TestOmittedKeysKeepTheirDefaults. Defaults are applied before unmarshalling
// precisely so that leaving a section out does not disable it — the failure
// mode this guards against is a sensor that quietly stops emulating half of
// what its operator thinks it does.
func TestOmittedKeysKeepTheirDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wisp.yaml")
	if err := os.WriteFile(path, []byte("node: partial\nservices:\n  jenkins:\n    addr: \"0.0.0.0:9999\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, found, err := Load(path)
	if err != nil || !found {
		t.Fatalf("load: %v (found=%v)", err, found)
	}

	if cfg.Node != "partial" {
		t.Errorf("node = %q, want the configured value", cfg.Node)
	}
	if cfg.Services.Jenkins.Addr != "0.0.0.0:9999" {
		t.Errorf("jenkins addr = %q, want the override", cfg.Services.Jenkins.Addr)
	}
	if !cfg.Services.Jenkins.Enabled {
		t.Error("overriding one key of a service disabled it")
	}
	if cfg.Services.Jenkins.Version == "" {
		t.Error("overriding one key of a service cleared the others")
	}
	if !cfg.Services.Docker.Enabled || cfg.Services.Docker.Addr == "" {
		t.Error("a service the file did not mention lost its defaults")
	}
	if !cfg.Log.RateLimit.Enabled {
		t.Error("rate limiting turned itself off because the file did not mention it")
	}
}

// serviceKeys reads the yaml tags off the Services struct, so the list can
// never drift from the code the way a hand-written one would.
func serviceKeys(t *testing.T) []string {
	t.Helper()

	// Round-tripping the zero value is the cheapest way to get yaml.v3's own
	// view of the field names, tags and all.
	b, err := yaml.Marshal(Services{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var keys []string
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "-") {
			continue
		}
		key, _, ok := strings.Cut(line, ":")
		if ok {
			keys = append(keys, key)
		}
	}
	if len(keys) < 15 {
		t.Fatalf("only found %d service keys, the tag reader is broken: %v", len(keys), keys)
	}
	return keys
}
