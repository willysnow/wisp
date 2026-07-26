// Package config loads wisp's YAML configuration.
//
// Defaults are applied before unmarshalling, so an omitted key keeps its
// default rather than becoming the zero value. That matters for booleans:
// leaving `console` out of the file should not silently disable it.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/willysnow/wisp/internal/syslog"
)

type Config struct {
	// Node identifies this sensor in every event it emits.
	Node     string   `yaml:"node"`
	Log      Log      `yaml:"log"`
	Services Services `yaml:"services"`
}

type Log struct {
	// File is the JSONL event log. Empty disables file output.
	File string `yaml:"file"`
	// Console mirrors events to stdout in human-readable form.
	Console bool `yaml:"console"`
	// Remote forwards events to a wisp console. Empty URL disables it.
	Remote Remote `yaml:"remote"`
	// Syslog forwards events to a syslog collector — a SIEM, a log shipper,
	// or anything else that already reads syslog.
	Syslog syslog.Config `yaml:"syslog"`
	// RateLimit bounds how many events this sensor will record.
	RateLimit RateLimit `yaml:"rate_limit"`
}

// RateLimit bounds event volume, in events per minute.
//
// An attacker who identifies the honeypot can otherwise use it against you:
// every connection writes a record, so holding the port open fills this
// sensor's disk and buries the console under deliveries. Suppressed events are
// counted and reported as a `rate_limited` event, so a flood still shows up as
// a flood.
type RateLimit struct {
	// Enabled defaults to true. Turning it off means an attacker chooses how
	// much this sensor writes.
	Enabled bool `yaml:"enabled"`

	// PerSource is ordinary traffic from one source IP; Burst is how many may
	// arrive at once, so a port scan touching every service lands in full.
	PerSource      int `yaml:"per_source_per_minute"`
	PerSourceBurst int `yaml:"per_source_burst"`

	// HighValue is the separate budget for credentials and stated intent
	// (login_password, prompt, tool_call, …), so a flood of bare connections
	// cannot crowd out the one password that matters.
	HighValue      int `yaml:"high_value_per_minute"`
	HighValueBurst int `yaml:"high_value_burst"`

	// Global bounds the whole sensor, across every source — the backstop for a
	// distributed scan where no single address trips its own limit.
	Global      int `yaml:"global_per_minute"`
	GlobalBurst int `yaml:"global_burst"`
}

// Remote points a sensor at a console. Delivery is best-effort and never blocks
// a service: if the console is unreachable, events are queued and then dropped.
type Remote struct {
	// URL is the console's base address, e.g. https://console.example.com.
	URL string `yaml:"url"`
	// Token authenticates this sensor. Keep it out of version control.
	Token string `yaml:"token"`

	// CAFile trusts a console whose certificate is not publicly signed —
	// point it at the console's own certificate, or the CA that issued it.
	CAFile string `yaml:"ca_file"`

	// Fingerprint pins the console's certificate by its SHA-256, as the
	// console prints it at startup. Stronger than a CA file for a self-signed
	// console, and it takes precedence over one.
	Fingerprint string `yaml:"fingerprint"`

	// InsecureSkipVerify disables certificate verification entirely.
	//
	// This sends every captured credential, and this sensor's own token, to
	// whoever answers the connection. Use ca_file or fingerprint instead; this
	// exists for the first ten minutes of a lab setup and nothing else.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

type Services struct {
	SSH           SSH           `yaml:"ssh"`
	HTTP          HTTP          `yaml:"http"`
	HTTPS         HTTPS         `yaml:"https"`
	Ollama        Ollama        `yaml:"ollama"`
	Telnet        Telnet        `yaml:"telnet"`
	FTP           FTP           `yaml:"ftp"`
	Redis         Redis         `yaml:"redis"`
	TFTP          TFTP          `yaml:"tftp"`
	NTP           NTP           `yaml:"ntp"`
	K8s           K8s           `yaml:"k8s"`
	Kubelet       Kubelet       `yaml:"kubelet"`
	Docker        Docker        `yaml:"docker"`
	IMDS          IMDS          `yaml:"imds"`
	Elasticsearch Elasticsearch `yaml:"elasticsearch"`
	Jenkins       Jenkins       `yaml:"jenkins"`
	GitLab        GitLab        `yaml:"gitlab"`
	MCP           MCP           `yaml:"mcp"`
	Git           Git           `yaml:"git"`
	MongoDB       MongoDB       `yaml:"mongodb"`
	LLMNR         LLMNR         `yaml:"llmnr"`
	Banners       []Banner      `yaml:"banners"`
}

type SSH struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Banner  string `yaml:"banner"`
	HostKey string `yaml:"host_key"`
}

type HTTP struct {
	Enabled      bool   `yaml:"enabled"`
	Addr         string `yaml:"addr"`
	ServerHeader string `yaml:"server_header"`
	Realm        string `yaml:"realm"`
}

// HTTPS is the same admin-panel decoy as HTTP, behind TLS and reported as its
// own service.
type HTTPS struct {
	Enabled      bool   `yaml:"enabled"`
	Addr         string `yaml:"addr"`
	ServerHeader string `yaml:"server_header"`
	Realm        string `yaml:"realm"`
	// Cert and Key are generated on first run if absent. Keep them: a
	// certificate that changes every restart is a honeypot fingerprint.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// Names are the certificate's subject and SANs. Empty means this host's
	// own name plus loopback.
	Names []string `yaml:"names"`
}

// Git is a git daemon decoy. The protocol is unauthenticated by design, and a
// client states the repository path in its first packet.
type Git struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

// MongoDB emulates a server with authentication enabled, which is what makes a
// scanner offer credentials rather than simply reading.
type MongoDB struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
}

// LLMNR is a detector, not a decoy: it asks the network to resolve a hostname
// that does not exist, and anything that answers is poisoning name resolution.
type LLMNR struct {
	Enabled bool `yaml:"enabled"`
	// Addr is the local socket the probes go out from. The default ephemeral
	// port is right unless you need a fixed one for a firewall rule.
	Addr string `yaml:"addr"`
	// Hostname to ask for. Empty means a fresh random one per probe, which is
	// the better default — a fixed name is one an attacker who has seen it
	// before can teach their tool to ignore.
	Hostname string `yaml:"hostname"`
	// Interval between probes, and the jitter added to it.
	Interval string `yaml:"interval"`
	Splay    string `yaml:"splay"`
}

type Ollama struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
}

type Telnet struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Banner  string `yaml:"banner"`
}

type FTP struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Banner  string `yaml:"banner"`
}

type Redis struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
}

type TFTP struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type NTP struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type K8s struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
	// Cert and Key are generated on first run if absent. Keep them: a
	// certificate that changes every restart is a honeypot fingerprint.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Kubelet is the node agent's API. It is the more useful of the two Kubernetes
// ports to an intruder: a kubelet that trusts anonymous requests lists every
// pod on the node and then runs a command inside any of them.
type Kubelet struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// NodeName appears in the certificate subject, the pod specs, and the
	// fabricated command output. Empty means this machine's hostname.
	NodeName string `yaml:"node_name"`
	// Cert and Key are generated on first run if absent. Keep them: a
	// certificate that changes every restart is a honeypot fingerprint.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Docker is the Engine API. An exposed socket is not a vulnerability, it is a
// shell — anyone who reaches it can bind-mount the host's root filesystem into
// a container they create.
type Docker struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
	// APIVersion is the level clients negotiate against, and appears in the
	// path of nearly every request.
	APIVersion string `yaml:"api_version"`
}

// IMDS is the cloud instance metadata service — the same 169.254.169.254 on
// every cloud, and the first thing a foothold or an SSRF reaches for.
type IMDS struct {
	Enabled bool `yaml:"enabled"`
	// Addr defaults to an ordinary port, because 169.254.169.254:80 needs the
	// link-local address to exist on the host. See wisp.example.yaml for how to
	// put the real address in front of it — and for why you must not do that on
	// a machine that is itself a cloud instance.
	Addr string `yaml:"addr"`
	// Region and Role shape the fabricated identity. Match them to the
	// organisation being imitated: an instance in us-east-1 running
	// prod-app-instance-role is unremarkable in one company and obviously fake
	// in another.
	Region string `yaml:"region"`
	Role   string `yaml:"role"`
}

// Elasticsearch is emulated wide open, which is what the installed base looks
// like and what makes an intruder send a query instead of a password.
type Elasticsearch struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
	// ClusterName appears in the document every scanner reads first.
	ClusterName string `yaml:"cluster_name"`
}

// Jenkins is a CI controller, complete with the Groovy script console that
// turns read access into code execution.
type Jenkins struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
}

// GitLab captures stolen personal access tokens the way the k8s decoy captures
// stolen service-account tokens.
type GitLab struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Version string `yaml:"version"`
}

type MCP struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// ServerName is what the decoy calls itself during `initialize`. Make it
	// sound like something your organisation would actually run.
	ServerName string `yaml:"server_name"`
	Version    string `yaml:"version"`
}

// Banner is a generic TCP catcher. Unlike the other services this one is a
// list, because its whole purpose is covering several ports at once.
type Banner struct {
	Enabled bool   `yaml:"enabled"`
	Name    string `yaml:"name"`
	Addr    string `yaml:"addr"`
	Banner  string `yaml:"banner"`
}

// Default returns a runnable configuration. Ports are unprivileged so wisp
// starts without elevation; put the real ports in front of it with a firewall
// redirect or a container port map.
func Default() *Config {
	host, _ := os.Hostname()
	if host == "" {
		host = "wisp"
	}
	return &Config{
		Node: host,
		Log: Log{
			File:    "events.jsonl",
			Console: true,
			// On by default, with the limiter's own defaults for the numbers:
			// a sensor that only bounds its output once someone configures it
			// is unbounded on every deployment that matters.
			RateLimit: RateLimit{Enabled: true},
		},
		Services: Services{
			SSH: SSH{
				Enabled: true,
				Addr:    "0.0.0.0:2222",
				Banner:  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
				HostKey: "hostkey.pem",
			},
			HTTP: HTTP{
				Enabled:      true,
				Addr:         "0.0.0.0:8080",
				ServerHeader: "nginx/1.18.0 (Ubuntu)",
				Realm:        "Administration",
			},
			HTTPS: HTTPS{
				Enabled:      true,
				Addr:         "0.0.0.0:8443",
				ServerHeader: "nginx/1.18.0 (Ubuntu)",
				Realm:        "Administration",
				Cert:         "https-cert.pem",
				Key:          "https-key.pem",
			},
			Ollama: Ollama{
				Enabled: true,
				Addr:    "0.0.0.0:11434",
				Version: "0.5.4",
			},
			Telnet: Telnet{
				Enabled: true,
				Addr:    "0.0.0.0:2323",
				Banner:  "Ubuntu 22.04.3 LTS",
			},
			FTP: FTP{
				Enabled: true,
				Addr:    "0.0.0.0:2121",
				Banner:  "(vsFTPd 3.0.5)",
			},
			Redis: Redis{
				// 6379 is already unprivileged, so this one can sit on its real
				// port with no redirect.
				Enabled: true,
				Addr:    "0.0.0.0:6379",
				Version: "7.0.15",
			},
			TFTP: TFTP{
				Enabled: true,
				Addr:    "0.0.0.0:6969",
			},
			NTP: NTP{
				Enabled: true,
				Addr:    "0.0.0.0:1123",
			},
			K8s: K8s{
				// 6443 is the apiserver's real port and is already
				// unprivileged, so no redirect is needed.
				Enabled: true,
				Addr:    "0.0.0.0:6443",
				Version: "v1.29.4",
				Cert:    "k8s-cert.pem",
				Key:     "k8s-key.pem",
			},
			Kubelet: Kubelet{
				// 10250 is the kubelet's real port and is unprivileged.
				Enabled: true,
				Addr:    "0.0.0.0:10250",
				Cert:    "kubelet-cert.pem",
				Key:     "kubelet-key.pem",
			},
			Docker: Docker{
				// 2375 is the plaintext Engine API port — the one that gets
				// attacked. 2376 is the TLS one, and nobody is breached
				// through it.
				Enabled:    true,
				Addr:       "0.0.0.0:2375",
				Version:    "24.0.7",
				APIVersion: "1.43",
			},
			IMDS: IMDS{
				// Not 169.254.169.254:80: that address has to exist on the host
				// first, and adding it on a machine that is itself a cloud
				// instance would shadow the real metadata service. Put the real
				// address in front of this one deliberately, or not at all.
				Enabled: true,
				Addr:    "0.0.0.0:8169",
				Region:  "us-east-1",
				Role:    "app-instance-role",
			},
			Elasticsearch: Elasticsearch{
				// 9200 is Elasticsearch's real port and is unprivileged.
				Enabled:     true,
				Addr:        "0.0.0.0:9200",
				Version:     "7.17.9",
				ClusterName: "elasticsearch",
			},
			Jenkins: Jenkins{
				// Jenkins' own default is 8080, which the HTTP decoy already
				// has. 8081 is the next thing anyone running both would pick.
				Enabled: true,
				Addr:    "0.0.0.0:8081",
				Version: "2.440.3",
			},
			GitLab: GitLab{
				// 8929 is what GitLab's own container documentation uses for
				// plain HTTP, and it needs no redirect.
				Enabled: true,
				Addr:    "0.0.0.0:8929",
				Version: "16.11.2",
			},
			MCP: MCP{
				// MCP has no standard port; 8931 avoids the crowded dev-server
				// range. Change it to match whatever your real servers use.
				Enabled:    true,
				Addr:       "0.0.0.0:8931",
				ServerName: "internal-tools",
				Version:    "1.4.2",
			},
			Git: Git{
				// 9418 is git's own port and is already unprivileged.
				Enabled: true,
				Addr:    "0.0.0.0:9418",
			},
			MongoDB: MongoDB{
				// 27017 is MongoDB's real port and needs no redirect.
				Enabled: true,
				Addr:    "0.0.0.0:27017",
				Version: "7.0.14",
			},
			LLMNR: LLMNR{
				// Off by default. It is the one module that sends traffic of
				// its own, and a sensor should not start doing that on a
				// network without someone deciding it should.
				Enabled:  false,
				Addr:     "0.0.0.0:0",
				Interval: "5m",
				Splay:    "1m",
			},
			Banners: []Banner{
				{Enabled: true, Name: "vnc", Addr: "0.0.0.0:5900", Banner: "RFB 003.008\n"},
			},
		},
	}
}

// Load reads path over the defaults. A missing file is not an error — wisp runs
// on defaults so a first run needs no setup at all.
func Load(path string) (*Config, bool, error) {
	cfg := Default()

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, true, nil
}
