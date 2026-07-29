// Package config loads wisp's YAML configuration.
//
// Defaults are applied before unmarshalling, so an omitted key keeps its
// default rather than becoming the zero value. That matters for booleans:
// leaving `console` out of the file should not silently disable it.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/willysnow/wisp/internal/persona"
	"github.com/willysnow/wisp/internal/syslog"
)

type Config struct {
	// Node identifies this sensor in every event it emits.
	Node string `yaml:"node"`
	// Device is what this sensor pretends to be, on every port at once.
	Device   Device   `yaml:"device"`
	Log      Log      `yaml:"log"`
	Services Services `yaml:"services"`
	// Portscan is a detector, not a listener, so it sits beside Services rather
	// than in it — it binds no port and correlates the events the others emit.
	Portscan Portscan `yaml:"portscan"`
}

// Portscan flags a source that sweeps many of the sensor's ports in a short
// window. It is not a service: it binds nothing and captures no packets, it
// watches the events every decoy already emits. That makes it cross-platform
// and unprivileged, at the cost of only seeing the ports wisp binds and only
// scans that complete a connection — a stealth SYN scan to an unbound port is
// invisible to it, which is why its events say `method=connect`.
type Portscan struct {
	// Enabled defaults to true. A quiet internal segment is exactly where a
	// sweep across the decoy's ports is worth an alert.
	Enabled bool `yaml:"enabled"`
	// Threshold is how many distinct ports one source must touch, within Window,
	// to count as a scan. Zero uses the built-in default.
	Threshold int    `yaml:"threshold"`
	Window    string `yaml:"window"`
	// Cooldown is the least time between portscan events for one source, so a
	// thousand-port sweep is one alert, not nine hundred.
	Cooldown string `yaml:"cooldown"`
	// IgnoreSources are never treated as scanners — monitoring, health checks,
	// loopback.
	IgnoreSources []string `yaml:"ignore_sources"`
}

// Device gives the sensor one identity instead of several.
//
// Left to themselves the emulators describe a machine that cannot exist: an
// Ubuntu SSH daemon in front of an nginx serving a panel called
// "Administration", with a vsftpd underneath. Any one of those is convincing;
// together they are a tell, because a real device is one product and every port
// it answers says that product's name.
type Device struct {
	// Persona selects a built-in device. See internal/persona for the list;
	// an unknown value is an error rather than a silent fallback, because a
	// typo would otherwise leave the sensor wearing the default clothes while
	// its operator believed otherwise.
	Persona string `yaml:"persona"`

	// Name and Desc label the device. They are stamped onto every event when
	// set, so an alert says what the box was pretending to be. Empty means take
	// them from the persona; with no persona they are absent from events
	// entirely, which is what every existing deployment already looks like.
	Name string `yaml:"name"`
	Desc string `yaml:"desc"`
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
	// HPFeeds publishes events to a honeypot-fleet broker.
	HPFeeds HPFeeds `yaml:"hpfeeds"`
	// RateLimit bounds how many events this sensor will record.
	RateLimit RateLimit `yaml:"rate_limit"`
	// Rotate bounds how much disk the event log may take.
	Rotate Rotate `yaml:"rotate"`
}

// Rotate bounds the size of the JSONL event log.
//
// The rate limiter stops a flood arriving faster than the disk can take it. It
// does not stop a year of ordinary traffic from filling the partition, and a
// sensor whose disk is full stops recording the intrusion that filled it — the
// same failure the console's retention policy exists to prevent, at the other
// end of the pipe.
type Rotate struct {
	// MaxSizeMB is the threshold. Zero means the built-in default; -1 disables
	// rotation, for a deployment that already points logrotate at the file.
	MaxSizeMB int `yaml:"max_size_mb"`

	// MaxFiles is how many rotated generations to keep beside the live one.
	// Zero means the built-in default; -1 keeps none.
	MaxFiles int `yaml:"max_files"`
}

// rotation defaults, applied when the keys are absent. A fresh install is
// bounded at roughly half a gigabyte: large enough that a quiet sensor never
// rotates, small enough that a noisy one cannot fill a small disk unnoticed.
const (
	defaultRotateMB    = 100
	defaultRotateFiles = 5
)

// MaxSizeBytes is the threshold in bytes, with 0 meaning "use the default" and
// a negative value meaning "no rotation".
//
// Zero has to mean the default rather than "unbounded" for the same reason the
// rate limiter is on by default: a sensor that only bounds its disk once
// somebody configures it is unbounded on every deployment that matters. Turning
// it off stays possible, but it has to be typed.
func (r Rotate) MaxSizeBytes() int64 {
	switch {
	case r.MaxSizeMB < 0:
		return 0
	case r.MaxSizeMB == 0:
		return defaultRotateMB << 20
	default:
		return int64(r.MaxSizeMB) << 20
	}
}

// Files is how many generations to keep, with the same convention.
func (r Rotate) Files() int {
	switch {
	case r.MaxFiles < 0:
		return 0
	case r.MaxFiles == 0:
		return defaultRotateFiles
	default:
		return r.MaxFiles
	}
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

// HPFeeds publishes to the pub/sub bus honeypot operators share data over — the
// transport behind the Honeynet Project's collections, and what OpenCanary,
// Cowrie and Dionaea speak when they feed a shared collector. It is here so a
// wisp sensor can join an existing fleet rather than sit beside one.
type HPFeeds struct {
	Enabled bool `yaml:"enabled"`
	// Addr is the broker, host:port. The conventional port is 10000.
	Addr string `yaml:"addr"`
	// Ident and Secret are the credentials the broker issued. The secret is
	// never sent — the protocol proves knowledge of it against a nonce.
	Ident  string `yaml:"ident"`
	Secret string `yaml:"secret"`
	// Channel to publish on. Brokers authorise per channel, so this has to be
	// one the ident may write to.
	Channel string `yaml:"channel"`

	// TLS wraps the connection. hpfeeds has no transport security of its own
	// and these messages carry captured credentials, so this belongs on for
	// anything crossing a network you do not own.
	TLS bool `yaml:"tls"`
	// The same two ways of trusting a private certificate the console
	// connection offers, with the same precedence: fingerprint, then CA file.
	CAFile      string `yaml:"ca_file"`
	Fingerprint string `yaml:"fingerprint"`
	// InsecureSkipVerify sends every captured credential to whoever answers the
	// connection. For a lab and nothing else.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
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
	MySQL         MySQL         `yaml:"mysql"`
	MSSQL         MSSQL         `yaml:"mssql"`
	SMB           SMB           `yaml:"smb"`
	VNC           VNC           `yaml:"vnc"`
	SIP           SIP           `yaml:"sip"`
	HTTPProxy     HTTPProxy     `yaml:"http_proxy"`
	SNMP          SNMP          `yaml:"snmp"`
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
	// Realm titles the login page, and Footer is the firmware line beneath the
	// form — the detail that makes a fake panel look maintained rather than
	// generic.
	Realm  string `yaml:"realm"`
	Footer string `yaml:"footer"`
}

// HTTPS is the same admin-panel decoy as HTTP, behind TLS and reported as its
// own service.
type HTTPS struct {
	Enabled      bool   `yaml:"enabled"`
	Addr         string `yaml:"addr"`
	ServerHeader string `yaml:"server_header"`
	Realm        string `yaml:"realm"`
	Footer       string `yaml:"footer"`
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

// MySQL emulates a server with authentication required, which is what makes a
// client hand over a mysql_native_password response — a value that cracks
// offline as hashcat mode 11200, the same shape of artifact the SMB and MongoDB
// decoys capture.
type MySQL struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// Version is the server build reported in the handshake — the first thing a
	// client and every fingerprinting tool reads. Empty falls back to a current
	// server; the device persona can set it to match the rest of the disguise.
	Version string `yaml:"version"`
}

// MSSQL emulates a Microsoft SQL Server through the TDS handshake. A LOGIN7
// carries the password only lightly obfuscated, so unlike the other database
// decoys this one recovers the cleartext password itself, not a hash to crack.
type MSSQL struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// Version is the build reported in the PRELOGIN response. ServerName is what
	// the server calls itself in the login-error token — the @@SERVERNAME a
	// client reads back. Both empty fall back to a plain current server.
	Version    string `yaml:"version"`
	ServerName string `yaml:"server_name"`
}

// SMB emulates a file server through the NTLM handshake, which is what makes a
// client hand over a NetNTLMv2 hash — the native answer to the one thing
// OpenCanary needs an external Samba install to do.
type SMB struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// ComputerName and DomainName are what the server calls itself in the NTLM
	// challenge the client hashes against. Empty falls back to a plain file
	// server; the device persona sets them so a NAS on 445 agrees with the NAS
	// on every other port.
	ComputerName string `yaml:"computer_name"`
	DomainName   string `yaml:"domain_name"`
}

// VNC emulates an RFB server that offers only VNC Authentication, which is what
// makes a client return the DES challenge-response. Unlike a banner catcher on
// 5900, this captures a credential that cracks offline (John the Ripper's `vnc`
// format), not just the fact that someone connected.
type VNC struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// Version is the RFB protocol version offered first, e.g. "3.8". It decides
	// which security handshake the exchange uses; empty falls back to 3.8.
	Version string `yaml:"version"`
}

// SIP emulates a VoIP server on UDP that answers OPTIONS to look like a live PBX
// and challenges REGISTER with a digest nonce, so a scanner returns an
// Authorization digest that cracks offline (hashcat 11400). This is the protocol
// sipvicious and friendly-scanner sweep for.
type SIP struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// Realm is what the client folds into its digest, so it is part of what makes
	// the capture crackable; Server names the PBX product. Empty falls back to an
	// Asterisk PBX.
	Realm  string `yaml:"realm"`
	Server string `yaml:"server"`
}

// HTTPProxy emulates an HTTP forward proxy. It records where a client wanted to
// go — a CONNECT target or an absolute-form URL, which catches SSRF-through-proxy
// and open-proxy abuse — and answers 407 to capture cleartext Proxy-Authorization
// credentials. It never opens an outbound connection.
type HTTPProxy struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	// ServerHeader is the proxy product the decoy claims to be; Realm titles its
	// authentication challenge. Empty falls back to a Squid proxy.
	ServerHeader string `yaml:"server_header"`
	Realm        string `yaml:"realm"`
}

// SNMP emulates an agent on UDP whose v1/v2c community string is the credential,
// sent in the clear on every request. The decoy records every community tried
// (the onesixtyone spray) and never answers — SNMP is the internet's favourite
// amplification protocol, and an agent that replied could be turned into a
// reflector.
type SNMP struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
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
				Footer:       "Firmware 2.1.14",
			},
			HTTPS: HTTPS{
				Enabled:      true,
				Addr:         "0.0.0.0:8443",
				ServerHeader: "nginx/1.18.0 (Ubuntu)",
				Realm:        "Administration",
				Footer:       "Firmware 2.1.14",
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
			MySQL: MySQL{
				// 3306 is MySQL's real port and is already unprivileged.
				Enabled: true,
				Addr:    "0.0.0.0:3306",
				Version: "8.0.36",
			},
			MSSQL: MSSQL{
				// 1433 is SQL Server's real port and is already unprivileged.
				Enabled:    true,
				Addr:       "0.0.0.0:1433",
				Version:    "16.0.1000",
				ServerName: "SQLSERVER",
			},
			SMB: SMB{
				// 445 is privileged, so wisp binds an unprivileged port and the
				// operator redirects 445 to it — the same pattern as ssh on
				// 2222. See wisp.example.yaml.
				Enabled:      true,
				Addr:         "0.0.0.0:4445",
				ComputerName: "FILESERVER",
				DomainName:   "WORKGROUP",
			},
			VNC: VNC{
				// 5900 is VNC's real port and is already unprivileged.
				Enabled: true,
				Addr:    "0.0.0.0:5900",
				Version: "3.8",
			},
			SIP: SIP{
				// 5060/udp is SIP's real port and is already unprivileged.
				Enabled: true,
				Addr:    "0.0.0.0:5060",
				Realm:   "asterisk",
				Server:  "Asterisk PBX 18.10.0",
			},
			HTTPProxy: HTTPProxy{
				// 3128 is Squid's default port and is already unprivileged.
				Enabled:      true,
				Addr:         "0.0.0.0:3128",
				ServerHeader: "squid/5.7",
				Realm:        "Squid proxy-caching web server",
			},
			SNMP: SNMP{
				// 161/udp is privileged, so wisp binds an unprivileged port by
				// default and the operator redirects 161 to it — the same pattern
				// as ntp on 1123. See wisp.example.yaml.
				Enabled: true,
				Addr:    "0.0.0.0:1161",
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
				// A demonstration of the generic catcher on a port without a
				// real emulator yet. RDP sends no greeting, so the banner is
				// empty and the catcher just records the client's first bytes.
				{Enabled: true, Name: "rdp", Addr: "0.0.0.0:3389", Banner: ""},
			},
		},
		Portscan: Portscan{
			Enabled:       true,
			Threshold:     5,
			Window:        "60s",
			Cooldown:      "5m",
			IgnoreSources: []string{"127.0.0.1", "::1"},
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
	if err := cfg.applyPersona(); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, true, nil
}

// applyPersona dresses the appliance services in one product's clothes.
//
// A field is replaced only if it is still at its built-in default. That rule is
// what makes the two settings compose: pick a persona for the whole box, then
// override any single banner your environment needs differently, and the
// override wins — because once it is set it is no longer the default.
func (c *Config) applyPersona() error {
	if c.Device.Persona == "" {
		return nil
	}

	p, ok := persona.Lookup(c.Device.Persona)
	if !ok {
		// An unknown persona is an error rather than a silent fallback. A typo
		// would otherwise leave the sensor in the default clothes while its
		// operator believed it was wearing something else, and nothing about
		// the running system would say so.
		return fmt.Errorf("device.persona: unknown persona %q (available: %s)",
			c.Device.Persona, strings.Join(persona.IDs(), ", "))
	}

	def := Default()
	s, d := &c.Services, &def.Services
	setIfDefault(&s.SSH.Banner, d.SSH.Banner, p.SSHBanner)
	setIfDefault(&s.HTTP.ServerHeader, d.HTTP.ServerHeader, p.ServerHeader)
	setIfDefault(&s.HTTP.Realm, d.HTTP.Realm, p.Realm)
	setIfDefault(&s.HTTP.Footer, d.HTTP.Footer, p.Footer)
	setIfDefault(&s.HTTPS.ServerHeader, d.HTTPS.ServerHeader, p.ServerHeader)
	setIfDefault(&s.HTTPS.Realm, d.HTTPS.Realm, p.Realm)
	setIfDefault(&s.HTTPS.Footer, d.HTTPS.Footer, p.Footer)
	setIfDefault(&s.FTP.Banner, d.FTP.Banner, p.FTPBanner)
	setIfDefault(&s.Telnet.Banner, d.Telnet.Banner, p.TelnetBanner)
	setIfDefault(&s.SMB.ComputerName, d.SMB.ComputerName, p.SMBComputer)
	setIfDefault(&s.SMB.DomainName, d.SMB.DomainName, p.SMBDomain)

	if c.Device.Name == "" {
		c.Device.Name = p.Name
	}
	if c.Device.Desc == "" {
		c.Device.Desc = p.Desc
	}
	return nil
}

// PersonaWarnings reports where the chosen persona and the enabled services
// disagree about what this machine is.
//
// A persona with no banner for a service is saying the real product does not
// answer that port — a LaserJet has no sshd. The service is left running,
// because whether to run it is the operator's call and not a config file's, but
// it is said out loud at startup: an SSH banner announcing Ubuntu on a box
// whose other ports all say "HP LaserJet" is exactly the inconsistency a
// persona exists to remove.
func (c *Config) PersonaWarnings() []string {
	if c.Device.Persona == "" {
		return nil
	}
	p, ok := persona.Lookup(c.Device.Persona)
	if !ok {
		return nil
	}

	var out []string
	for _, s := range []struct {
		name    string
		enabled bool
		banner  string
	}{
		{"ssh", c.Services.SSH.Enabled, p.SSHBanner},
		{"ftp", c.Services.FTP.Enabled, p.FTPBanner},
		{"telnet", c.Services.Telnet.Enabled, p.TelnetBanner},
	} {
		if s.enabled && s.banner == "" {
			out = append(out, fmt.Sprintf(
				"%s is enabled but a %s does not answer it - its banner still says something else",
				s.name, p.Desc))
		}
	}
	return out
}

// setIfDefault replaces a field only when the operator has not chosen it, and
// only when the persona has something to say about it.
func setIfDefault(field *string, def, want string) {
	if *field == def && want != "" {
		*field = want
	}
}
