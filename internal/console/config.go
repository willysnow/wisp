package console

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/willysnow/wisp/internal/console/notify"
	"github.com/willysnow/wisp/internal/syslog"
	"github.com/willysnow/wisp/internal/token"
)

// Config is the console's YAML configuration. Everything is optional: with no
// config file the console runs as a plain aggregator with no notifications.
type Config struct {
	TLS       TLSConfig       `yaml:"tls"`
	UI        UIConfig        `yaml:"ui"`
	Sensors   SensorsConfig   `yaml:"sensors"`
	Retention RetentionConfig `yaml:"retention"`
	Notify    NotifyConfig    `yaml:"notify"`
	Tokens    TokensConfig    `yaml:"tokens"`
}

// TokensConfig covers honeytokens: lures planted in data that call home when
// opened or used. The console mints them, plants nothing itself, and receives
// their callbacks — over HTTP for every kind, and over DNS for the one that has
// to reach a network HTTP cannot leave.
type TokensConfig struct {
	// BaseURL is this console's public origin, e.g. https://console.example.com.
	// It is where HTTP token callbacks land, so it must be the address an
	// intruder's machine can reach — not a loopback or an internal-only name the
	// planted data will never resolve.
	BaseURL string `yaml:"base_url"`

	// DNS configures the authoritative server for DNS tokens.
	DNS TokenDNSConfig `yaml:"dns"`
}

// TokenDNSConfig configures the DNS token server. It is off by default: it is
// the one part of the console that wants a privileged port and a domain
// delegated to it, so it runs only when both are set up.
type TokenDNSConfig struct {
	Enabled bool `yaml:"enabled"`

	// Zone is the domain delegated to this server, e.g. tokens.example.com. A
	// DNS token is <id>.<zone>, so the zone's NS records must point at this host.
	Zone string `yaml:"zone"`

	// Addr is the listen address. Empty means :53, which needs privilege or a
	// redirect — see the deployment notes.
	Addr string `yaml:"addr"`

	// Answer is the A record handed back for names under the zone. Empty means
	// 127.0.0.1, a black hole: the answer only has to satisfy the resolver that
	// carried the id, not lead anywhere.
	Answer string `yaml:"answer"`
}

// SensorsConfig covers what the console watches for on the sensors' behalf.
//
// A sensor cannot report its own death. If someone finds it and stops it, the
// last thing it does is go quiet — which looks exactly like a network where
// nothing is happening. The console is the only place that can tell those
// apart.
type SensorsConfig struct {
	// SilenceAfter is how long a sensor may go without delivering before the
	// console raises an alert. Empty or 0 disables the check.
	SilenceAfter string `yaml:"silence_after"`

	// CheckInterval is how often the check runs. Empty means 1m.
	CheckInterval string `yaml:"check_interval"`
}

// UIConfig covers the operator interface, which is behind a login in every
// configuration — there is no setting here that turns authentication off.
type UIConfig struct {
	// SessionTTL is how long a login lasts. Empty means DefaultSessionTTL.
	SessionTTL string `yaml:"session_ttl"`

	// SecureCookies is auto, always, or never. Empty means auto.
	SecureCookies string `yaml:"secure_cookies"`

	// TrustProxy makes the console believe X-Forwarded-For and
	// X-Forwarded-Proto. Enable it only when a reverse proxy you control is in
	// front: those headers are otherwise set by whoever is connecting.
	TrustProxy bool `yaml:"trust_proxy"`
}

// RetentionConfig bounds how much history the console keeps. Empty means
// unlimited, which is the honest default — but see the warning the console
// prints at startup, because unlimited means the disk is sized by whoever is
// scanning your sensors.
type RetentionConfig struct {
	// Events is the maximum age of a stored event, e.g. 30d or 720h. Empty or
	// 0 keeps events forever.
	Events string `yaml:"events"`

	// MaxEvents keeps only the newest N events. 0 means no cap.
	MaxEvents int64 `yaml:"max_events"`

	// Interval is how often the policy is applied. Empty means 1h.
	Interval string `yaml:"interval"`
}

type NotifyConfig struct {
	// Window is how long a repeated alert stays suppressed. Empty means 15m.
	Window string `yaml:"window"`

	// Kinds overrides which event kinds notify. Empty means the built-in list
	// (credentials and stated intent). Use ["*"] to notify on everything —
	// expect to regret it during the first port scan.
	Kinds []string `yaml:"kinds"`

	Email    EmailConfig     `yaml:"email"`
	LINE     LINEConfig      `yaml:"line"`
	Webhooks []WebhookConfig `yaml:"webhooks"`

	// Syslog forwards alerts to a collector. Unlike the sensor's own syslog
	// sink, what leaves here is already deduplicated and filtered to the kinds
	// worth acting on — a SIEM receives the alerts someone would have been
	// paged for, not every packet anyone sent at a honeypot.
	Syslog syslog.Config `yaml:"syslog"`
}

type EmailConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Host     string   `yaml:"host"` // host:port
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type LINEConfig struct {
	Enabled bool `yaml:"enabled"`
	// Token is a LINE Messaging API channel access token.
	Token string `yaml:"token"`
	// To is the destination user, group, or room ID.
	To string `yaml:"to"`
}

type WebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	// Format is json, slack, teams, or discord. Empty means json.
	Format string `yaml:"format"`
}

// LoadConfig reads path. A missing file yields an empty config rather than an
// error, so the console runs with no setup at all.
func LoadConfig(path string) (*Config, bool, error) {
	var cfg Config

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &cfg, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, false, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, true, nil
}

// Notifiers builds the configured notifiers, validating each one. A
// misconfigured notifier is an error rather than a silent skip: an operator who
// thinks they will be alerted and will not is worse off than one who knows the
// console is only a dashboard.
func (c *Config) Notifiers() ([]notify.Notifier, error) {
	var out []notify.Notifier

	if e := c.Notify.Email; e.Enabled {
		switch {
		case e.Host == "":
			return nil, fmt.Errorf("notify.email: host is required")
		case e.From == "":
			return nil, fmt.Errorf("notify.email: from is required")
		case len(e.To) == 0:
			return nil, fmt.Errorf("notify.email: at least one recipient is required")
		}
		out = append(out, notify.NewEmail(e.Host, e.Username, e.Password, e.From, e.To))
	}

	if l := c.Notify.LINE; l.Enabled {
		switch {
		case l.Token == "":
			return nil, fmt.Errorf("notify.line: token is required")
		case l.To == "":
			return nil, fmt.Errorf("notify.line: to is required")
		}
		out = append(out, notify.NewLINE(l.Token, l.To))
	}

	if sl := c.Notify.Syslog; sl.Enabled {
		n, err := notify.NewSyslog("syslog", sl)
		if err != nil {
			return nil, fmt.Errorf("notify.syslog: %w", err)
		}
		out = append(out, n)
	}

	for i, w := range c.Notify.Webhooks {
		if !w.Enabled {
			continue
		}
		if w.URL == "" {
			return nil, fmt.Errorf("notify.webhooks[%d]: url is required", i)
		}
		name := w.Name
		if name == "" {
			name = fmt.Sprintf("webhook-%d", i)
		}
		switch notify.Format(w.Format) {
		case "", notify.FormatJSON, notify.FormatSlack, notify.FormatTeams, notify.FormatDiscord:
		default:
			return nil, fmt.Errorf("notify.webhooks[%d]: unknown format %q", i, w.Format)
		}
		out = append(out, notify.NewWebhook(name, w.URL, notify.Format(w.Format)))
	}

	return out, nil
}

// ServerOptions builds the UI half of the server options. The caller fills in
// the ingest token and dispatcher, which do not come from this file.
func (c *Config) ServerOptions() (Options, error) {
	var opts Options

	if v := c.UI.SessionTTL; v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return opts, fmt.Errorf("ui.session_ttl: %w", err)
		}
		if d <= 0 {
			return opts, fmt.Errorf("ui.session_ttl: must be positive")
		}
		opts.SessionTTL = d
	}

	switch CookieMode(c.UI.SecureCookies) {
	case "", CookieAuto:
		opts.CookieMode = CookieAuto
	case CookieAlways:
		opts.CookieMode = CookieAlways
	case CookieNever:
		opts.CookieMode = CookieNever
	default:
		return opts, fmt.Errorf("ui.secure_cookies: want auto, always, or never, got %q",
			c.UI.SecureCookies)
	}

	opts.TrustProxy = c.UI.TrustProxy

	// The UI marks sensors with the same threshold the watcher alerts on, so
	// the page and the notification can never disagree.
	silence, err := c.SilencePolicy()
	if err != nil {
		return opts, err
	}
	opts.SilenceAfter = silence.After

	return opts, nil
}

// TokenArtifactConfig is what the artifacts and the UI need: where the console
// can be reached. It is not validated here — an empty base URL is a legitimate
// state (no HTTP tokens minted yet), and the error is raised where a token that
// needs it is actually rendered.
func (c *Config) TokenArtifactConfig() token.Config {
	return token.Config{
		BaseURL: strings.TrimSpace(c.Tokens.BaseURL),
		DNSZone: strings.TrimSpace(c.Tokens.DNS.Zone),
	}
}

// TokenDNS parses the DNS token server configuration.
func (c *Config) TokenDNS() (DNSConfig, error) {
	d := c.Tokens.DNS
	out := DNSConfig{
		Enabled: d.Enabled,
		Zone:    strings.Trim(strings.TrimSpace(d.Zone), "."),
		Addr:    strings.TrimSpace(d.Addr),
	}

	if d.Enabled && out.Zone == "" {
		return out, fmt.Errorf("tokens.dns.zone is required when tokens.dns.enabled is true")
	}

	if a := strings.TrimSpace(d.Answer); a != "" {
		ip := net.ParseIP(a)
		if ip == nil {
			return out, fmt.Errorf("tokens.dns.answer is not an IP address: %q", a)
		}
		if ip.To4() == nil {
			// Only A records are served, so the answer has to be IPv4. An
			// operator who set a v6 address here would get silent empty answers.
			return out, fmt.Errorf("tokens.dns.answer must be an IPv4 address, got %q", a)
		}
		out.Answer = ip
	}

	return out, nil
}

// SilencePolicy parses the sensor-watching section.
func (c *Config) SilencePolicy() (SilencePolicy, error) {
	var p SilencePolicy

	if v := c.Sensors.SilenceAfter; v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return p, fmt.Errorf("sensors.silence_after: %w", err)
		}
		if d < 0 {
			return p, fmt.Errorf("sensors.silence_after: must not be negative")
		}
		p.After = d
	}

	if v := c.Sensors.CheckInterval; v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return p, fmt.Errorf("sensors.check_interval: %w", err)
		}
		if d <= 0 {
			return p, fmt.Errorf("sensors.check_interval: must be positive")
		}
		p.CheckInterval = d
	}
	if p.CheckInterval == 0 {
		p.CheckInterval = DefaultSilenceCheck
	}

	return p, nil
}

// RetentionPolicy parses the retention section.
func (c *Config) RetentionPolicy() (Retention, error) {
	r := Retention{MaxEvents: c.Retention.MaxEvents}

	if v := c.Retention.Events; v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return r, fmt.Errorf("retention.events: %w", err)
		}
		if d < 0 {
			return r, fmt.Errorf("retention.events: must not be negative")
		}
		r.MaxAge = d
	}

	if v := c.Retention.Interval; v != "" {
		d, err := ParseDuration(v)
		if err != nil {
			return r, fmt.Errorf("retention.interval: %w", err)
		}
		if d <= 0 {
			return r, fmt.Errorf("retention.interval: must be positive")
		}
		r.Interval = d
	}
	if r.Interval == 0 {
		r.Interval = DefaultRetentionInterval
	}

	if r.MaxEvents < 0 {
		return r, fmt.Errorf("retention.max_events: must not be negative")
	}
	return r, nil
}

// ParseDuration is time.ParseDuration plus days and weeks.
//
// Retention is written in days by everyone who has ever written a retention
// policy, and making an operator work out that 90 days is 2160h is a good way
// to end up with a typo holding the wrong amount of evidence.
func ParseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		return scaleDuration(n, 24*time.Hour, s)
	}
	if n, ok := strings.CutSuffix(s, "w"); ok {
		return scaleDuration(n, 7*24*time.Hour, s)
	}
	return time.ParseDuration(s)
}

func scaleDuration(number string, unit time.Duration, original string) (time.Duration, error) {
	n, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", original)
	}
	return time.Duration(n * float64(unit)), nil
}

// Window parses the configured suppression window.
func (c *Config) Window() (time.Duration, error) {
	if c.Notify.Window == "" {
		return notify.DefaultWindow, nil
	}
	d, err := time.ParseDuration(c.Notify.Window)
	if err != nil {
		return 0, fmt.Errorf("notify.window: %w", err)
	}
	return d, nil
}
