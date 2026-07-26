package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/persona"
)

func load(t *testing.T, body string) *Config {
	t.Helper()

	path := filepath.Join(t.TempDir(), "wisp.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, found, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !found {
		t.Fatal("the config file was not read")
	}
	return cfg
}

// TestPersonaDressesEveryApplianceService is the whole point. An intruder who
// touches 22, 80 and 21 has to get three answers that agree, because a real
// device is one product and every port it answers says that product's name.
func TestPersonaDressesEveryApplianceService(t *testing.T) {
	cfg := load(t, "device:\n  persona: synology\n")

	want, ok := persona.Lookup("synology")
	if !ok {
		t.Fatal("the synology persona is missing")
	}

	for _, c := range []struct{ field, got, want string }{
		{"ssh.banner", cfg.Services.SSH.Banner, want.SSHBanner},
		{"http.server_header", cfg.Services.HTTP.ServerHeader, want.ServerHeader},
		{"http.realm", cfg.Services.HTTP.Realm, want.Realm},
		{"http.footer", cfg.Services.HTTP.Footer, want.Footer},
		{"https.server_header", cfg.Services.HTTPS.ServerHeader, want.ServerHeader},
		{"https.realm", cfg.Services.HTTPS.Realm, want.Realm},
		{"ftp.banner", cfg.Services.FTP.Banner, want.FTPBanner},
		{"telnet.banner", cfg.Services.Telnet.Banner, want.TelnetBanner},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
	}

	// Nothing should still be describing an Ubuntu box.
	def := Default()
	if strings.Contains(cfg.Services.SSH.Banner, "Ubuntu") {
		t.Errorf("ssh still says Ubuntu under a NAS persona: %q", cfg.Services.SSH.Banner)
	}
	if cfg.Services.HTTP.ServerHeader == def.Services.HTTP.ServerHeader {
		t.Error("the HTTP server header was left at the default")
	}
}

// TestExplicitConfigBeatsThePersona is the rule that makes the two settings
// compose: pick a persona for the whole box, then override the one banner your
// environment needs differently.
func TestExplicitConfigBeatsThePersona(t *testing.T) {
	cfg := load(t, `
device:
  persona: synology
services:
  ssh:
    banner: "SSH-2.0-OpenSSH_9.6"
  http:
    realm: "Storage Manager"
`)

	if cfg.Services.SSH.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("ssh.banner = %q, want the operator's override", cfg.Services.SSH.Banner)
	}
	if cfg.Services.HTTP.Realm != "Storage Manager" {
		t.Errorf("http.realm = %q, want the operator's override", cfg.Services.HTTP.Realm)
	}

	// Everything not overridden still follows the persona.
	want, _ := persona.Lookup("synology")
	if cfg.Services.FTP.Banner != want.FTPBanner {
		t.Errorf("ftp.banner = %q, want the persona's", cfg.Services.FTP.Banner)
	}
	if cfg.Services.HTTP.Footer != want.Footer {
		t.Errorf("http.footer = %q, want the persona's", cfg.Services.HTTP.Footer)
	}
}

// TestNoPersonaChangesNothing. Every existing deployment has no device section,
// and its banners and events must come out exactly as they did before.
func TestNoPersonaChangesNothing(t *testing.T) {
	cfg := load(t, "node: sensor-1\n")
	def := Default()

	if cfg.Services.SSH.Banner != def.Services.SSH.Banner {
		t.Errorf("ssh.banner = %q, want the untouched default", cfg.Services.SSH.Banner)
	}
	if cfg.Services.HTTP.Realm != def.Services.HTTP.Realm {
		t.Errorf("http.realm = %q, want the untouched default", cfg.Services.HTTP.Realm)
	}
	if cfg.Device.Name != "" || cfg.Device.Desc != "" {
		t.Errorf("device labels appeared without a persona: %q / %q",
			cfg.Device.Name, cfg.Device.Desc)
	}
}

// TestUnknownPersonaIsAnError, and the error lists the alternatives.
//
// A silent fallback would leave the sensor in the default clothes while its
// operator believed it was wearing something else, and nothing about the
// running system would say so.
func TestUnknownPersonaIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wisp.yaml")
	if err := os.WriteFile(path, []byte("device:\n  persona: synollogy\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := Load(path)
	if err == nil {
		t.Fatal("an unknown persona was accepted")
	}
	if !strings.Contains(err.Error(), "synollogy") {
		t.Errorf("error = %v, want it to name the bad value", err)
	}
	if !strings.Contains(err.Error(), "synology") {
		t.Errorf("error = %v, want it to list what is available", err)
	}
}

// TestDeviceLabelsComeFromThePersonaButCanBeOverridden.
func TestDeviceLabelsComeFromThePersonaButCanBeOverridden(t *testing.T) {
	cfg := load(t, "device:\n  persona: qnap\n")
	want, _ := persona.Lookup("qnap")
	if cfg.Device.Name != want.Name || cfg.Device.Desc != want.Desc {
		t.Errorf("labels = %q / %q, want the persona's", cfg.Device.Name, cfg.Device.Desc)
	}

	cfg = load(t, "device:\n  persona: qnap\n  name: nas-fileshare-02\n")
	if cfg.Device.Name != "nas-fileshare-02" {
		t.Errorf("device.name = %q, want the operator's", cfg.Device.Name)
	}
	if cfg.Device.Desc != want.Desc {
		t.Errorf("device.desc = %q, want the persona's", cfg.Device.Desc)
	}
}

// TestPersonaWarnsAboutAServiceTheDeviceWouldNotRun.
//
// A LaserJet has no sshd. The service is left running because that is the
// operator's call, but an SSH banner announcing Ubuntu on a box whose other
// ports all say "HP LaserJet" is exactly the inconsistency a persona exists to
// remove, so it is said out loud.
func TestPersonaWarnsAboutAServiceTheDeviceWouldNotRun(t *testing.T) {
	cfg := load(t, "device:\n  persona: hp-printer\n")

	warnings := strings.Join(cfg.PersonaWarnings(), "\n")
	if !strings.Contains(warnings, "ssh") {
		t.Errorf("warnings = %q, want ssh flagged on a printer", warnings)
	}

	// And it stops warning once the operator acts on it.
	cfg = load(t, "device:\n  persona: hp-printer\nservices:\n  ssh:\n    enabled: false\n")
	if got := cfg.PersonaWarnings(); len(got) != 0 {
		t.Errorf("warnings = %v, want none once ssh is off", got)
	}

	// A persona whose device runs everything it is asked to says nothing.
	cfg = load(t, "device:\n  persona: synology\n")
	if got := cfg.PersonaWarnings(); len(got) != 0 {
		t.Errorf("warnings = %v, want none for a NAS", got)
	}
}

// TestEveryPersonaIsComplete. A persona missing a field silently leaves that
// service wearing the previous device's clothes, which is the exact failure the
// whole package exists to prevent. Only the SSH banner may be empty, and only
// because a real printer has no sshd.
func TestEveryPersonaIsComplete(t *testing.T) {
	for _, id := range persona.IDs() {
		p, ok := persona.Lookup(id)
		if !ok {
			t.Fatalf("Lookup(%q) failed for an ID that IDs() returned", id)
		}

		for _, f := range []struct{ name, value string }{
			{"Name", p.Name},
			{"Desc", p.Desc},
			{"ServerHeader", p.ServerHeader},
			{"Realm", p.Realm},
			{"Footer", p.Footer},
			{"FTPBanner", p.FTPBanner},
			{"TelnetBanner", p.TelnetBanner},
		} {
			if f.value == "" {
				t.Errorf("persona %q has no %s", id, f.name)
			}
		}
	}
}

// TestUbuntuPersonaIsTheBuiltInDefault. It exists so the others have something
// to be compared against and so it can be asked for explicitly; selecting it
// must change nothing.
func TestUbuntuPersonaIsTheBuiltInDefault(t *testing.T) {
	cfg := load(t, "device:\n  persona: ubuntu\n")
	def := Default()

	for _, c := range []struct{ field, got, want string }{
		{"ssh.banner", cfg.Services.SSH.Banner, def.Services.SSH.Banner},
		{"http.server_header", cfg.Services.HTTP.ServerHeader, def.Services.HTTP.ServerHeader},
		{"http.realm", cfg.Services.HTTP.Realm, def.Services.HTTP.Realm},
		{"http.footer", cfg.Services.HTTP.Footer, def.Services.HTTP.Footer},
		{"ftp.banner", cfg.Services.FTP.Banner, def.Services.FTP.Banner},
		{"telnet.banner", cfg.Services.Telnet.Banner, def.Services.Telnet.Banner},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want the built-in default %q", c.field, c.got, c.want)
		}
	}
}
