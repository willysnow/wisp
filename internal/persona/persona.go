// Package persona gives a sensor one identity instead of several.
//
// Left to themselves, the emulators each pick a plausible banner and between
// them describe a machine that cannot exist: an Ubuntu SSH daemon in front of
// an nginx that serves a login page for something called "Administration",
// with a vsftpd underneath. Any one of those is convincing. Together they are a
// tell, because a real device on a real network is one product, and every port
// it answers says the same product's name.
//
// A persona is that product. Setting one renames the banners of the services an
// appliance would actually run, so an intruder who touches 22, 80 and 21 gets
// three answers that agree.
//
// # What a persona does not cover
//
// Only the appliance services — ssh, http, https, ftp, telnet. It deliberately
// leaves the cloud, container and CI decoys alone, because a Synology NAS does
// not run a Kubernetes apiserver either, and dressing one up as the other would
// swap a small inconsistency for a larger one. A sensor running both sets is
// already describing two machines; if that matters for your deployment, run two
// sensors.
package persona

// Persona is one device's story, told the same way on every port.
type Persona struct {
	// ID is the config value that selects it.
	ID string

	// Name and Desc are the device's own labels. They are stamped onto every
	// event when a persona is in use, so an alert says what the box was
	// pretending to be without anyone having to look up the sensor.
	Name string
	Desc string

	// SSHBanner is the version string sshd offers before anything else. It is
	// the single most-fingerprinted string on any host.
	SSHBanner string

	// ServerHeader is the HTTP Server header, and Realm titles the login page.
	// Footer is the firmware or version line under the form — the detail that
	// makes a fake admin panel look maintained rather than generic.
	ServerHeader string
	Realm        string
	Footer       string

	FTPBanner    string
	TelnetBanner string
}

// personas are the devices wisp can dress up as.
//
// The strings are the ones these products really send. That matters more than
// it looks: an intruder's tooling matches on them, and a header that is close
// but not right identifies the host as something imitating the product rather
// than the product.
var personas = []Persona{
	{
		// The built-in default, named so it can be asked for explicitly and so
		// the others have something to be compared against. Selecting it
		// changes nothing.
		ID:           "ubuntu",
		Name:         "srv-app-01",
		Desc:         "Ubuntu 22.04.3 LTS server",
		SSHBanner:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		ServerHeader: "nginx/1.18.0 (Ubuntu)",
		Realm:        "Administration",
		Footer:       "Firmware 2.1.14",
		FTPBanner:    "(vsFTPd 3.0.5)",
		TelnetBanner: "Ubuntu 22.04.3 LTS",
	},
	{
		ID:           "synology",
		Name:         "DiskStation",
		Desc:         "Synology DiskStation DS220j, DSM 7.2",
		SSHBanner:    "SSH-2.0-OpenSSH_8.2p1",
		ServerHeader: "nginx",
		Realm:        "DiskStation",
		Footer:       "Synology DiskStation Manager 7.2-64570",
		FTPBanner:    "DiskStation FTP server ready.",
		TelnetBanner: "Synology DiskStation DSM 7.2-64570",
	},
	{
		ID:           "qnap",
		Name:         "NAS4A21B8",
		Desc:         "QNAP TS-233, QTS 5.1.0",
		SSHBanner:    "SSH-2.0-OpenSSH_8.4p1",
		ServerHeader: "http server 1.0",
		Realm:        "QNAP Turbo NAS",
		Footer:       "QTS 5.1.0.2444",
		FTPBanner:    "QNAP FTP Server Ready.",
		TelnetBanner: "QNAP Turbo NAS QTS 5.1.0",
	},
	{
		// A printer is the most-overlooked box on any office network: it has an
		// unauthenticated web UI, it is never patched, and nobody notices
		// traffic to it. It also has no SSH, which is the point of having the
		// persona set the banners rather than leaving each service to guess.
		ID:           "hp-printer",
		Name:         "NPI4C2F9E",
		Desc:         "HP LaserJet Pro MFP M428fdw",
		SSHBanner:    "",
		ServerHeader: "HP HTTP Server; HP LaserJet MFP M428f-M429f - Firmware 20230330; Serial Number: CNBRP1234X;",
		Realm:        "HP LaserJet MFP M428fdw",
		Footer:       "Firmware 002.2321A",
		FTPBanner:    "HP LaserJet MFP M428fdw FTP Server",
		TelnetBanner: "HP JetDirect",
	},
	{
		ID:           "truenas",
		Name:         "truenas",
		Desc:         "TrueNAS SCALE 23.10.2",
		SSHBanner:    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
		ServerHeader: "nginx",
		Realm:        "TrueNAS",
		Footer:       "TrueNAS SCALE 23.10.2",
		FTPBanner:    "Welcome to TrueNAS FTP",
		TelnetBanner: "TrueNAS SCALE 23.10.2",
	},
}

// Lookup finds a persona by its config ID.
func Lookup(id string) (Persona, bool) {
	for _, p := range personas {
		if p.ID == id {
			return p, true
		}
	}
	return Persona{}, false
}

// IDs lists what can be asked for, so a typo in the config can be answered with
// the alternatives rather than just a refusal.
func IDs() []string {
	out := make([]string, 0, len(personas))
	for _, p := range personas {
		out = append(out, p.ID)
	}
	return out
}
