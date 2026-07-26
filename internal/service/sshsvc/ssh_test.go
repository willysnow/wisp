package sshsvc

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

const banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

func start(t *testing.T) *servicetest.StreamHarness {
	t.Helper()

	keyPath := filepath.Join(t.TempDir(), "hostkey.pem")
	return servicetest.StartStream(t, func(addr string) service.StreamService {
		svc, err := New(addr, banner, keyPath)
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		return svc
	})
}

// dialSSH attempts a login and returns the error the client saw. Every attempt
// is expected to fail — that is the point of the service.
func dialSSH(t *testing.T, addr string, auth ssh.AuthMethod, user string) error {
	t.Helper()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // the decoy's key is self-signed by design
		Timeout:         3 * time.Second,
	})
	if err == nil {
		client.Close()
		t.Fatal("the decoy accepted a login — nothing may ever be granted")
	}
	return err
}

// TestPasswordIsCaptured is the service's reason for existing: SSH is the most
// brute-forced port on the internet, and the credential pair is the artifact.
func TestPasswordIsCaptured(t *testing.T) {
	h := start(t)

	dialSSH(t, h.Addr, ssh.Password("hunter2"), "root")

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "root" {
		t.Errorf("username = %v, want root", ev.Data["username"])
	}
	if ev.Data["password"] != "hunter2" {
		t.Errorf("password = %v, want hunter2", ev.Data["password"])
	}
	// The client's own version string, which identifies the toolkit doing the
	// brute forcing at least as well as the password does.
	if client, _ := ev.Data["client_version"].(string); !strings.Contains(client, "SSH-2.0") {
		t.Errorf("client_version = %q, want the client's banner", client)
	}
}

// TestPublicKeyFingerprintIsCaptured.
//
// A key fingerprint often identifies a specific toolkit or actor, and unlike a
// password it is stable across every host they touch — so the same fingerprint
// appearing on two sensors ties the two intrusions together.
func TestPublicKeyFingerprintIsCaptured(t *testing.T) {
	h := start(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	dialSSH(t, h.Addr, ssh.PublicKeys(signer), "deploy")

	ev := h.WaitFor(t, "login_pubkey")
	fingerprint, _ := ev.Data["fingerprint"].(string)
	if want := ssh.FingerprintSHA256(signer.PublicKey()); fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", fingerprint, want)
	}
	if ev.Data["username"] != "deploy" {
		t.Errorf("username = %v, want deploy", ev.Data["username"])
	}
}

// TestNeverGrantsAccess covers the first rule of the project against the
// credentials an attacker actually tries first.
func TestNeverGrantsAccess(t *testing.T) {
	h := start(t)

	for _, creds := range [][2]string{
		{"root", "root"},
		{"root", ""},
		{"admin", "admin"},
		{"ubuntu", "ubuntu"},
	} {
		// dialSSH fails the test if any of these is accepted.
		dialSSH(t, h.Addr, ssh.Password(creds[1]), creds[0])
	}

	if h.Count("login_password") < 4 {
		t.Errorf("recorded %d attempts, want 4", h.Count("login_password"))
	}
}

// TestBannerIsPresented — the version string is what a scanner fingerprints on
// before it tries anything, and it has to match the OS being impersonated.
func TestBannerIsPresented(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	buf := make([]byte, len(banner))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if got := string(buf); !strings.HasPrefix(got, banner) {
		t.Errorf("banner = %q, want %q", got, banner)
	}
}

// TestHostKeyIsReused across restarts.
//
// A host key that changes every restart identifies the box as a honeypot to
// anyone who connects twice — and SSH clients shout about it, which means the
// attacker is told rather than us.
func TestHostKeyIsReused(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "hostkey.pem")

	first, err := New("127.0.0.1:0", banner, keyPath)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("the host key was not persisted: %v", err)
	}

	second, err := New("127.0.0.1:0", banner, keyPath)
	if err != nil {
		t.Fatalf("new again: %v", err)
	}

	if ssh.FingerprintSHA256(first.signer.PublicKey()) !=
		ssh.FingerprintSHA256(second.signer.PublicKey()) {
		t.Error("the host key changed between restarts — that is a honeypot fingerprint")
	}

	// And it is not readable by other users: it is key material, even if it is
	// a decoy's. Skipped on Windows, where Go's file mode does not map to an
	// ACL and every file reports 0666 — the check still runs on the platforms
	// where the permission bits mean something, including CI.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("host key mode is %v, want it kept from other users", perm)
		}
	}
}

// TestConnectionIsRecorded even when the client never authenticates — a scan
// that opens a socket and leaves is still a scan.
func TestConnectionIsRecorded(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	conn.Close()

	h.WaitFor(t, "connect")
}

// TestGarbageDoesNotStopTheListener: a client that sends noise instead of a
// handshake must not take the service down for everyone else.
func TestGarbageDoesNotStopTheListener(t *testing.T) {
	h := start(t)

	conn := h.Dial()
	if _, err := conn.Write([]byte("not an ssh handshake\r\n\x00\xff")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	// Still serving.
	dialSSH(t, h.Addr, ssh.Password("after"), "still-here")
	h.WaitFor(t, "login_password")
}
