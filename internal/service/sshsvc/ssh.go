// Package sshsvc emulates an OpenSSH server far enough to capture credentials.
//
// Authentication always fails. The value is entirely in what the attacker hands
// over on the way to failing: username, password, and — for key auth — the
// public key fingerprint, which often identifies a specific toolkit or actor.
package sshsvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "ssh"

type Service struct {
	addr   string
	banner string
	signer ssh.Signer
}

// New loads (or creates) the host key and returns a ready service.
//
// The host key is persisted because a key that changes on every restart is
// itself a honeypot fingerprint — a scanner that revisits and sees a new key
// learns more about us than we learn about it.
func New(addr, banner, hostKeyPath string) (*Service, error) {
	signer, err := loadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}
	return &Service{addr: addr, banner: banner, signer: signer}, nil
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

// handle runs one connection. service.Accept owns closing the connection and
// setting its deadline.
func (s *Service) handle(conn net.Conn, emit event.Emitter) {
	remote, local := conn.RemoteAddr(), conn.LocalAddr()
	emit.Emit(event.New(name, "connect", remote, local))

	// The config is per-connection so the auth callbacks can close over the
	// local address without a lookup.
	cfg := &ssh.ServerConfig{
		ServerVersion: s.banner,

		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			ev := event.New(name, "login_password", c.RemoteAddr(), local)
			ev.Data["username"] = c.User()
			ev.Data["password"] = string(pass)
			ev.Data["client_version"] = string(c.ClientVersion())
			emit.Emit(ev)
			return nil, errors.New("permission denied")
		},

		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			ev := event.New(name, "login_pubkey", c.RemoteAddr(), local)
			ev.Data["username"] = c.User()
			ev.Data["key_type"] = key.Type()
			ev.Data["fingerprint"] = ssh.FingerprintSHA256(key)
			ev.Data["client_version"] = string(c.ClientVersion())
			emit.Emit(ev)
			return nil, errors.New("permission denied")
		},
	}
	cfg.AddHostKey(s.signer)

	// This is expected to fail — we reject every credential. The handshake is
	// only a vehicle for the callbacks above.
	if sc, _, _, err := ssh.NewServerConn(conn, cfg); err == nil {
		_ = sc.Close()
	}
}

// loadOrCreateHostKey reads an ed25519 private key from path, generating and
// persisting one if the file does not exist.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("%s: not a PEM file", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return ssh.NewSignerFromKey(key)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
