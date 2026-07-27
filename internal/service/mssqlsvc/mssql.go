// Package mssqlsvc emulates a Microsoft SQL Server far enough to capture the one
// thing an intruder came to 1433 for: an account name and, for SQL Server
// authentication, the cleartext password itself.
//
// It works the way the SMB and MongoDB decoys do, but the artifact is stronger.
// A client opens with a TDS PRELOGIN to negotiate encryption; the decoy answers
// "encryption not supported", which a willing client accepts by sending its
// LOGIN7 — password included — unencrypted. The password in a LOGIN7 is not
// hashed, only obfuscated with a fixed, reversible nibble-swap-and-XOR, so the
// decoy recovers it in the clear:
//
//	mssql  login_password  username=sa  password=Summer2024!  app=sqlcmd
//
// That is not a hash to crack — it is the password. It is logged as a
// login_password event, the same kind the SSH, FTP and Redis decoys emit when
// they catch a cleartext credential.
//
// The one case the decoy cannot open is a client that requires TLS or uses
// Windows/integrated authentication: the first needs a real certificate the
// decoy does not have, and the second carries an NTLM blob rather than a
// password. Those are recorded as attempts with what identifying detail the
// LOGIN7 still carries — the SECURITY.md limitations list says as much — but no
// password comes out of them.
//
// Nothing is ever granted. Every LOGIN7 ends in error 18456, the code for a
// failed login, for the same reason the MongoDB decoy always answers
// AuthenticationFailed: a door that is merely locked invites a key.
package mssqlsvc

import (
	"context"
	"net"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service"
)

const name = "mssql"

// logLimit bounds any single captured field before it reaches the event log.
const logLimit = 1024

type Service struct {
	addr string
	// serverName is what the server calls itself — it appears in the login-error
	// token and is the @@SERVERNAME a client reads back. Match it to the device
	// persona so a box claiming to be one thing does not name itself another.
	serverName string
	// version is the build reported in the PRELOGIN response, the first thing a
	// fingerprinting tool reads.
	version [6]byte
}

// New builds the decoy. Empty values fall back to a plausible current server.
func New(addr, version, serverName string) *Service {
	if version == "" {
		version = "16.0.1000"
	}
	if serverName == "" {
		serverName = "SQLSERVER"
	}
	return &Service{
		addr:       addr,
		serverName: serverName,
		version:    parseVersion(version),
	}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	return service.Accept(ctx, ln, func(c net.Conn) { s.handle(c, emit) })
}

// handle drives the TDS handshake, a fixed two-step sequence: answer the
// client's PRELOGIN, then read its LOGIN7, record the credential, and refuse.
// Authentication never succeeds, so there is nothing past the refusal — no
// batch, no query, no result to get wrong.
func (s *Service) handle(nc net.Conn, emit event.Emitter) {
	spoke := false
	defer func() {
		if !spoke {
			emit.Emit(event.New(name, "connection", nc.RemoteAddr(), nc.LocalAddr()))
		}
	}()

	msgType, payload, err := readMessage(nc)
	if err != nil {
		return
	}
	if msgType != pktPrelogin {
		// Anything but a PRELOGIN first is not a TDS client worth answering.
		return
	}
	spoke = true

	pl := parsePrelogin(payload)
	s.emitProbe(nc, emit, pl)

	if err := writeMessage(nc, pktReply, preloginResponse(s.version)); err != nil {
		return
	}

	// A client that demanded encryption gives up here, because the decoy said it
	// has none; there is nothing more to read. One that was willing sends its
	// LOGIN7 next.
	msgType, payload, err = readMessage(nc)
	if err != nil {
		return
	}
	if msgType != pktLogin7 {
		return
	}

	l, ok := parseLogin7(payload)
	if !ok {
		return
	}
	s.capture(nc, emit, l)

	_ = writeMessage(nc, pktReply, loginError(l.username, s.serverName, l.tdsMajor))
}

// emitProbe records that a TDS client reached the server and what its PRELOGIN
// disclosed — the encryption mode it wanted and any instance name it asked for.
// A scanner that sends only a PRELOGIN (nmap's ms-sql-info) produces exactly
// this and no login.
func (s *Service) emitProbe(nc net.Conn, emit event.Emitter, pl prelogin) {
	ev := event.New(name, "probe", nc.RemoteAddr(), nc.LocalAddr())
	if pl.haveEnc {
		ev.Data["encryption"] = encryptionName(pl.encryption)
	}
	if pl.instance != "" {
		ev.Data["instance"] = truncate(pl.instance)
	}
	emit.Emit(ev)
}

// capture records the credential. SQL Server authentication yields a cleartext
// password and is logged as login_password; integrated (Windows) auth carries
// an NTLM blob the decoy does not unwrap, and is logged as an auth_attempt with
// whatever the LOGIN7 still named.
func (s *Service) capture(nc net.Conn, emit event.Emitter, l login) {
	kind := "login_password"
	if l.integrated {
		kind = "auth_attempt"
	}
	ev := event.New(name, kind, nc.RemoteAddr(), nc.LocalAddr())

	if l.username != "" {
		ev.Data["username"] = truncate(l.username)
	}
	if l.integrated {
		ev.Data["auth"] = "integrated"
	} else {
		ev.Data["password"] = truncate(l.password)
	}
	if l.database != "" {
		ev.Data["database"] = truncate(l.database)
	}
	if l.appName != "" {
		ev.Data["application"] = truncate(l.appName)
	}
	if l.library != "" {
		ev.Data["library"] = truncate(l.library)
	}
	if l.hostname != "" {
		ev.Data["hostname"] = truncate(l.hostname)
	}
	if l.serverName != "" {
		ev.Data["target"] = truncate(l.serverName)
	}
	emit.Emit(ev)
}

// encryptionName names a PRELOGIN encryption value for the event log.
func encryptionName(v byte) string {
	switch v {
	case encryptOff:
		return "off"
	case encryptOn:
		return "on"
	case encryptNotSup:
		return "not_supported"
	case encryptReq:
		return "required"
	default:
		return "unknown"
	}
}
