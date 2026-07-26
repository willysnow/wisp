package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Email sends alerts over SMTP.
//
// Email is the lowest-common-denominator channel and the one most likely to
// reach someone who is not at their desk, which is exactly when a honeypot
// alert matters.
type Email struct {
	host     string // "smtp.example.com:587"
	username string
	password string
	from     string
	to       []string
}

func NewEmail(host, username, password, from string, to []string) *Email {
	return &Email{host: host, username: username, password: password, from: from, to: to}
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(ctx context.Context, a Alert) error {
	if len(e.to) == 0 {
		return fmt.Errorf("email: no recipients configured")
	}

	host, _, err := net.SplitHostPort(e.host)
	if err != nil {
		return fmt.Errorf("email: bad host %q: %w", e.host, err)
	}

	msg := e.compose(a)

	// net/smtp has no context support, so the deadline is enforced by dialing
	// ourselves rather than letting SendMail block indefinitely.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(sendTimeout)
	}
	conn, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "tcp", e.host)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()

	// STARTTLS whenever the server offers it. Alerts contain captured
	// credentials; sending them in the clear would leak exactly what we are
	// trying to protect.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}

	if e.username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.username, e.password, host)); err != nil {
			return err
		}
	}

	if err := c.Mail(e.from); err != nil {
		return err
	}
	for _, rcpt := range e.to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (e *Email) compose(a Alert) string {
	var b strings.Builder

	fmt.Fprintf(&b, "From: %s\r\n", e.from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.to, ", "))
	fmt.Fprintf(&b, "Subject: [wisp] %s\r\n", a.Summary())
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")

	b.WriteString("A wisp sensor recorded an interaction.\r\n\r\n")
	for _, line := range detailLines(a) {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString("Nothing legitimate has a reason to talk to a wisp sensor.\r\n")
	b.WriteString("Treat this as a real intrusion until proven otherwise.\r\n")

	return b.String()
}
