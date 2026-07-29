# Security policy

## Reporting a vulnerability

Report privately, through GitHub's private vulnerability reporting:

**<https://github.com/willysnow/wisp/security/advisories/new>**

Please do not open a public issue for a security problem. A public report on a
detection tool tells the people it is meant to detect exactly where to look,
while every deployment is still vulnerable.

If you cannot use that form, open an issue containing nothing but "security
report — request a private channel", and a way to reach you privately will be
arranged. Do not include details.

What helps: the version (`wispd -version` or `wisp-console -version`), what an
attacker gains, and the smallest reproduction you have. A proof of concept is
welcome but not required — a clear description of the flaw is enough to start.

**Expect an acknowledgement within seven days.** This is a small project, so
that is a commitment about answering, not about a fix date; the timeline for a
fix depends on severity and will be agreed with you. Credit is given in the
advisory unless you would rather not be named.

## Supported versions

Pre-1.0: only the latest release is supported. Fixes land on `main` and go out
in the next tagged release, or immediately for anything critical.

## What counts as a vulnerability here

This project has an unusual threat model — it is software you deliberately
expose to attackers — so it is worth being specific.

**In scope, and taken seriously:**

- **Any path where a decoy grants real access.** The first rule of every
  emulator is that no credential is ever accepted, no command executes, and no
  file is written. A way around that is the most serious bug this project can
  have.
- **Remote code execution or memory-unsafe behaviour in a decoy.** Every
  protocol module parses attacker-controlled input by design.
- **Reading console data without authenticating** — an authentication or
  session bypass, an information leak from an unauthenticated endpoint, or any
  route that returns event data to a signed-out request. The console database
  holds captured credentials, prompts, and tokens belonging to third parties.
- **Sensor impersonation or ingest forgery** — anything that lets one
  credential deliver events attributed to a different node, or lets an
  unenrolled party deliver at all.
- **Certificate verification bypass** on the sensor-to-console path, including
  a pinned fingerprint or a configured CA being ignored.
- **Turning a sensor into a weapon against a third party**: reflection or
  amplification, or a decoy that can be induced to make outbound connections
  an operator did not configure. (This is why the NTP module never answers
  mode 7 `monlist`, and why a test enforces it.)
- **Silencing a sensor or a console** — resource exhaustion, a crash, or a hang
  reachable from the network. A sensor that stops reporting looks exactly like
  a quiet network, which is the failure mode this project exists to prevent.
- **Leaking captured data to somewhere it was not configured to go.**
- **Vulnerable dependencies** with a reachable call path. CI runs
  `govulncheck`, so if you find one it reports, that is a CI bug too.

**Not vulnerabilities** — these are known properties, documented, and reports
about them will be closed with a pointer here:

- **The honeypot can be fingerprinted.** `nmap -O` identifies the host OS
  because user-space Go cannot shape the TCP/IP stack; banners, timing, and
  behaviour can all give a decoy away to a careful attacker. Improving realism
  is welcome as a feature request, but it is not a vulnerability.
- **The decoys reject every credential.** That is the design, not an
  authentication weakness.
- **The HTTP proxy decoy never forwards a request.** It answers every request
  with 407 and never opens an outbound connection, so it cannot be abused as an
  open relay or SSRF hop — that it does not proxy is the point, not a defect.
- **The SNMP decoy never answers.** It parses each request, records the community
  string and OIDs, and sends nothing back. SNMP is a top UDP amplification
  protocol, and an agent that replied could be reflected at a spoofed victim; the
  community is in the request, so silence loses no capture. "It does not respond
  to snmpget" is the design.
- **The DNS token server is authoritative-only.** When enabled it answers for the
  one delegated zone and refuses everything else — it never recurses, so it is not
  an open resolver, and it returns a single A record the size of the query, so it
  is not an amplifier. It puts the console on the public DNS, which is why it is
  off by default and opt-in; that it exists is the design, the same way the SNMP
  decoy's silence is.
- **The token callback endpoint is unauthenticated by design.** `/t/<id>` has to
  be public — an intruder trips it, and an intruder has no session. It records the
  hit and returns only a 1×1 GIF for a live id or a 404 for anything else; it never
  returns captured data, and the id space is 120 bits of randomness, so the 404 is
  not a useful oracle. A planted token id is not a secret in the first place: it
  travels inside the data it was planted in.
- **The portscan packet sniffer only reads.** Its Linux AF_PACKET socket captures
  packets to classify stealth scans; it never sends one. It needs `CAP_NET_RAW`,
  and where that is absent — or off Linux — it logs that it is unavailable and the
  cross-platform fan-out detection carries on, so it is never a reason wisp fails
  to start. Passive read-only capture is deliberately in scope; forging packets
  (which TCP/IP fingerprint spoofing would require) is deliberately not.
- **A credential-capturing decoy only captures what the client sends it.** The
  database and SMB decoys steer a client onto the authentication path that hands
  over a crackable — or, for MSSQL, cleartext — credential, but a client that
  insists on a path the decoy cannot speak yields no credential: the MSSQL decoy
  has no certificate, so a client that requires TLS or uses Windows/integrated
  authentication is recorded only as an attempt; the MySQL decoy captures the
  native-password response, not a `caching_sha2_password` secret carried over
  TLS; SMB captures NTLMv2, not Kerberos; the RDP decoy captures the CredSSP/NLA
  NetNTLMv2, not the legacy standard-security or plain-TLS credential path. This
  is a property of not holding the keys a real server would, not a weakness.
- **The console warns loudly about a shared ingest token, missing TLS, or no
  retention policy.** Those warnings describe configuration choices; the
  defaults are documented and the warnings say what to do.
- **`insecure_skip_verify` disables certificate verification.** It is named for
  what it does and documented as a lab setting.
- **An operator can read captured credentials in the UI.** That is what the UI
  is for. The relevant question is whether someone who is *not* an operator can.
- Anything requiring an attacker to already have root, the console database
  file, or a valid operator password.

## Testing safely

Test against a deployment you control. A wisp console on the internet belongs
to someone who is watching their alerts, and probing it is indistinguishable
from the intrusion it was built to catch — you will be treated as an attacker,
because the whole point is that nothing legitimate talks to it.

## If you are running wisp

Two things carry other people's data, and both deserve the handling you would
give a password store:

- **The console database** holds credentials, prompts, and tokens captured from
  whoever touched your sensors. Some of that belongs to third parties, and some
  of it will be real credentials reused from elsewhere.
- **Notification channels** — email, LINE, webhooks — carry the same content to
  whoever operates the endpoint. Point them at infrastructure you control.

Sensor tokens and operator passwords are stored only as hashes, so a stolen
database yields no working access to wisp itself. It still yields everything
the sensors captured.
