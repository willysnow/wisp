# wisp

A single-binary network honeypot sensor. Deploy it on an internal segment, wait
for something to touch it, and get an alert with the credentials, the prompt,
the query, the container spec, or the paths the intruder tried.

> The name is the will-o'-the-wisp: a light in the dark that leads you off the
> path. It is deliberately **not** Canary-anything — "Canary" and
> "Canarytokens" are Thinkst trademarks, and this project is an independent
> reimplementation rather than a fork or a successor.

> **Status: early.** `wisp` covers 18 of OpenCanary's 21 protocol modules and
> is not yet a replacement for it — see [Honest comparison](#honest-comparison)
> before you deploy it.

## Why this exists

[OpenCanary](https://github.com/thinkst/opencanary) (BSD-3-Clause, by Thinkst)
proved the model, is more complete than this project, and remains a genuine
contribution to the field. `wisp` is not a criticism of it — it is a bet that
two things are worth redoing:

1. **Deployment.** OpenCanary needs Python 3.10+, Twisted, Scapy, pcapy-ng, and
   — for SMB — a working Samba install with a `full_audit` VFS module writing to
   syslog for OpenCanary to tail. `wisp` is one static binary.
2. **Attack surface.** Intruders on an internal network in 2026 reach for the
   Kubernetes API, the kubelet, the Docker socket, cloud IMDS, the CI server,
   and whatever LLM infrastructure someone stood up without auth. Nine of the
   decoys below exist because of that, and OpenCanary has none of them.

Everything else OpenCanary does, it currently does better, because it does it
at all.

## Honest comparison

OpenCanary ships 21 protocol modules. `wisp` has reimplemented **18** of them,
plus 9 decoys OpenCanary does not have.

| | OpenCanary | wisp today |
|---|---|---|
| Protocol modules | 21 | **18** + 9 new decoys |
| Implemented here | — | `ssh`, `http`, `https`, `telnet`, `ftp`, `redis`, `tftp`, `ntp`, `git`, `mongodb`, `mysql`, `mssql`, `smb`, `vnc`, `sip`, HTTP proxy, `llmnr`, TCP banner |
| Still missing | — | RDP, SNMP, portscan |
| SMB | yes, via external Samba | **native** — no Samba, captures NetNTLMv2 |
| Cloud / container / CI / LLM decoys | no | **yes** (`k8s`, `kubelet`, `docker`, `imds`, `elasticsearch`, `jenkins`, `gitlab`, `ollama`, `mcp`) |
| Alerting | file, syslog, HPFeeds, email, webhook, + separate dedup daemon | JSONL, syslog, HPFeeds, email, LINE, webhook (Slack/Teams/Discord), **dedup built in** |
| Fleet console | none | **included, self-hosted** |
| Install | Python + Twisted + Scapy (+ Samba for SMB) | one static binary |
| Platforms | Linux-first, root for several modules | anywhere Go cross-compiles |

The generic TCP banner catcher covers any additional port at connection level —
enough to see a scan or a probe, but it cannot capture credentials the way a
real emulator does. It ships pointed at RDP by default, which has no native
emulator yet: X.224 catches the connection, but capturing a hash there needs
NLA/CredSSP.

If you need full coverage today, run OpenCanary. Run `wisp` if you want the LLM
decoy, or if the Python/Samba dependency chain is what is stopping you from
deploying a honeypot at all.

## What it emulates today

| Service | Default port | What it captures |
|---|---|---|
| `ssh` | 2222/tcp | usernames, passwords, public-key fingerprints, client versions |
| `http` | 8080/tcp | admin-panel credentials, probed paths, user agents |
| `https` | 8443/tcp | the same, plus the **SNI** — the name they expected to find here |
| `telnet` | 2323/tcp | usernames and passwords (IAC negotiation stripped) |
| `ftp` | 2121/tcp | usernames, passwords, and post-login command intent |
| `redis` | 6379/tcp | AUTH credentials **and the full command sequence** |
| `tftp` | 6969/udp | requested filename and whether it was a read or a write |
| `ntp` | 1123/udp | client requests, and **mode 7 `monlist` amplification recon** |
| `git` | 9418/tcp | the **repository path** requested, and whether they meant to push |
| `mongodb` | 27017/tcp | usernames and **SCRAM proofs that crack offline**, driver and app name |
| `mysql` | 3306/tcp | usernames and **native-password responses that crack offline** — hashcat 11200 |
| `mssql` | 1433/tcp | usernames and the **cleartext password itself** — TDS obfuscation is reversible, not a hash |
| `smb` | 445/tcp | **NetNTLMv2 hashes** and the account name — hashcat 5600, no Samba |
| `vnc` | 5900/tcp | the **VNC-auth challenge-response** — cracks offline, John the Ripper `vnc` |
| `sip` | 5060/udp | the **REGISTER digest** — cracks offline (hashcat 11400), plus scanner recon |
| `http-proxy` | 3128/tcp | the **tunnel target** (SSRF/open-proxy intent) and cleartext proxy creds |
| `llmnr` | outbound | **an active poisoner on the segment**, and the address it claims |
| banner | any | first bytes sent, for ports without a real emulator |
| `ollama` | 11434/tcp | **model-list recon, and the actual prompts sent to your "GPU"** |
| `k8s` | 6443/tls | **stolen service-account bearer tokens**, client certs, resources probed |
| `kubelet` | 10250/tls | **the command they ran inside a pod**, and the token they ran it with |
| `docker` | 2375/tcp | **the container spec** — the host mount, the `Privileged` flag, the command |
| `imds` | 169.254.169.254 | **cloud role-credential theft**, on AWS, GCP and Azure paths |
| `elasticsearch` | 9200/tcp | **the search query** — which fields they wanted, and how many rows |
| `jenkins` | 8081/tcp | **the Groovy script** posted to the console, and login attempts |
| `gitlab` | 8929/tcp | **stolen `glpat-` access tokens**, and what they pointed them at |
| `mcp` | 8931/tcp | **which agent connected, and the tool calls it made with arguments** |

### The nine decoys OpenCanary does not have

These cover the surface an intruder actually reaches for on a 2026 network, and
each captures something a connection log cannot.

To be accurate about it: single-purpose honeypots exist for some of these —
ElasticPot for Elasticsearch, and more than one Docker-socket trap — and T-Pot
will run a pile of them side by side. What is not on offer elsewhere is all nine
in one static binary, reporting to one console, with the LLM and MCP decoys
alongside them.

- **`ollama`** records the prompt. An unauthenticated inference endpoint is a
  free GPU, a pivot, and — when wired to internal RAG — an exfiltration path.
- **`k8s`** answers `403`, not `401`. That is what an anonymous-auth-enabled
  cluster does, and the difference matters: `401` reads as "wrong door" and ends
  the interaction, while `403` reads as "right door, wrong credentials", so the
  attacker retries with a stolen token. Knowing *which service account* was
  compromised is far more actionable than knowing someone knocked.
- **`kubelet`** is the more useful of the two Kubernetes ports. A kubelet that
  trusts anonymous requests lists every pod on the node and then runs a command
  inside any of them — no cluster credential involved. The command is the
  capture, and nothing is executed to produce the reply:

  ```
  kubelet  command  pod=payments-api-7d4f9c8b5-2xk4n
           cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token
  ```

- **`docker`** records the container specification, which is a written-down
  plan. Nobody bind-mounts `/` into a container by accident, so the `escape`
  field names the reasons the spec would have handed over the host:

  ```
  docker  container_create  image=alpine  cmd=chroot /host sh
          binds=/:/host  privileged=true  escape=host_filesystem privileged
  ```

  It also decodes `X-Registry-Auth`, which carries a registry username and
  password in the clear — usually the intruder's own.

- **`imds`** answers on 169.254.169.254 for AWS, GCP and Azure at once. There is
  no benign reason for an unfamiliar process to ask it for role credentials,
  which makes this one of the very few honeypot signals with almost no
  false-positive story. Which cloud's API they reached for says what they
  believed they had landed on, and an `X-Forwarded-For` on the request says it
  was an SSRF rather than a foothold. The credentials returned are well-formed
  and authenticate to nothing — they exist so the request *after* the credential
  request still happens.

- **`elasticsearch`** is the one decoy deliberately left wide open, because that
  is what the installed base looks like and because the credential is not the
  prize here. The query is:

  ```
  elasticsearch  search_query  index=customers
                 query={"query":{"match_all":{}},"_source":["email","card_last4"],"size":10000}
  ```

  A cluster that asked for a password would have produced a 401 in the scanner's
  log and nothing else. `DELETE /*` followed by a write to `read_me` — the two
  halves of an Elasticsearch ransom — are recorded as `delete_request` and
  `write_request`, and neither actually happens.

- **`jenkins`** has the Groovy script console, which turns read access into code
  execution on the controller. The submitted script says which credential store
  they already knew to ask for. There is no interpreter behind it.

- **`gitlab`** captures stolen personal access tokens the way `k8s` captures
  stolen service-account tokens — from the `PRIVATE-TOKEN` header, the `JOB-TOKEN`
  header, or the query string, which is how they leak in the first place. Public
  endpoints answer so there is somewhere to point the token; nothing is ever
  accepted.

- **`mcp`** records the agent's own `clientInfo` (a much stronger identifier
  than a user-agent) and the arguments of every `tools/call`. The advertised
  tools are deliberately tempting, so the one they reach for tells you what they
  were after:

  ```
  mcp  tool_call  tool=query_customer_db
       arguments={"query":"SELECT email, credit_card FROM customers LIMIT 5000"}
  ```

Several of these answer instead of refusing, because a plausible reply keeps the
attacker talking and every further message is more intelligence:

- **redis** returns `+OK`, so a scripted takeover runs its whole playbook where
  you can watch it. A real attack looks like `CONFIG SET dir /root/.ssh` →
  `CONFIG SET dbfilename authorized_keys` → `SET x "ssh-rsa …"` → `SAVE`, and
  all four land in your log.
- **ollama** returns a model list and a refusal message, so the scanner sends a
  real prompt.
- **kubelet** answers `id` with `uid=0(root)` from a table of eight commands.
  An intruder whose first command comes back empty concludes the endpoint is
  broken and leaves; one who sees a root identity sends a second command, and
  the second command is usually the one that says what they came for.
- **elasticsearch** returns three fabricated documents rather than zero hits,
  for the same reason.
- **ntp** answers ordinary mode 3 client requests.

Nothing is actually granted — no file is written, no command executes, no
container is created, no index is deleted, and every credential is rejected.
Each of those is covered by a test that fails loudly rather than a comment
saying it must not happen: the kubelet decoy is sent `touch <path>` and the
path must not exist afterwards; the Docker decoy is asked to create three
containers and its inventory must not change.

**`ntp` never answers mode 7 (`monlist`).** Replying would turn the sensor into
a working DDoS amplifier pointed at whatever address the attacker spoofed. It
logs the probe and stays silent; the property is covered by a test.

**`llmnr` never answers a query.** It is the one module that is not a decoy: it
multicasts a request for a hostname that does not exist and waits. A correct
network answers with silence, so a reply is proof of a poisoner — Responder,
Inveigh, and the rest answer everything, because answering everything is how
they work. Answering one ourselves would *be* that attack, and a detector that
performs the attack it detects is not a detector. Also covered by a test.

It is off by default, because it is the only module that puts packets on the
network of its own accord.

**`mongodb` claims authentication is required** rather than pretending to be
wide open, for the same reason `k8s` answers 403. A locked door invites a key:
the driver then runs SCRAM, which hands over the username immediately and — once
the client sends its proof — a value that can be attacked offline the way a
captured NetNTLMv2 response can. Nothing is ever accepted; every conversation
ends in `AuthenticationFailed`.

**`mysql` captures a crackable password response, the same shape as `smb` and
`mongodb`.** The server issues a random scramble and the client answers with a
value keyed by the password; recorded together they crack offline as hashcat
mode 11200. The decoy advertises `mysql_native_password` rather than MySQL 8's
default `caching_sha2_password` on purpose — native's response is a clean value a
wordlist can attack, while caching_sha2 needs TLS or an RSA exchange to carry the
secret and yields nothing crackable — and switches a client that offers a
different plugin onto native, the way a real server does. A test computes a
genuine response for a known password and cracks the captured line back to it, so
a hash that does not crack fails the build. Every login ends in access denied.

**`mssql` goes one better and recovers the cleartext password.** A TDS client
opens by negotiating encryption; the decoy answers "not supported", which a
willing client accepts by sending its `LOGIN7` — password included — in the
clear. A `LOGIN7` password is not hashed, only obfuscated with a fixed,
reversible nibble-swap-and-XOR, so what comes out is the password itself, logged
as a `login_password` event like any other cleartext credential. The one case it
cannot open is a client that requires TLS or uses Windows authentication — the
first needs a certificate the decoy does not have, the second carries an NTLM
blob rather than a password — and those are recorded as attempts with whatever
the login named, but no password. Every login ends in error 18456.

**`smb` is that same NetNTLMv2 capture, done natively.** It is the module that
answers "why not just run OpenCanary": OpenCanary's SMB is not OpenCanary at all
but an external Samba install with a `full_audit` VFS module writing to syslog
for it to tail — the ugliest link in its dependency chain, and the reason a lot
of people never get it running. Here it is one static binary. A client that
reaches a share authenticates with NTLMv2 first, so the server issues a
challenge and the client answers with an HMAC over it keyed by the password;
choose the challenge yourself — a fixed one, the way Responder does — and the
answer is a credential that cracks offline:

```
smb  auth_attempt  username=jsmith  domain=CORP  workstation=WKS-4021
     netntlmv2=jsmith::CORP:1122334455667788:<NTproof>:<blob>
```

That line is hashcat mode 5600, ready to paste. Choosing the challenge does not
weaken anyone — the credential captured is the intruder's, and knowing the
challenge does not help attack the server that issued it. Nothing is ever
granted: every authentication ends in `STATUS_LOGON_FAILURE`, so the session
never completes and there is no share, no tree connect, and no file operation
to get wrong. The property that matters most has an executable proof — a test
computes a genuine NTLMv2 response for a known password, captures it through the
decoy, and then cracks the captured line back to that password, because a hash
that does not crack is not the deliverable.

`smb` binds an unprivileged port by default (`4445`) and you redirect 445 to it,
the same pattern as `ssh` on 2222. On a Windows sensor, where the OS holds 445
open itself, the decoy is for a segment reached through that redirect rather
than the host's own port.

**`vnc` is the same challenge-response capture on 5900.** It was a banner catcher
until it learned to do the RFB handshake, and the change is the same one that
separates `mongodb` from a connection log: the decoy offers *only* VNC
Authentication, never "None", so a client cannot connect without returning the
DES-encrypted challenge. Record the challenge next to the response and the pair
cracks offline with John the Ripper's `vnc` format — there is no clean hashcat
mode for it, because the DES key is the password with its bits reversed, over two
blocks. Every attempt ends in a security-result failure, so no framebuffer is
ever served. Like `mysql` and `smb`, the load-bearing property has a test that
computes a real response for a known password and cracks the captured line back
to it.

**`sip` looks like a live PBX so a scanner escalates.** It is the protocol
sipvicious and friendly-scanner sweep for, and the decoy plays the part: it
answers OPTIONS with 200 OK — which is exactly how `svmap` decides a box is a
real PBX worth attacking — and challenges REGISTER with a digest nonce it chose
and recorded. When the client answers, the username, realm, nonce, method, URI
and response are captured together as a hashcat-11400 line (also John's SIP
format). A test verifies both halves of that: that the captured components
re-derive the response from a known password, and that the assembled line splits
the URI so hashcat computes the same HA2 the client did. It runs on UDP, only
answers well-formed SIP, and its reply is the size of the request, so it is not
an amplifier. Every credential ends in 403.

**`http-proxy` catches the pivot.** An intruder scans for an open proxy to borrow
someone else's egress, and the request itself is the signal: a CONNECT to
169.254.169.254 or an internal address is an SSRF hop through the decoy, and an
absolute-form `GET http://…` is an open-proxy checker confirming the relay works.
The decoy records the target and answers 407 — never opening the connection,
because a sensor that made outbound requests on an intruder's behalf would be an
actual relay. The 407 also does what a closed proxy does: it invites credentials,
and a `Proxy-Authorization: Basic` header is base64, not a hash, so what comes out
is the cleartext proxy password, logged as `login_password`.

**`imds` listens on an ordinary port by default (`8169`), not on
169.254.169.254.** That address has to exist on the host before anything can
bind it, so putting it in front of the decoy is a deliberate step —
`ip addr add 169.254.169.254/32 dev lo` plus a `REDIRECT` rule, both spelled out
in [`wisp.example.yaml`](wisp.example.yaml).

**Do not take that step on a machine that is itself a cloud instance.** You
would shadow the real metadata service, and every process on the box that needs
role credentials would start receiving fabricated ones. The decoy belongs on a
sensor host that is *not* an EC2/GCE/Azure VM, or on one where you have
confirmed nothing depends on the real 169.254.169.254.

## One device, not several

Left to themselves the emulators describe a machine that cannot exist: an
Ubuntu SSH daemon in front of an nginx serving a panel called
"Administration", with a vsftpd underneath. Any one of those is convincing.
Together they are a tell, because a real device on a real network is one
product, and every port it answers says that product's name.

```yaml
device:
  persona: synology
```

That renames the banners of `ssh`, `http`, `https`, `ftp` and `telnet` at once,
so an intruder who touches three ports gets three answers that agree — down to
the title on the login page and the firmware string under the form. Built in:
`ubuntu` (the default, so selecting it changes nothing), `synology`, `qnap`,
`truenas`, `hp-printer`.

Anything set explicitly under `services:` still wins, so you can take a whole
device and then correct the one banner your environment needs differently.

Two honest limits:

- **It stops at the appliance services.** A Synology NAS does not run a
  Kubernetes apiserver either, so the persona deliberately leaves the cloud,
  container and CI decoys alone rather than swapping a small inconsistency for a
  larger one. A sensor running both sets is already describing two machines; run
  two sensors if that matters.
- **A persona with nothing to say about a port says so.** A LaserJet has no
  sshd, so `persona: hp-printer` with `ssh` enabled warns at startup instead of
  quietly leaving an Ubuntu banner on a box whose every other port says HP.
  Whether to run the service is still your call.

When `device.name` or `device.desc` is set — a persona fills both in — they are
stamped onto every event, so an alert says what the box was pretending to be
without anyone having to look up the deployment. With no persona configured
neither appears, and the events are exactly the shape they always were.

## Quick start

```bash
go mod tidy
go run ./cmd/wispd
```

No config file is required — it runs on defaults. To customise:

```bash
cp wisp.example.yaml wisp.yaml
go run ./cmd/wispd -config wisp.yaml
```

Then trip it:

```bash
ssh -p 2222 root@localhost
```

```bash
curl -s localhost:11434/api/generate -d '{"model":"llama3.2","prompt":"cat /etc/shadow","stream":false}'
```

```bash
curl -sk https://localhost:10250/pods
```

```bash
curl -s localhost:2375/v1.43/containers/create -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host","sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
```

```bash
curl -s localhost:9200/customers/_search -H 'Content-Type: application/json' \
  -d '{"query":{"match_all":{}},"_source":["email","card_last4"],"size":10000}'
```

```bash
curl -s localhost:8169/latest/meta-data/iam/security-credentials/app-instance-role
```

## Docker

One `Dockerfile` builds both images, and both are distroless — no shell, no
package manager, nothing to pivot into. The sensor is the container most likely
to be attacked on purpose, so it carries the least.

```bash
docker build --target sensor -t wisp/sensor .
```

```bash
docker build --target console -t wisp/console .
```

A one-host evaluation stack (in production the console belongs somewhere other
than the segment you expect to be attacked):

```bash
docker compose up --build
```

Two things about running a honeypot in a container matter more than the rest:

- **Use host networking on Linux.** With published ports, Docker can rewrite
  the client's address to the bridge gateway, and an alert saying every
  intrusion came from `172.17.0.1` is one nobody can act on. On Docker Desktop
  (macOS/Windows) that rewriting is unavoidable — map ports there and treat
  source IPs as unreliable.
- **Keep the volumes.** They hold the SSH host key, the decoy TLS
  certificates, the console database, and the operator accounts. Key material
  that changes on every restart identifies the box as a honeypot to anyone who
  connects twice.

Both containers run as a non-root user with a read-only root filesystem, every
capability dropped, and `no-new-privileges`. Ports are the unprivileged
defaults, so nothing needs to be granted back.

The console image has no shell to run a health probe with, so the binary probes
itself — `wisp-console healthcheck` is wired up as the image's `HEALTHCHECK`
and is what an orchestrator will use to decide the console is alive.

## systemd

Units for both halves are in [`deploy/systemd/`](deploy/systemd), sandboxed to
the same standard as the containers: no capabilities, nothing writable but
their own state directory, a seccomp filter, and no path back to root. The
sensor parses hostile input by design, and a unit file should not depend on the
code being correct.

```bash
sudo install -m 0755 wispd /usr/local/bin/wispd
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wisp
sudo install -m 0644 deploy/systemd/wispd.service /etc/systemd/system/
sudo systemctl enable --now wispd
```

`StateDirectory` and `ConfigurationDirectory` create `/var/lib/wisp` and
`/etc/wisp` with the right ownership, so there is no `chown` step. Full
instructions, including the console and how to bind privileged ports without
granting the capability, are in
[`deploy/systemd/README.md`](deploy/systemd/README.md).

## Output

Two sinks, both on by default. Console for humans:

```
14:22:07  ollama  prompt         10.0.3.44:51188 -> :11434  model=llama3.2  path=/api/generate  prompt=cat /etc/shadow
```

…and `events.jsonl` for machines — one JSON object per line, ready for Vector,
Filebeat, or a SIEM:

```json
{"time":"2026-07-24T14:22:07.113Z","node":"wisp-01","service":"ollama","kind":"prompt","src_ip":"10.0.3.44","src_port":51188,"dst_port":11434,"data":{"model":"llama3.2","prompt":"cat /etc/shadow"}}
```

## Console

A fleet of sensors writing to their own local files is not a monitoring system.
`wisp-console` is the piece that makes it one: sensors deliver over HTTPS with a
bearer token, and every alert lands in one place.

It is self-hosted and needs nothing but a writable file — SQLite via a pure-Go
driver, so the console is a single static binary too.

```bash
go build -o wisp-console ./cmd/wisp-console
./wisp-console sensor add sensor-01
```

That prints a token — once. Put it in the sensor's config:

```yaml
log:
  file: events.jsonl
  console: true
  remote:
    url: "https://console.example.com"
    token: "wisp_..."
```

Then run the console:

```bash
./wisp-console -addr :8000
```

Each sensor gets its own token, and **the node name comes from the token, not
from the request body**. A sensor cannot claim to be a different one, so an
operator chasing an alert is never sent to the wrong machine. Manage them with:

```bash
./wisp-console sensor list
```

```bash
./wisp-console sensor revoke sensor-01
```

Re-running `sensor add` for an existing node issues a new token and invalidates
the old one — that is both rotation and "I lost the token". Only the SHA-256 of
a token is stored, so a stolen console database yields no working credentials.

For compatibility a single shared token still works (`-token`, or
`WISP_CONSOLE_TOKEN`), but the console warns at startup: with a shared token the
node name falls back to whatever the payload claims, and any holder can forge
events attributed to any sensor.

Then open the console in a browser. Credential events (`login_password`,
`auth_attempt`, …) are highlighted; clicking a sensor, service, or source IP
filters the view.

### Signing in

The UI is behind a login, and there is no setting that turns that off. Locking
ingest behind a token while leaving the dashboard open would protect nothing —
the dashboard is where every captured password, prompt, and stolen token ends
up.

On its first start the console creates one operator account and prints the
password once:

```
created console operator "admin" with password: QOavm-F81rHgpHHQuX-Cqv48
```

Manage accounts from the CLI:

```bash
./wisp-console user add alice
```

```bash
./wisp-console user list
```

`user add` and `user passwd` generate a password and print it once; pass
`-password-stdin` to supply your own instead (minimum 12 characters):

```bash
printf '%s\n' "$NEW_PASSWORD" | ./wisp-console user passwd alice -password-stdin
```

Changing a password signs out every session that account holds — a password is
usually changed *because* it leaked, and leaving the old sessions live would
defeat the point. Sessions last 12h by default (`ui.session_ttl`), live in the
database so a restart does not sign everyone out, and are stored as hashes, so
a stolen database yields no working access.

Sensor tokens and operator logins are separate credentials on purpose: a sensor
sitting on a hostile segment can write events and nothing else. Its token will
not open the UI, and a UI session will not deliver events.

Behind a reverse proxy, set `ui.trust_proxy: true` so the login rate limit sees
real client addresses instead of the proxy's — otherwise one attacker's failed
logins lock everybody out.

### TLS

The console terminates TLS itself — no reverse proxy required. Sensors send
captured credentials and their bearer tokens, and operators send a password;
none of that should cross a network in the clear.

```yaml
tls:
  mode: self-signed        # off | self-signed | file | acme
  cert_file: console-cert.pem
  key_file: console-key.pem
  domains: ["console.internal"]
```

**`self-signed`** is the right answer for most consoles, which live on an
internal segment with no public DNS name. The certificate is generated once and
kept — one that changed every restart could not be pinned — and its fingerprint
is printed at startup:

```
TLS: self-signed certificate
     SHA-256 51:49:55:A1:64:D0:50:F0:DD:CE:22:40:A2:EA:D3:A6:...
```

Give that to the sensors, so nobody has to reach for "skip verification":

```yaml
log:
  remote:
    url: "https://console.internal:8000"
    token: "wisp_..."
    fingerprint: "51:49:55:A1:..."   # or ca_file: console-cert.pem
```

A sensor with a pin refuses to deliver to anything else — including a TLS
proxy that re-signs the connection. (That is not hypothetical: on a machine
running Norton's Web Shield, the pinned sensor correctly refused to talk to a
console on the same host, because what it was handed was Norton's certificate
and not the console's.) `insecure_skip_verify` exists, is documented as a lab
setting, and sends every captured credential to whoever answers the connection.

**`acme`** obtains certificates from Let's Encrypt for a public name. It
requires `accept_tos: true` — agreeing to a CA's terms on an operator's behalf
is not the software's call. Port 80 is optional: with no `http_addr`, issuance
uses TLS-ALPN-01 over 443. Set `http_addr: ":80"` to serve the HTTP-01
challenge and redirect plain HTTP to HTTPS.

**`off`** is still there for a deployment that already has a proxy in front,
and the console warns loudly on every start.

### Searching, paging, and exporting

The event list pages at 100 rows, and the search box matches free text against
every column **including the JSON data blob** — which is where the interesting
strings live. Searching `hunter2` finds the login that used it; searching
`/etc/shadow` finds the prompt that asked for it; searching `10.0.0.9` finds
everything that address touched. Clicking a sensor, service, or source IP still
filters, and search narrows within whatever is already filtered rather than
replacing it.

Export takes the same filter as the page it is started from, as CSV or as
newline-delimited JSON — the same shape a sensor's `events.jsonl` has, so
anything already pointed at that will read this too.

```
/export.csv?q=hunter2&hours=168
```

One detail worth knowing about the CSV: every field in it is attacker-chosen —
a username, a probed path, a prompt. A value beginning with `=` is executed as
a formula when a spreadsheet opens the file, so an attacker who picks their
username carefully could get code execution on the machine of the analyst
reading the export. Those values are prefixed with an apostrophe on the way
out; the payload is still readable as evidence, it just is not run.

### When a sensor goes quiet

A sensor cannot report its own death. If someone finds it and stops it, the
last thing it does is go silent — and a silent sensor looks exactly like a
network where nothing is happening. The console is the only place that can tell
those apart:

```yaml
sensors:
  silence_after: 30m
  check_interval: 1m
```

Crossing the threshold raises a `sensor_silent` event: stored in the timeline,
pushed through every notifier, and marked in red on the sensor list. Coming
back raises `sensor_returned`, because whoever was woken at 3am should not have
to guess whether it is still down. Each is reported once per transition, so a
sensor that stays down does not page anyone every minute.

This is the only alert in wisp that fires because nothing arrived, and it is
the one most likely to matter: an intrusion that begins by killing the sensor
is otherwise invisible.

### Retention

Left alone, the database grows forever and its size is decided by whoever is
scanning your sensors — a console whose disk fills up stops recording the
intrusion that filled it. Set a policy in `console.yaml`:

```yaml
retention:
  events: 90d          # maximum age; accepts d and w as well as h/m/s
  max_events: 1000000  # hard cap whatever the age; oldest go first
  interval: 1h         # how often the policy is applied
```

Both limits apply, whichever bites first. The count cap is the backstop age
cannot provide: a sensor under sustained scan produces months of events in an
afternoon. Purged space is returned to the filesystem — SQLite reuses freed
pages but never shrinks the file on its own, so the console rebuilds it after a
large enough sweep.

The default is unlimited, because silently discarding an operator's evidence
would be the wrong way round — but the console warns at startup until a policy
is set.

Delivery is best-effort by design: `Emit` never blocks a service goroutine, and
when the console is unreachable events queue and are eventually dropped. A
sensor that stops answering the network because its reporting channel stalled is
worse than one that loses telemetry — a hung service is a detectable tell.

### Notifications

A dashboard nobody opens is not monitoring. Copy `console.example.yaml` to
`console.yaml` to send alerts by **email**, **LINE**, or **webhook** (JSON,
Slack, Teams, Discord).

Two rules decide what gets sent, and both matter:

**Only meaningful kinds notify.** Credentials offered (`login_password`,
`auth_attempt`, …) and intent stated (`prompt`, `tool_call`, `command`, …).
Bare connections and version probes are stored but not pushed — they are
context for an investigation, not a reason to wake someone at 3am.

**Repeats are suppressed per `sensor|service|kind|source-IP`** for a configurable
window (15m by default). The next alert after the window says how many were
folded in: `ssh login_password from 10.0.0.9 (+47 similar suppressed)`. A second
source IP is always a new alert — suppression must never hide a new attacker.

In a local end-to-end run, 40 stored events produced 7 notifications — a repeated
telnet brute force from one source collapsed from 4 alerts to 1. Without this,
a single port scan mutes your channel and the next real intrusion is missed.

LINE is there because in Taiwan and Japan that is where operations teams
actually are.

## Rate limiting

A honeypot writes a record every time a stranger touches it. An attacker who
works out what it is can turn that around: hold the port open and the sensor
fills its own disk and buries the console under deliveries. The sensor must not
be the thing that takes down the fleet's monitoring.

Limits are on by default. All values are events per minute; a burst is how many
may arrive at once:

```yaml
log:
  rate_limit:
    enabled: true
    per_source_per_minute: 60
    per_source_burst: 30
    high_value_per_minute: 30    # credentials and stated intent
    high_value_burst: 60
    global_per_minute: 600       # the whole sensor, every source
    global_burst: 300
```

Three properties matter more than the numbers:

- **The first events from a new source always land.** That is the alert;
  dropping it to save disk would be exactly backwards.
- **Credentials and prompts have their own budget.** A flood of bare
  connections cannot crowd out the one `login_password` that matters — the
  protected list is the same one the console notifies on.
- **Suppression is reported, not silent.** A truncated log looks like a quiet
  network, and going quiet is the opposite of what a flood should look like.
  Throttled sources emit a `rate_limited` event with the tally:

```json
{"service":"http","kind":"rate_limited","src_ip":"127.0.0.1",
 "data":{"dropped":92,"duration":"1m2s","kinds":{"probe":92}}}
```

In a local run, 100 requests in ten seconds were recorded as 8 events plus that
one summary — the flood is still visible, and it costs 9 lines instead of 100.

The per-source limit is also what protects the sensor-wide budget: one flooding
address can only ever spend its own allowance, so it cannot silence the rest of
the network. The source table is bounded too, because an attacker rotating
addresses is the same denial of service by another route.

### Log rotation

Rate limiting stops a flood arriving faster than the disk can take it. It does
not stop a year of ordinary traffic from filling the partition, and a sensor
whose disk is full stops recording the intrusion that filled it — the same
failure the console's retention policy prevents, at the other end of the pipe.

```yaml
log:
  file: events.jsonl
  rotate:
    max_size_mb: 100
    max_files: 5
```

On by default at those values, for the same reason the rate limiter is: a sensor
that only bounds its disk once somebody configures it is unbounded on every
deployment that matters. Set `max_size_mb: -1` if logrotate or journald already
manages the file — two rotators fighting over one file is worse than either
alone.

Rotation is by rename, oldest first: `events.jsonl.5` is removed, `.4` becomes
`.5`, and the live file becomes `.1`, so `events.jsonl` is always the one to
tail. The size check happens *before* each write rather than after, which is
what keeps a record whole: the JSONL sink hands over one complete line at a
time, so a line always lands in exactly one file. Rotating afterwards would
leave the tail of a JSON object in one file and nothing in the next, and a
half-written object is a parse error in whatever you pointed at the log.

### HPFeeds

Events can also be published to an [hpfeeds][hpfeeds] broker — the pub/sub bus
honeypot operators share data over, and what OpenCanary, Cowrie and Dionaea
speak when they feed a shared collector. It is here so a wisp sensor can join an
existing fleet rather than sit beside one.

```yaml
log:
  hpfeeds:
    enabled: true
    addr: "broker.internal:10000"
    ident: "wisp-01"
    secret: "..."
    channel: "wisp.events"
    tls: true
```

The payload is the same JSON object `events.jsonl` holds, so a collector pointed
at both does not need two parsers. The secret is never sent — the broker
announces a nonce and the client proves it knows the secret by hashing the two
together — but that protects the credential and nothing else: the events
themselves carry captured passwords, so `tls: true` belongs on for anything
leaving a network you own. It trusts a private certificate the same two ways the
console connection does, by fingerprint or CA file.

Delivery is best-effort on the same contract as the console sink. `Emit` never
blocks, a full queue drops events and counts them, and a broker that goes away is
reconnected to with backoff. A service goroutine held up because a collector is
slow is a service that answers the network late, and a hung service is a
detectable tell.

[hpfeeds]: https://hpfeeds.org/

## Layout

```
cmd/wispd/              sensor entry point, service wiring, signal handling
cmd/wisp-console/       console server, sensor/user CLI, healthcheck
internal/config/        sensor YAML config with defaults-first loading
internal/event/         the one event type every service emits
internal/persona/       the device this sensor claims to be, on every port
internal/sink/          console + JSONL output with rotation, remote delivery,
                        hpfeeds, rate limiting
internal/tlsutil/       decoy certificates, and how a sensor trusts a console
internal/service/       the Service interface
  httpdecoy/            the machinery the HTTP-shaped decoys share
  servicetest/          the harness every emulator is tested with
  sshsvc/               OpenSSH emulation via x/crypto/ssh
  httpsvc/              fake device admin login, plain and behind TLS
  mongosvc/             MongoDB wire protocol and SCRAM capture
  mysqlsvc/             MySQL handshake and native-password hash capture
  mssqlsvc/             MSSQL/TDS handshake and cleartext LOGIN7 password capture
  smbsvc/               SMB2/3 and NTLMv2 hash capture, no external Samba
  vncsvc/               RFB handshake and VNC-auth challenge-response capture
  sipsvc/               SIP over UDP, REGISTER digest capture (hashcat 11400)
  proxysvc/             HTTP forward proxy: tunnel target and cleartext creds
  llmnrsvc/             LLMNR poisoning detection (not a decoy)
  ollamasvc/            fake Ollama inference server
  k8ssvc/               Kubernetes apiserver, and the tokens aimed at it
  kubeletsvc/           kubelet: pod inventory and in-pod command capture
  dockersvc/            Docker Engine API and container-escape specs
  imdssvc/              cloud instance metadata, AWS + GCP + Azure
  elasticsvc/           open Elasticsearch and the queries run against it
  jenkinssvc/           Jenkins, including the Groovy script console
  gitlabsvc/            GitLab, and stolen glpat- access tokens
internal/console/       UI, auth, retention, TLS termination
  store/                SQLite: events, sensors, operators, sessions
  notify/               email, LINE, webhooks, and alert dedup
```

Adding a protocol means one package implementing `service.Service` and one line
in `buildServices`.

## Development

```bash
go test ./...
```

CI runs on every push and pull request: `gofmt`, `go vet`, `go mod tidy`
cleanliness, tests on Linux/macOS/Windows, the race detector, `govulncheck`,
and a cross-compile of every supported target — "anywhere Go cross-compiles" is
a claim in this README, so it is checked rather than left for the first person
to try it on a Raspberry Pi. (It has already earned its keep: the Ollama decoy's
model sizes were untyped constants larger than a 32-bit `int`, so the sensor did
not build for `linux/arm` at all.) Both container images are built — never
pushed — and the console is started to confirm it answers its own healthcheck.

Almost every test here binds a loopback listener. On a Windows machine running
endpoint security software, the first connection to a freshly built test binary
can stall for exactly the ten-second header timeout and then fail with `EOF` — a
different test each run, moving around, and most often one of the TLS ones. It
is the scanner touching each new binary's first socket rather than a race in the
code. Serialising the packages makes it much less frequent, though not
impossible:

```bash
go test ./... -p 1
```

If you see it, re-run before investigating. The same suite is green on all three
platforms in CI, where nothing is inspecting the sockets.

### Releasing

Tagging is the whole procedure:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

That runs the tests again (a tag can be pushed at a commit CI never saw), builds
both binaries for seven platforms, publishes a GitHub release with checksums and
a build-provenance attestation, and pushes multi-architecture container images
to `ghcr.io`. A tag containing a hyphen (`v0.3.0-rc1`) is marked as a
pre-release.

Every binary is stamped: `wispd -version` reports the release, the commit, and
the Go version. A build from a working tree says `dev` — nothing pretends to be
a release it is not.

To check a download is the build it claims to be:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

```bash
gh attestation verify wisp_v0.2.0_linux_amd64.tar.gz --repo willysnow/wisp
```

## Operating notes

- **Ports are unprivileged by default** so `wisp` starts without elevation.
  Redirect 22 → 2222 at the firewall, or map ports in Docker, to catch scans on
  the real ports.
- **Keep `hostkey.pem`.** A host key that changes every restart identifies the
  box as a honeypot to anyone who connects twice.
- **Never grant access.** Every credential is rejected, and the HTTP service
  always answers "invalid username or password" — never "no such user", which
  would let an attacker enumerate accounts.
- **This is a sensor, not a shield.** It detects; it does not block. Treat any
  alert as a real intrusion until proven otherwise — nothing legitimate has a
  reason to talk to it.

## Roadmap

Rough order. The parity work is unglamorous but it is what makes `wisp` usable
as anything other than a demo.

**Catching up to OpenCanary** (~6 weeks of focused work)

- [x] Easy protocols, first batch: TCP banner, telnet, FTP, TFTP, NTP, redis
- [x] Easy protocols, remainder: git, LLMNR, MongoDB, HTTPS
- [x] MySQL and MSSQL — both capture a credential that survives the connection:
      MySQL a native-password response that cracks offline (hashcat 11200), MSSQL
      the cleartext LOGIN7 password itself, since TDS only obfuscates it
- [x] VNC — real RFB handshake, not a banner catcher: offers only VNC
      Authentication so the client returns the DES challenge-response, captured
      as a John-the-Ripper `vnc` line that cracks offline
- [x] SIP and HTTP proxy — SIP answers OPTIONS to look like a live PBX and
      captures the REGISTER digest (hashcat 11400); the HTTP proxy records the
      CONNECT/absolute-form target and captures cleartext proxy credentials
- [ ] Medium protocols, remainder: SNMP
- [ ] Port-scan detection (OpenCanary drives iptables; a cross-platform version
      needs pcap instead)
- [ ] RDP — X.224 alone catches the connection; NLA is needed for credentials
- [x] Native SMB2/3 with NTLMSSP — no external Samba. Captures NetNTLMv2 hashes
      and the *account name* used, not just "someone touched the share"
- [x] Alerting parity: email, webhook, LINE, and alert dedup
- [x] Syslog output, from the sensor and from the console
- [x] HPFeeds sink

**Going past it**

- [x] Kubernetes API decoy
- [x] MCP server decoy
- [x] Slack / Teams / Discord / LINE notification sinks
- [x] Self-hosted console with alert dedup and notification fan-out
- [x] Per-sensor ingest tokens, enrollment, and revocation
- [x] Console UI authentication and event retention
- [x] Console search, pagination, CSV/JSON export, and sensor-silence alerting
- [x] kubelet, Docker socket, cloud IMDS, Elasticsearch, Jenkins and
      GitLab decoys
- [x] TLS termination in the console itself (self-signed, file, or ACME)
- [x] Sensor-side rate limiting with reported suppression
- [x] Event-log rotation, so the sensor's disk is not sized by whoever is
      scanning it
- [x] Device personas — one identity across every port, instead of each
      service inventing its own
- [ ] TCP/IP stack fingerprint shaping (defeating `nmap -O` needs nfqueue or
      eBPF; user-space Go cannot change TTL or window size)
- [ ] **Token service** — DNS/HTTP callback, Word docs, kubeconfig, MCP configs.
      Decoys only see an intruder who is already on your network; a token
      travels with the data and fires wherever it ends up. The two cover
      different halves of the problem and the console is the natural place to
      receive callbacks.

**Getting it deployable**

- [x] CI: format, vet, tests on three platforms, race detector, govulncheck,
      cross-compile, and container builds
- [x] Distroless container images and a compose stack
- [x] Release process: tagged cross-platform binaries, checksums, provenance
      attestation, and published container images
- [x] Sandboxed systemd units for the sensor and the console
- [x] CONTRIBUTING, SECURITY.md, issue templates

## Contributing

The most useful contribution is a protocol module — the gap between 18 and 21 is
what stops this being usable as anything other than a demo. The checklist, and
the constraints every change has to respect, are in
[CONTRIBUTING.md](CONTRIBUTING.md).

Security problems go through [private vulnerability reporting][security], never
a public issue: a public report on a detection tool tells the people it detects
where to look, while every deployment is still vulnerable.
[SECURITY.md](SECURITY.md) says what counts as one here — and what does not,
because "the honeypot can be fingerprinted" is a documented limitation rather
than a vulnerability.

[security]: https://github.com/willysnow/wisp/security/advisories/new

## Licence

BSD-3-Clause, matching OpenCanary — from which several protocol behaviours were
studied, though none of its code was copied. See `LICENSE` for the terms and
`NOTICE` for the attribution.
