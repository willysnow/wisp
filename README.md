# wisp

A single-binary network honeypot sensor. Deploy it on an internal segment, wait
for something to touch it, and get an alert with the credentials, the prompt,
the query, the container spec, or the paths the intruder tried.

> **Status: pre-1.0.** `wisp` covers all 21 of OpenCanary's protocol modules,
> plus 9 decoys and a honeytoken service it has none of — the coverage is
> complete, but it is younger and less battle-tested. See
> [Honest comparison](#honest-comparison) first.

The design rationale behind every decoy, emulator and token — the *why* — lives
in **[docs/design.md](docs/design.md)**, so this page can stay about what wisp
does and how to run it.

## Demo

A sensor gets scanned and probed for credentials while the console captures every
attempt in real time. **[▶ Watch the demo](docs/wisp-demo.mp4)** — or reproduce it
step by step with **[docs/demo.md](docs/demo.md)**.

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

OpenCanary ships 21 protocol modules. `wisp` has reimplemented **all 21** of them,
plus 9 decoys OpenCanary does not have.

| | OpenCanary | wisp today |
|---|---|---|
| Protocol modules | 21 | **21** + 9 new decoys |
| Still missing | — | none — all 21 |
| SMB | yes, via external Samba | **native** — no Samba, captures NetNTLMv2 |
| Cloud / container / CI / LLM decoys | no | **yes** (`k8s`, `kubelet`, `docker`, `imds`, `elasticsearch`, `jenkins`, `gitlab`, `ollama`, `mcp`) |
| Alerting | file, syslog, HPFeeds, email, webhook, + separate dedup daemon | JSONL, syslog, HPFeeds, email, LINE, webhook (Slack/Teams/Discord), **dedup built in** |
| Fleet console | none | **included, self-hosted** |
| Honeytokens | no — Canarytokens is a separate hosted service | **DNS, HTTP, Word doc, kubeconfig, MCP — self-hosted** |
| Install | Python + Twisted + Scapy (+ Samba for SMB) | one static binary |
| Platforms | Linux-first, root for several modules | anywhere Go cross-compiles |

The `banner` and `portscan` rows are the two that are not full emulators — a
connection-level catch-all, and a scan detector that correlates the events the
other decoys emit (plus a Linux packet sniffer for stealth scans). How each works
is in [docs/design.md](docs/design.md).

OpenCanary is still the more battle-tested of the two. Reach for `wisp` when the
Python/Samba/Scapy dependency chain is what stops you deploying a honeypot at
all, or when you want the cloud, container and LLM decoys it has none of.

## What it emulates today

| Service | Default port | What it captures |
|---|---|---|
| `ssh` | 2222/tcp | usernames, passwords, key fingerprints, client version |
| `http` | 8080/tcp | admin-panel credentials, probed paths, user agents |
| `https` | 8443/tcp | the same, plus the **SNI** |
| `telnet` | 2323/tcp | usernames and passwords |
| `ftp` | 2121/tcp | usernames, passwords, post-login intent |
| `redis` | 6379/tcp | AUTH credentials **and the full command sequence** |
| `tftp` | 6969/udp | the filename, and read vs write |
| `ntp` | 1123/udp | client requests, and **`monlist` amplification recon** |
| `git` | 9418/tcp | the **repository path**, and push vs fetch |
| `mongodb` | 27017/tcp | **SCRAM proofs that crack offline**, driver and app name |
| `mysql` | 3306/tcp | **native-password responses** — hashcat 11200 |
| `mssql` | 1433/tcp | the **cleartext password** — TDS obfuscation is reversible |
| `smb` | 445/tcp | **NetNTLMv2 hashes** and the account — hashcat 5600, no Samba |
| `vnc` | 5900/tcp | the **VNC-auth challenge-response** — cracks offline |
| `rdp` | 3389/tcp | **NetNTLMv2** via CredSSP/NLA — hashcat 5600 — plus the `mstshash` user |
| `sip` | 5060/udp | the **REGISTER digest** — hashcat 11400 |
| `http-proxy` | 3128/tcp | the **tunnel target** (SSRF intent) and cleartext creds |
| `snmp` | 161/udp | the **community string** and OIDs — never answers |
| `llmnr` | outbound | **a poisoner on the segment**, and the address it claims |
| banner | any | first bytes sent, for ports with no emulator |
| `portscan` | correlation | **a source sweeping the ports** — stealth types on Linux |
| `ollama` | 11434/tcp | model-list recon, and **the prompts sent to your "GPU"** |
| `k8s` | 6443/tls | **stolen service-account tokens**, client certs |
| `kubelet` | 10250/tls | **the command run inside a pod**, and the token |
| `docker` | 2375/tcp | **the container spec** — host mount, `Privileged`, command |
| `imds` | 169.254.169.254 | **cloud role-credential theft** (AWS/GCP/Azure) |
| `elasticsearch` | 9200/tcp | **the search query** — the fields and the row count |
| `jenkins` | 8081/tcp | **the Groovy script**, and login attempts |
| `gitlab` | 8929/tcp | **stolen `glpat-` tokens**, and their target |
| `mcp` | 8931/tcp | **the agent, and the tool calls it made** |

The last nine — `ollama` through `mcp` — are the cloud, container, CI and LLM
decoys OpenCanary has none of. **Why each service captures and answers the way it
does** is in [docs/design.md](docs/design.md).

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

Build the sensor and run it — no config needed, it runs on defaults:

```bash
go build -o wispd ./cmd/wispd
./wispd
```

Trip it:

```bash
curl -s localhost:11434/api/generate -d '{"model":"llama3.2","prompt":"cat /etc/shadow","stream":false}'
```

and the prompt is captured to `events.jsonl`:

```json
{"service":"ollama","kind":"prompt","src_ip":"::1","dst_port":11434,"data":{"model":"llama3.2","prompt":"cat /etc/shadow"}}
```

Every service in the [table above](#what-it-emulates-today) is tripped the same
way — point a client at its port. To customise ports, personas, or output:

```bash
cp wisp.example.yaml wisp.yaml
./wispd -config wisp.yaml
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
go build -o wispd ./cmd/wispd
```

**Start the console first** — the token a sensor needs is minted here:

```bash
./wisp-console -addr :8001
```

It prints a one-time operator password on first start (the UI login — see
[Signing in](#signing-in)). In another terminal, enrol the sensor to get its
token:

```bash
./wisp-console sensor add sensor-01
```

Then point the sensor at the console and start it. The token and URL go in the
environment, so there is **no config file to write**:

```bash
export WISP_TOKEN='wisp__...' WISP_REMOTE_URL='http://127.0.0.1:8001'
./wispd
```

That is the whole setup. `wispd` with no config runs every decoy on its defaults
and delivers to the console; open `http://127.0.0.1:8001` in a browser to watch
the events arrive.

To control what the box pretends to be — a persona so every port tells one story,
or which decoys run — keep a `wisp.yaml` beside the binary. `wispd` reads it
automatically, so the command stays `./wispd`; pass `-config <path>` only for a
file somewhere else:

```yaml
device:
  persona: synology            # ssh/http/https/ftp/telnet all answer as Synology
services:
  docker: { enabled: false }   # turn off what this box would not run
```

`token` and `url` can stay out of that file — left empty, they fall back to
`WISP_TOKEN` and `WISP_REMOTE_URL`. That is what lets one `wisp.yaml` ship to a
whole fleet in version control while each host supplies its own secret out of
band, through a systemd `EnvironmentFile` or a container's environment:

```bash
printf 'WISP_TOKEN=%s\n' 'wisp__...' | sudo tee /etc/wisp/wisp.env >/dev/null && sudo chmod 600 /etc/wisp/wisp.env && sudo systemctl restart wispd
```

```bash
echo "WISP_TOKEN=wisp__..." >> .env
```

(The two lines are the systemd unit's `EnvironmentFile` and a `.env` beside
`docker-compose.yml` — `.gitignore` both.)

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

In the console, credential events (`login_password`, `auth_attempt`, …) stand
out in red. Click any event to open its full detail — every captured field on
one page — and narrow the timeline with the search box or the sensor and
service side panels. Add `?live` to the URL and the page auto-refreshes (a plain
`<meta refresh>`, no JavaScript) — handy for a wall display.

To reproduce the walkthrough end to end — one sensor, an attacker, the console
lighting up in real time — see **[docs/demo.md](docs/demo.md)**.

### Signing in

The UI is behind a login, and there is no setting that turns that off. Locking
ingest behind a token while leaving the dashboard open would protect nothing —
the dashboard is where every captured password, prompt, and stolen token ends
up.

On its first start the console creates one operator account and prints the
password once:

```
========================================================================
  CONSOLE OPERATOR CREATED — this password is shown once. Save it now.

      username:  admin
      password:  pSymBGpoDhZdiRZUMVyEeUjt

  Change it later with:  wisp-console user passwd admin
========================================================================
```

Miss it, or lose it later? It cannot be re-printed — only the hash is stored —
but resetting is one command that generates a fresh password and prints it on
the spot. It is safe to run while the console is up: the database is WAL-mode
with a busy timeout, so the CLI and the server share it without either stopping.

```bash
./wisp-console user passwd admin
```

To set the password yourself instead of taking the generated one, pass
`-password-stdin` (minimum 12 characters):

```bash
printf '%s\n' 'your-strong-password' | ./wisp-console user passwd admin -password-stdin
```

Add more operators, or list them, the same way — `user add` also prints a
generated password once and accepts `-password-stdin`:

```bash
./wisp-console user add alice
```

```bash
./wisp-console user list
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

A sensor with a pin refuses to deliver to anything else — including a TLS proxy
that re-signs the connection, which is a real failure mode and not a hypothetical
one ([docs/design.md](docs/design.md#tls-pinning) has the story).
`insecure_skip_verify` exists, is documented as a lab setting, and sends every
captured credential to whoever answers the connection.

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

## Tokens

A decoy waits on the network for an intruder who is already inside to touch it.
A **token** is the other half: a lure planted *inside data* — a document, a
kubeconfig, an MCP server entry — that does nothing until someone opens or uses
it, then calls home from wherever the data ended up. A firing lands in the same
console, timeline, search, export and notifications as every decoy capture — a
`token_triggered` event like any other. (It is the idea Thinkst's Canarytokens
popularised; OpenCanary has no token component. wisp's are self-hosted.)

Mint one from the console CLI:

```bash
./wisp-console token add -kind docx -memo "finance share"
```

`token add` has to know the console's own address — it is what the planted token
calls home to — so it fails until one is set. Either put `tokens.base_url` in
`console.yaml`, or pass it on the command:

```bash
./wisp-console token add -kind docx -memo "finance share" -url https://console.example.com
```

Use whatever address the planted data will call home from: `http://127.0.0.1:8001`
while you are testing on the console's own box, but a name the intruder's machine
can actually resolve for a token you really plant. A token pointing at
`127.0.0.1` never fires once it leaves this host.

`-memo` rides on every alert the token raises, so "which lure fired" needs no
lookup. `token list` shows every token and its firings; `token show <id>`
re-prints an artifact; `token disable <id>` stops recording new hits.

Five kinds, by what each is planted as:

| Kind | Planted as | Fires when |
|---|---|---|
| `http` | a URL | it is fetched — a bookmarked admin link, a wiki page, an `<img>` |
| `dns` | a hostname | it is resolved — a config value, an allowlist, a host entry |
| `docx` | a Word document | it is opened; Word fetches the document's linked image |
| `kubeconfig` | a kubeconfig file | kubectl is first pointed at it |
| `mcp` | an MCP client config | an agent loads it and connects |

Everything but the DNS token rides an HTTP request to `/t/<id>`, so set
`tokens.base_url` to an address the intruder's machine can reach. The DNS token
reaches the console even where outbound HTTP is blocked, via an authoritative
server for a zone you delegate to the console:

```yaml
tokens:
  base_url: "https://console.example.com"   # where HTTP callbacks land
  dns:
    enabled: true                            # off by default; wants port 53 + NS delegation
    zone: "tokens.example.com"
    addr: ":53"
    answer: "127.0.0.1"                      # a black hole; only satisfies the resolver
```

**Test one before you plant it.** The `http` kind is the easiest to trigger by
hand: mint it, then fetch the URL it prints, the way an intruder's tool would.

```bash
./wisp-console token add -kind http -url http://127.0.0.1:8001 -memo "test"
```

```bash
curl http://127.0.0.1:8001/t/<id>          # the URL the command above printed
```

The fetch lands as a `token_triggered` event in the timeline and on the tokens
page, exactly like a decoy capture — `/t/` is public by design, since the whole
point is that an intruder trips it. A `docx` token fires the same way when Word
opens it; a `dns` token when its hostname is resolved
(`dig <id>.tokens.example.com`).

How the `docx` and `dns` tokens actually fire, why a token id is not a secret,
and what a callback can and cannot tell you are in
[docs/design.md](docs/design.md#tokens).

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
cmd/wisp-console/       console server, sensor/user/token CLI, healthcheck
internal/config/        sensor YAML config with defaults-first loading
internal/event/         the one event type every service emits
internal/ntlm/          NTLMSSP challenge + NetNTLMv2 capture, shared by smb + rdp
internal/persona/       the device this sensor claims to be, on every port
internal/sink/          console + JSONL output with rotation, remote delivery,
                        hpfeeds, rate limiting
internal/portscan/      scan detection: fan-out correlation everywhere, plus a
                        Linux AF_PACKET sniffer for stealth scans (build-tagged)
internal/tlsutil/       decoy certificates, and how a sensor trusts a console
internal/token/         honeytoken artifacts: URL, DNS name, Word doc, kubeconfig,
                        MCP config — rendered from a token id and the console's address
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
  rdpsvc/               RDP negotiation + CredSSP/NLA NetNTLMv2 capture over TLS
  sipsvc/               SIP over UDP, REGISTER digest capture (hashcat 11400)
  proxysvc/             HTTP forward proxy: tunnel target and cleartext creds
  snmpsvc/              SNMP over UDP, community-string capture (hand-rolled BER)
  llmnrsvc/             LLMNR poisoning detection (not a decoy)
  ollamasvc/            fake Ollama inference server
  k8ssvc/               Kubernetes apiserver, and the tokens aimed at it
  kubeletsvc/           kubelet: pod inventory and in-pod command capture
  dockersvc/            Docker Engine API and container-escape specs
  imdssvc/              cloud instance metadata, AWS + GCP + Azure
  elasticsvc/           open Elasticsearch and the queries run against it
  jenkinssvc/           Jenkins, including the Groovy script console
  gitlabsvc/            GitLab, and stolen glpat- access tokens
internal/console/       UI, auth, retention, TLS termination, token callbacks
                        (HTTP + an authoritative DNS server for DNS tokens)
  store/                SQLite: events, sensors, operators, sessions, tokens
  notify/               email, LINE, webhooks, and alert dedup
```

Adding a protocol means one package implementing `service.Service` and one line
in `buildServices`.

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

## Contributing

Protocol coverage is complete, so the most useful contributions now are the ones
that make it battle-tested: real-world hardening, a new decoy for the 2026 attack
surface, or an improvement to a capture's fidelity. The checklist, and the
constraints every change has to respect, are in [CONTRIBUTING.md](CONTRIBUTING.md).

Security problems go through [private vulnerability reporting][security], never
a public issue: a public report on a detection tool tells the people it detects
where to look, while every deployment is still vulnerable.
[SECURITY.md](SECURITY.md) says what counts as one here — and what does not,
because "the honeypot can be fingerprinted" is a documented limitation rather
than a vulnerability.

[security]: https://github.com/willysnow/wisp/security/advisories/new

> The name is the will-o'-the-wisp: a light in the dark that leads you off the
> path. It is deliberately **not** Canary-anything — "Canary" and "Canarytokens"
> are Thinkst trademarks, and this project is an independent reimplementation
> rather than a fork or a successor.

## Licence

BSD-3-Clause, matching OpenCanary — from which several protocol behaviours were
studied, though none of its code was copied. See `LICENSE` for the terms and
`NOTICE` for the attribution.
