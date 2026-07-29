# wisp — design notes

The [README](../README.md) says what wisp does and how to run it. This page is
the *why*: the reasoning behind every decoy and every protocol emulator — the
choices a connection log or a plain banner would get wrong. It is reference, not
required reading; the tables in the README stand on their own.

## The nine decoys OpenCanary does not have

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

**`rdp` reads the username off the first packet, then captures the hash.** Every
RDP session opens with an X.224 negotiation in the clear, before any TLS, and a
client volunteers the account it is about to try as a routing cookie —
`Cookie: mstshash=Administrator` — so the decoy has the targeted username before a
credential is sent, alongside the security the client offered. Then it goes for
the credential: it selects CredSSP (Network Level Authentication, the modern
default), terminates TLS, and runs the NTLM exchange inside it. That yields a
NetNTLMv2 response — the identical hashcat-5600 artifact the `smb` decoy captures,
over a different transport, and literally the same code: the NTLM challenge and
the NetNTLMv2 extraction live in `internal/ntlm`, which both decoys wrap. The one
DER the decoy builds is the CredSSP `TSRequest` that carries its challenge;
everything inbound is located by the NTLM signature, the way SMB reads SPNEGO.
Nothing is granted: the handshake stops at the AUTHENTICATE, before the
public-key exchange a real success continues with. What it does not open is the
legacy path — a client that speaks only standard RDP security or plain-TLS,
never CredSSP, is recorded at the negotiation but hands over no hash.

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

**`snmp` captures the community string and deliberately never answers.** In SNMP
v1 and v2c the community string is the credential — sent in the clear on every
request — so `onesixtyone` and `snmpwalk` spray it: `public`, `private`, the
vendor defaults. The decoy decodes each request with a small hand-written
BER/ASN.1 reader (the one dependency the other decoys did not already imply) and
records the community, the operation and the OIDs; a `SetRequest` is an attempt
to reconfigure the device, stated in the OIDs it would change. What it does *not*
do is reply. SNMP is the internet's favourite UDP amplification protocol — a
`GETBULK` response can dwarf its request — so an agent that answered could be
turned into a reflector aimed at a spoofed victim. The community arrives in the
request, so capturing it needs no reply; the decoy listens, records, and stays
silent, which is also what a firewalled agent looks like. `SECURITY.md` lists the
silence as a deliberate property, not a defect.

**`portscan` is not a decoy but a detector, and it captures nothing new — it
correlates.** wisp already binds two dozen ports; a host sweep lights up a whole
row of them, so instead of adding a packet sniffer, the detector watches the
events the decoys already emit and flags a source that touches many distinct
ports in a short window. It sits in the pipeline outside the rate limiter, so a
flood still feeds it, and it collapses a thousand-port sweep into one event
naming the services swept:

```
portscan  src_ip=10.0.0.9  ports=14  window=8s  method=connect
          services=ftp,mongodb,mysql,redis,smb,ssh,vnc
```

That baseline is cross-platform, zero-dependency and zero-privilege, and it is
honest about its blind spot: it sees only the ports wisp binds, and only scans
that complete a connection, so a stealth SYN/NULL/FIN scan to an unbound port is
invisible to it and its events say `method=connect`. On Linux, catching those is
the packet half: a pure-Go AF_PACKET sniffer (no cgo, no libpcap) reads probes to
closed ports, classifies the scan from the TCP flags, and feeds the same
correlation, so a mixed sweep is one event carrying both `services` (the open
ports it connected to) and `scan_types` (`syn,xmas,udp`, the closed ones it
probed). It needs `CAP_NET_RAW`; without it — or off Linux — it says so once and
the baseline carries on, so wisp never fails to start over it. The socket only
reads and never writes, which is the line that separates it from the TCP/IP
fingerprint spoofing wisp will not do: passive capture is fine, forging packets
is not.

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

## Tokens

The [README](../README.md#tokens) covers the token kinds and how to mint them.
The mechanics behind the two that do something clever, and the honest limits of
all of them, are here.

**The `docx` token is the one that leaves the network the sensors watch.** It
carries a *linked* — not embedded — image whose relationship is marked
`TargetMode="External"`, and Word resolves that target over the network when it
lays the page out. So the document can be carried off a share, mailed onward,
dropped in someone's personal cloud drive, and it still calls home from wherever
it is finally opened. Modern Office increasingly prompts before loading external
content, so this is not a certainty — but it is the classic technique and still
fires in many configurations.

**The `dns` token is the one that fires where HTTP cannot leave.** Its lure is a
hostname under a domain delegated to the console's own authoritative DNS server;
resolving it — from anywhere, through any recursive resolver — walks the query
out to the console, and the query itself is the callback. That is the same path
data exfiltration takes, so a segment locked down enough to stop the HTTP tokens
is usually still wide open to this one.

The DNS server is off by default: it is the one part of the console that wants a
privileged port and a domain delegated to it — the zone's `NS` records must point
at the console's host — so it runs only when both are set up. It is **not** an
amplifier: it answers a single A record the size of the question and never
recurses, and the address it hands back is a black hole whose only job is to let
the lookup that carried the id complete. Serving it fails soft — if port 53 is
already taken the console logs it and everything else keeps working, rather than
refusing to start.

Three honest limits:

- **A token id is not a secret.** It travels inside the planted data, so anyone
  who reads the lure can read the id; it is random only so it is unguessable and
  unique. What it protects is the correlation — which lure, planted where, was
  touched — not a credential. This is why the whole token record can be read back
  in the UI and the CLI, unlike a sensor token of which only the hash is kept.
- **A callback shows the resolver, not always the person.** A DNS token records
  the recursive resolver that walked the query out — often the organisation's own
  — not the end client, which DNS hides. An HTTP token records the fetching client
  directly.
- **Tokens catch use, not possession.** A lure that is copied but never opened is
  silent, and that is correct: the signal is someone *acting* on stolen data,
  which is the moment worth an alert.

## The TCP banner catcher

The generic banner catcher covers any port that has no real emulator: it records
the first bytes a client sends — enough to see a scan or a probe — but it cannot
capture credentials the way a protocol emulator does. It ships pointed at
memcached by default, a commonly-probed service with no native emulator here.

## TLS pinning

A sensor that pins the console's certificate refuses to deliver to anything that
presents a different one — which is a real failure mode, not a hypothetical. On
a machine running Norton's Web Shield, a pinned sensor correctly refused to talk
to a console on the same host, because what it was handed was Norton's
certificate and not the console's. That is the pin working, not a bug: the whole
point is that captured credentials go only to the console you configured, so
`insecure_skip_verify` is a lab setting and nothing more.
