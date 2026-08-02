# Reproducing the demo

A walkthrough of the console demo: one sensor is scanned and probed for
credentials while the console captures every attempt in real time. Run it
yourself in a few minutes.

## Topology

Two machines on one network — in VMware, set **both** to Bridged (or both to
Host-only) so they can reach each other by IP:

| Role | Host | Runs |
|---|---|---|
| Sensor + console | a headless Linux VM, here named `nas-backup-01` | `wispd` and `wisp-console` |
| Attacker + viewer | your workstation (e.g. Kali) | the attack commands and a browser |

The sensor and console share one VM here — the "evaluation stack" — to keep the
demo to two machines. In a real deployment the console lives elsewhere; see the
[Console](../README.md#console) section. The whole recording happens on the
attacker: the VM is never on screen, it is just an IP you attack and a URL you
watch.

## 1. Arm the sensor (on the VM)

Copy the `wispd` and `wisp-console` binaries onto the VM. In one terminal, start
the console — **first**, because the token the sensor needs is minted here:

```bash
./wisp-console -addr :8001
```

It prints a one-time operator password on first start; note it, that is the UI
login. In a second terminal, enrol the sensor to get its token, then start it:

```bash
./wisp-console sensor add nas-backup-01
```

```bash
export WISP_TOKEN='<token from sensor add>' WISP_REMOTE_URL='http://127.0.0.1:8001'
./wispd
```

That is the whole sensor setup — no config file. `wispd` runs every decoy on its
default (unprivileged) ports and delivers to the console over loopback. Leave
both terminals running and switch to the attacker.

> To make the box look like one product — a Synology NAS, say — add a `wisp.yaml`
> with `device.persona: synology`. It is not needed for the demo; see the
> [README](../README.md#console).

## 2. Attack it (on your workstation — this is what you record)

Find the VM's address (`hostname -I` on the VM), open the console in a browser,
and log in as `admin`:

```
http://<sensor-ip>:8001/?live=3
```

`?live=3` reloads the page every 3 seconds using a plain `<meta refresh>` (no
JavaScript), so events appear as you go — no need to refresh by hand. A green
`live` marker in the header shows it is on.

Now run the attacks one at a time, glancing at the console after each.

**Scan** — trips the port-scan detector and logs one connection per port. Use
`-sT`, a full TCP connect scan: nmap's default as root is a SYN scan, which never
completes the handshake, so the application-level decoys see nothing.

```bash
nmap -sT -Pn <sensor-ip> -p 2121,2222,2323,6379,8080,8443
```

**SSH** — captures the username and password. This is the highlight; open the
event's detail page afterwards to show the captured value in full.

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no admin@<sensor-ip>
```

Type any password at the prompt (for example `Summer2026!`). The login "fails",
but the console shows a `login_password` event with exactly what you typed.

**Telnet** — captures the username and password:

```bash
(echo admin; sleep 1; echo hunter2; sleep 1) | nc <sensor-ip> 2323
```

**Redis** — captures the AUTH password and the command sequence:

```bash
redis-cli -p 6379 -a 'S3cr3t!' --no-auth-warning KEYS '*'
```

**HTTP** — captures admin-panel credentials:

```bash
curl -s -u admin:hunter2 http://<sensor-ip>:8080/admin -o /dev/null -w 'HTTP %{http_code}\n'
```

Finish by clicking any credential event in the console to open its detail page —
every captured field on one screen.

## 3. Tear down (on the VM)

Stop the console and sensor with `Ctrl+C` in both terminals; if the VM existed
only for this, power it off.

## Troubleshooting

- **The scan captures nothing.** You ran a SYN scan (nmap's default as root). Use
  `-sT` so the connections actually complete — the decoys are application-level
  and only log established connections.
- **No events at all.** Check the sensor's `WISP_REMOTE_URL` (`http://127.0.0.1:8001`
  on the shared VM) and that the token was pasted correctly. Posting a test event
  to the console's `/api/v1/events` with the bearer token isolates console from
  sensor.
- **The browser or the ports are unreachable.** Both machines must be on the same
  VMware network (both Bridged, or both Host-only); confirm with `ping <sensor-ip>`.
  If ping works but the ports do not, check the VM's firewall (`sudo ufw status`).
- **A clean slate for a re-take.** The console UI is read-only by design — there is
  no delete button, so an attacker who gets a session cannot erase evidence. For an
  empty database, stop the console and `rm -f wisp-console.db wisp-console.db-*`,
  then re-enrol the sensor.
