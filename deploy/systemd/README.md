# systemd units

Two units, meant to run on different machines: the sensor belongs on a segment
you expect to be attacked, and the console does not.

Both are sandboxed hard — no capabilities, nothing writable but their own state
directory, a seccomp filter, and no path back to root. The sensor parses hostile
input by design, and a unit file should not depend on the code being correct.

They use `ProtectProc=` and `ProcSubset=`, so they need **systemd 247 or
newer** (Debian 11, RHEL 9, Ubuntu 22.04 and up). On anything older, delete
those two lines; everything else has been available since systemd 240.

## Sensor

```bash
sudo install -m 0755 wispd /usr/local/bin/wispd
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wisp
sudo install -m 0644 wispd.service /etc/systemd/system/wispd.service
```

`ConfigurationDirectory` and `StateDirectory` create `/etc/wisp` and
`/var/lib/wisp` with the right ownership on first start, so there is no `chown`
step:

```bash
sudo systemctl enable --now wispd
```

Drop a config in afterwards if you want more than the defaults — the sensor
runs on defaults with no file at all:

```bash
sudo install -m 0640 -o root -g wisp wisp.example.yaml /etc/wisp/wisp.yaml
sudo systemctl restart wispd
```

**Keep `/var/lib/wisp`.** It holds the SSH host key and the decoy TLS
certificates. Material that changes on every restart identifies the box as a
honeypot to anyone who connects twice.

Ports stay unprivileged so the service needs no capabilities. To catch scans on
the real ports, redirect at the firewall rather than granting
`CAP_NET_BIND_SERVICE`:

```bash
sudo nft add rule inet nat prerouting tcp dport 22 redirect to :2222
```

The IMDS decoy needs one extra step, because 169.254.169.254 is a link-local
address that has to exist on the host before anything can bind traffic for it:

```bash
sudo ip addr add 169.254.169.254/32 dev lo
```

```bash
sudo nft add rule inet nat prerouting ip daddr 169.254.169.254 tcp dport 80 redirect to :8169
```

**Do not do that on a machine that is itself a cloud instance.** You would
shadow the real metadata service, and every process on the box that needs role
credentials would start receiving fabricated ones. Without these two commands
the decoy still runs on `:8169` and still records anything that finds it; it
just will not catch the tooling that only ever asks 169.254.169.254.

## Console

```bash
sudo install -m 0755 wisp-console /usr/local/bin/wisp-console
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wisp-console
sudo install -m 0644 wisp-console.service /etc/systemd/system/wisp-console.service
sudo install -m 0640 -o root -g wisp-console console.example.yaml /etc/wisp-console/console.yaml
sudo systemctl enable --now wisp-console
```

The first start creates an operator account and prints its password exactly
once, so read the log before doing anything else:

```bash
sudo journalctl -u wisp-console --since "5 minutes ago"
```

Then enrol each sensor. Run these as the console's own user, or the files they
touch end up owned by root:

```bash
sudo -u wisp-console wisp-console sensor add sensor-01 -db /var/lib/wisp-console/wisp-console.db
```

To serve TLS on 443 directly — which ACME needs — uncomment the two
`CAP_NET_BIND_SERVICE` lines in the unit. Everything else stays as it is.

### DNS tokens

The DNS token server (`tokens.dns` in the config) is off unless you enable it,
and when on it wants port 53. That is privileged, so either grant the bind
capability — the same two `CAP_NET_BIND_SERVICE` lines as above cover both 443
and 53 — or listen high and redirect:

```yaml
tokens:
  dns:
    enabled: true
    zone: tokens.example.com
    addr: ":5353"
```

```bash
sudo nft add rule inet nat prerouting udp dport 53 redirect to :5353
sudo nft add rule inet nat prerouting tcp dport 53 redirect to :5353
```

Either way the zone's `NS` records must delegate `tokens.example.com` to this
host, or a lookup never arrives. The server only reads and answers a single A
record the size of the query, so it is not an amplifier — but it is the one part
of the console that puts it on the public DNS, so it stays opt-in.

## Checking the sandbox

```bash
systemd-analyze security wispd.service
```

Both units should score in systemd's "OK" band or better. If a change to a unit
makes that number worse, that is the review comment.
