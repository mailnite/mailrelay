# mailrelay

A stateless reverse relay that lets a **mailnite** server behind NAT (a home lab,
a laptop, any machine with no public IP) serve real mail and web on the public
internet — using only a cheap VDS that has a public IP and nothing else.

The relay **stores no mail and holds no user data.** It binds the public ports
(25, 465, 587, 143, 993, 995, 80, 443) on the VDS and forwards their raw bytes to
your mailnite instance over a single, mutually-authenticated
[value-rpc](https://go.arpabet.com/value-rpc) connection **that mailnite dials
outbound** — so your NAT/firewall never needs an inbound hole.

```
   public internet                         your LAN / behind NAT
  ┌──────────-─────┐    outbound, mutual-TLS   ┌──────────────────┐
  │    mailrelay   │◀───── value-rpc ─────-────│     mailnite     │
  │  (public VDS)  │   (mailnite dials out)    │  (no public IP)  │
  │                │                           │                  │
  │ binds :25 :443 │   raw bytes both ways     │ Serve(listener)  │
  │  :465 :587 …   │══════════════════════════▶│  as if local     │
  └───────▲────────┘                           └──────────────────┘
          │ SMTP/IMAP/HTTPS
      the world
```

## Why this exists

Standing up mail is the hardest part of self-hosting: you need a static public
IP, the ability to bind port 25 and friends, reverse DNS, and open inbound ports.
Most home/lab machines have none of these. mailrelay reduces the requirement to
**one VDS with a public IP and an SSH login** — the relay is disposable and
storage-free, so the sensitive parts (mail, keys, search index) stay on your
hardware.

## How it works

- **mailnite is the value-rpc client; the relay is the server.** mailnite dials
  out, so NAT is a non-issue. The relay listens on exactly one control port.
- **Three RPCs** carry everything (see [`protocol`](protocol/protocol.go)): a
  `session` chat (open the public ports; stream back one event per inbound
  connection), a `conn` chat per tunneled connection (raw bytes both ways), and a
  `ping`.
- **The reverse `net.Listener`.** On the mailnite side,
  [`relayclient`](relayclient/client.go) turns each bound public port into an
  ordinary `net.Listener`. mailnite's mail/web servers call `Serve(listener)`
  exactly as they would for a local `net.Listen` — they never know the socket is
  a thousand miles away.
- **Mutual TLS.** A private CA (created on the mailnite side) signs one relay
  server cert and one mailnite client cert; each end trusts only that CA. See
  [`pki`](pki/pki.go).
- **One relay, many clients.** Each connecting client gets its own independent
  set of public listeners, so several instances can share a single relay — one
  binding `:25`, another `:110`, and so on. Public ports are first-come,
  first-served; a per-connection capability secret (only ever sent to the owning
  client) keeps one client from attaching to another's tunneled connections.

## The whole shape in one picture

mailrelay is one half of a deliberate split between **infrastructure** (which
stays private) and the **public surface** (which is all a relay ever exposes):

```
  INTERNAL — loopback :8480, never exposed, never relayed     PUBLIC — direct, or via mailrelay
  ┌────────────────────────────────────────────────┐        ┌────────────────────────────────────┐
  │ Internal admin console                           │        │ Webmail HTTPS  (SPA + /api/*:        │
  │  • late-stage onboarding (relay, TLS, ports)     │        │    user + webmail-admin + mobile API │
  │  • infra admin: TLS · Storage · DNS · Queue/logs │        │    — never /api/admin infra routes)  │
  │    · Mail-server ports · Backup · Relay          │        │ SMTP 25 · submission 587 · SMTPS 465 │
  │  • value-rpc admin control plane (loopback)      │        │ IMAP/STARTTLS 143 · IMAPS 993        │
  └────────────────────────────────────────────────┘        └────────────────────────────────────┘
        configured locally, replaces the relay                    bound directly, or by the relay
```

- **Onboarding is two-tier.** First run (database-free) defines only storage +
  limits + the admin account, then restarts. Everything public — the relay, TLS,
  which ports — is configured afterwards on the **internal admin console** at
  `127.0.0.1:8480`, which is also where you later replace or reconfigure the relay.
- **Infra never leaves the box.** The internal console and the value-rpc control
  plane bind loopback and are absent from the relay's allow-list, so no `relay.*`
  setting can push them onto the internet.
- **A single seam picks direct vs. relay.** In mailnite a `ListenerFactory` hands
  each public server its `net.Listener` — a local bind, or the relay's reverse
  tunnel — so the servers `Serve(listener)` unchanged and only relay-exposable
  services (SMTP/submission/IMAP/POP3, and the public web server) can route
  through it.

## Transports

Selectable at runtime (`--transport`) — the name is the **carrier** the tunnel
rides; all three run under TLS (`tls` is accepted as a legacy alias of `tcp`):

| Transport | Auth | When |
|-----------|------|------|
| `tcp` (default) | **mutual TLS** (private CA client cert), or self-signed cert + **token** (key-authenticated mode) | the robust default for a direct VDS |
| `quic` | **mutual TLS** over QUIC (TLS 1.3, connection migration) | lossy/mobile networks |
| `ws` (wss) | server-cert TLS + **handshake token** | riding 443 behind a CDN / L7 proxy |

`ws` uses a token rather than a client certificate because the WebSocket client
dials with the system trust store; give the relay a publicly-trusted cert (e.g.
Let's Encrypt for a real domain) for that mode.

## Quick start

The one-command way — on the VDS, with the key from the mailnite admin console
(Mail relay → step 1):

```bash
curl -fsSL https://get.mailnite.com/relay | sudo bash -s -- --token <KEY>
```

That downloads the right binary, verifies its sha256 against the channel
manifest, installs a hardened systemd service that may bind ports below 1024
(via `AmbientCapabilities`, which — unlike `setcap` — survives binary updates),
starts it in key-authenticated mode, and enables a daily self-update timer.
It ends by printing the relay address to paste back into the console.

Updates land on their own via that daily timer, but to pull the latest release
now — on the VDS:

```bash
# re-run the installer in update mode (upgrades only if the channel moved,
# keeping the existing key/transport/bind), then restarts the service:
curl -fsSL https://get.mailnite.com/relay | sudo bash -s -- --update

# …or trigger the built-in updater immediately without re-fetching the script:
sudo systemctl start mailrelay-update.service
```

The same installer also pins versions (`--version vX.Y.Z`) and uninstalls
(`--uninstall`); see [install.sh](install.sh).

Prefer to drive it from your workstation over SSH, with mutual TLS instead of
the shared key? From this repo:

```bash
# 1. build the relay for the VDS
GOOS=linux GOARCH=amd64 go build -o mailrelay ./

# 2. create the tunnel CA and issue certs (--hosts = how mailnite reaches the relay)
./mailrelay gen-ca    --out ./relay-pki
./mailrelay gen-certs --hosts relay.example.com --out ./relay-pki

# 3. deploy to the VDS over SSH and start it (installs a systemd unit)
./mailrelay deploy \
  --host relay.example.com --user root --binary ./mailrelay --privileged \
  --transport tcp --bind 0.0.0.0:8443 \
  --ca ./relay-pki/ca.crt --cert ./relay-pki/relay.crt --key ./relay-pki/relay.key
```

`--privileged` grants the binary `CAP_NET_BIND_SERVICE` (via `setcap`) so it can
bind 25/443 without running as root; add `--sysctl` to flip
`net.ipv4.ip_unprivileged_port_start=0` instead. The mailnite side then dials the
relay with the `ca.crt` + `mailnite-client.crt` + `mailnite-client.key` bundle
(this is what the onboarding wizard's "No public IP" path automates).

## Commands

```
mailrelay serve        run the relay on the VDS
mailrelay gen-ca       generate the tunnel certificate authority
mailrelay gen-certs    issue relay + mailnite certs and a handshake token
mailrelay gen-ssh-key  generate the SSH keypair used to deploy
mailrelay deploy       ship the relay to a VDS over SSH and start it
```

`deploy` authenticates to the VDS by **public key** by preference: it tries an
explicit `--ssh-key` (passphrase-protected keys are supported via
`--ssh-key-passphrase`), then a running **ssh-agent** (`SSH_AUTH_SOCK`), then
the default `~/.ssh/id_ed25519` / `id_ecdsa` / `id_rsa` — so `mailrelay deploy
--host relay.example.com` just works with your existing key setup, no password.
`--password` remains as a fallback (and supplies `sudo` when `--user` isn't
root); `--no-agent` / `--no-default-keys` narrow the search when you need to.

See [DESIGN.md](DESIGN.md) for the architecture, the security model, and how the
`relayclient` listener drops into mailnite's existing server factories.

## Security notes

- The relay is a byte pump: it never terminates application TLS and never sees
  plaintext mail. STARTTLS/implicit-TLS on the mail ports is between the remote
  peer and mailnite, end to end through the tunnel.
- Guard `ca.key` — it is the trust root for the whole tunnel. `gen-*` write keys
  `0600`.
- SSH host keys are trust-on-first-use by default (the fingerprint is printed);
  pass `--host-key` to pin.

## Contributing

Issues and pull requests are welcome. Please keep changes `gofmt`-clean and run
the tests before submitting:

```bash
go build ./...
go test ./... -race
```

By contributing you agree that your contributions are licensed under the
project's Apache-2.0 license.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Copyright
2022-present Karagatan LLC. It builds on the arpabet libraries (value-rpc,
servion, cligo) under their own licenses; see [NOTICE](NOTICE).
