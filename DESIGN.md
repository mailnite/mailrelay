# Simplifying mailnite installation — design & proposal

Date: 2026-07-09.

This document proposes how to fix the two rough edges in mailnite's onboarding
and introduces **mailrelay**, the piece that makes the hardest install case —
"no public IP" — actually work. It covers what is built now and the concrete next
step to finish the integration.

---

## 1. The two onboarding problems

### 1.1 The "Offload attachments to S3" dead end

In *Storage limits*, ticking the offload checkbox showed only:

> *Set the S3 endpoint, bucket and credentials in the config (`blob.s3.*`);
> offload runs on the sweep schedule.*

That is a dead end: it names config keys the operator can't set from here, during
a phase whose whole point is to avoid hand-editing config. And it's misleading —
enabling offload without an endpoint does nothing (`blob_factory.go` runs
local-only when `blob.s3.endpoint` is empty; `api_handler.go` only reports offload
active when both the flag *and* an endpoint are set).

**Fix (done).** There is already a full **Admin → Storage** page
(`storageSettingsGet`/`storageSettingsSet` in `pkg/web/api_handler.go`) that
configures the S3 endpoint, bucket, region and credentials after install. The
onboarding hint now points there and states the real behaviour: attachments stay
on local disk until an object store is configured, and leaving the box ticked
just means offload begins automatically once it is. Nothing else is required at
install time — which matches your "set it up later in the admin console" steer
without removing the intent flag.

### 1.2 "Listening ports" assumed a public-facing deployment

The step asked for HTTP/HTTPS binds and *required the ports to bind locally
before continuing*. That is correct behind a proxy or on a VDS, but nonsensical
on a laptop or home-lab box with no public IP: binding `:443` locally does not
make mail reachable, and port 25 outbound is usually blocked by the ISP anyway.

**Fix (done).** The step is now **"Access"** and starts by asking *how mail
reaches this server*, with three models:

| Model | What it means | What onboarding does |
|-------|---------------|----------------------|
| **Direct** | public IP, faces the internet | bind the real ports here; run the local bind check |
| **Behind a proxy / ingress** | nginx/Traefik/K8s terminates TLS, forwards | bind high plaintext ports; recommend TLS off |
| **No public IP (NAT)** | home lab / laptop | a **mailrelay** on a VDS binds the ports and tunnels them here |

The local bind check now runs only for direct/proxy (for relay the ports bind on
the VDS, so there is nothing to check on this host). The relay path collects the
relay host + transport and produces the exact provisioning commands.

---

## 2. mailrelay — the "no public IP" solution

### 2.1 The core idea: a remote `net.Listener`

Every mailnite listener is created the same way (e.g. `SMTPServer.Bind` in
`pkg/server/smtp_server.go:96`):

```go
t.listener, err = net.Listen("tcp", t.address)   // then Serve(t.listener)
```

That single line is the seam. If, instead of `net.Listen`, mailnite is handed a
`net.Listener` whose connections arrive from a public VDS, **everything above it
is unchanged** — the SMTP/IMAP/POP3/HTTP servers keep calling `Serve(listener)`
and never learn the socket is remote. mailrelay provides exactly that listener.

### 2.2 Roles: mailnite dials out

NAT only blocks *inbound* connections, so the relay is the value-rpc **server**
(on the public IP) and mailnite is the **client** that dials **outbound**. Once
connected, value-rpc is peer-symmetric, so the direction of the initial dial is
just a setup detail — but it is the detail that defeats NAT.

### 2.3 The protocol (three RPCs)

See [`protocol/protocol.go`](protocol/protocol.go). Control messages are small
JSON documents in a `value.String`; only the byte path uses `value.Raw`.

- **`session`** (chat) — mailnite opens one, naming the public ports it wants.
  The relay opens those listeners on the VDS and streams back a `ready` event
  (per-port results) then one `accept` event per inbound public connection. **The
  chat's lifetime is the session:** when it ends (mailnite disconnects or the
  process exits), the relay drops every public listener — a dead mailnite never
  leaves ports bound. Teardown fires on either the handler `ctx` cancelling or the
  control channel closing.
- **`conn`** (chat) — one per tunneled connection. After an `accept`, mailnite
  opens `conn(connId)`; the two directions carry the raw TCP bytes (relay→mailnite
  = the public client's bytes, mailnite→relay = mailnite's reply). Closing either
  side tears the public connection down.
- **`ping`** (unary) — liveness.

### 2.4 Security model

- **Mutual TLS from a private CA** ([`pki`](pki/pki.go)). The CA is generated on
  the mailnite side; it signs exactly two leaves — the relay server cert and the
  mailnite client cert — and each end trusts only that CA. The relay rejects any
  client whose cert doesn't chain to it (`tls.RequireAndVerifyClientCert`);
  mailnite rejects any relay that isn't the one it issued for.
- **The relay is a byte pump.** It never terminates application TLS: STARTTLS and
  implicit TLS on the mail ports are end-to-end between the remote peer and
  mailnite, *through* the tunnel. The VDS sees ciphertext.
- **No data at rest on the VDS.** Only the CA cert, the relay's own cert/key, and
  (optionally) a token live there. Mail, user keys and the search index never
  leave your hardware.
- **`ws` transport** trades client-cert mTLS for a handshake token (its client
  uses the system trust store), so it can ride a CDN/443; use a publicly-trusted
  cert there.

### 2.5 Privileged ports (< 1024)

Binding 25/80/443/465/587/993/995 needs privilege. The relay reports a failed
sub-1024 bind as a structured result (`BindResult.Privileged = true`) so the UI
can show the remedy rather than an errno, and the deployer applies one of:

- `setcap cap_net_bind_service=+eip mailrelay` (least privilege; the default, also
  set as the systemd unit's `AmbientCapabilities`), or
- `--sysctl` → `net.ipv4.ip_unprivileged_port_start=0` (host-wide floor).

The `deploy` command does this automatically with `--privileged`.

### 2.6 SSH deployment

[`deploy`](deploy/ssh.go) reduces the operator's job to *an SSH login and a public
address*: it ships the binary and the CA + server cert, grants the port
capability, writes a hardened systemd unit (`NoNewPrivileges`, a single
`AmbientCapabilities=CAP_NET_BIND_SERVICE`) and starts it. `gen-ssh-key` produces
the ed25519 keypair and prints the one line the operator adds to the VDS's
`authorized_keys`. Host keys are trust-on-first-use (fingerprint printed) or
pinned with `--host-key`.

---

## 3. What is built vs. the next step

**Built and tested now** (this module — `go test ./... -race` green, including an
end-to-end round trip where a public TCP client's bytes are echoed back through
the full tunnel over mutual TLS):

- the relay server + reverse tunnel, runtime transport selection (tls/ws/quic);
- the private-CA PKI and the `relayclient` reverse `net.Listener`;
- the full CLI (`serve`, `gen-ca`, `gen-certs`, `gen-ssh-key`, `deploy`);
- the onboarding UI: the S3 fix and the Access/deployment-model step.

**The remaining step — wiring `relayclient` into mailnite.** It is intentionally
*not* in this pass because it touches the mail/web listener factories and should
be reviewed on its own. The shape:

1. **A relay dialer bean.** When `relay.enabled=1`, a bean dials the relay
   (`relayclient.Dial`) and `Bind`s the mail/web port set, exposing a
   `map[string]net.Listener` in the container.

2. **Listeners consult it.** Each server factory (`SMTPServer`, `IMAPServer`,
   `POP3Server`, and the servion HTTP server) checks for a relay listener under
   its name before falling back to `net.Listen`:

   ```go
   func (t *SMTPServer) Bind() (err error) {
       if l, ok := relayListener(t.Context, "smtp"); ok {
           t.listener = l                 // remote socket; nothing binds locally
           return nil
       }
       t.listener, err = net.Listen("tcp", t.address)   // unchanged fallback
       return err
   }
   ```

   Because the servers already separate `Bind()` from `Serve(listener)`, this is
   the only change per server — no protocol code moves.

3. **Onboarding provisions in-console.** New installer endpoints generate the CA +
   certs + SSH key (reusing this module's `pki`/`deploy`), show the operator the
   public SSH line, run `deploy.Deploy` against the entered host, and persist the
   `relay.*` settings. mailnite then depends on `github.com/mailnite/mailrelay`
   (require + local `replace`, like `mailcore`).

This keeps the risky, cross-cutting change (touching every listener) as a
separate, reviewable diff, while the relay itself is already proven.

---

## 4. Summary

- **S3 checkbox:** now points to Admin → Storage and states real behaviour — no
  dead end, no config-key spelunking.
- **Ports step → Access step:** asks how the server is reachable and adapts;
  stops demanding local binds where they make no sense.
- **mailrelay:** a stateless, mutually-authenticated reverse tunnel that turns
  "one VDS with a public IP + SSH" into a full public mail presence for a server
  behind NAT — with the mail and all secrets staying on your own hardware.
