/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relayclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/xerrors"
)

/*
Egress proxy for the tunnel dial (mailnite docs/design/ah-relay-proxy.md).

A mailnite behind a restrictive network may only reach its relay VDS through
an egress proxy. The proxy carries the OUTER TCP stream only: the tunnel's
own TLS (token mode) or mutual TLS runs end-to-end THROUGH it, so a proxy —
even a hostile one — sees ciphertext and can at worst refuse service.

Types, from the protocol survey:

  - socks5      RFC 1928; username/password per RFC 1929 (sent in the clear
                to the proxy — the standard has no encryption of its own).
  - socks5-tls  the de-facto "SOCKS over TLS" deployment (stunnel/gost/xray
                style): a TLS connection to the proxy first, the plain
                SOCKS5 dialogue inside. Not an IETF standard, but the only
                way SOCKS gets transport security; credentials ride inside
                the TLS envelope.
  - socks4      the 1992 protocol: CONNECT only, no password at all (the
                ident field carries a bare username). Hostname targets use
                the 4a extension so DNS stays with the proxy.
  - http        HTTP CONNECT (RFC 9110 §9.3.6) with optional Basic
                Proxy-Authorization — the classic corporate egress proxy.
  - https       HTTP CONNECT over TLS to the proxy — the standards-track
                answer to "an encrypted hop to the proxy".

SOCKS6 is deliberately absent: draft-olteanu-intarea-socks-6 expired in 2021
without becoming an RFC, its wire format changed incompatibly between draft
revisions, no deployed proxy speaks it, and it adds no confidentiality
anyway (the draft defers to TLS, exactly like SOCKS5). The protected
options here are the TLS-wrapped types above.
*/

// Proxy types accepted by ProxyConfig.Type.
const (
	ProxyNone      = ""
	ProxySocks5    = "socks5"
	ProxySocks5TLS = "socks5-tls"
	ProxySocks4    = "socks4"
	ProxyHTTP      = "http"
	ProxyHTTPS     = "https"
)

// ProxyConfig describes the egress proxy the tunnel dial must traverse.
type ProxyConfig struct {
	Type     string // one of the Proxy* constants; empty = direct
	Addr     string // host:port of the proxy
	Username string // socks5/socks5-tls/http/https: auth user; socks4: the ident field
	Password string // socks5/socks5-tls/http/https only — socks4 has no password
	CAPEM    []byte // socks5-tls/https: verify the proxy's cert against this CA (default: system roots)
}

// Enabled reports whether a proxy is configured at all.
func (p ProxyConfig) Enabled() bool { return p.Type != ProxyNone }

// NormalizeProxyType maps user input to a known type ("" when off).
func NormalizeProxyType(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "off":
		return ProxyNone, nil
	case ProxySocks5:
		return ProxySocks5, nil
	case "socks5-tls", "socks5s", "socks5+tls":
		return ProxySocks5TLS, nil
	case ProxySocks4, "socks4a":
		return ProxySocks4, nil
	case ProxyHTTP, "connect":
		return ProxyHTTP, nil
	case ProxyHTTPS:
		return ProxyHTTPS, nil
	}
	return "", xerrors.Errorf("unknown proxy type %q (socks5, socks5-tls, socks4, http, https)", s)
}

// Validate rejects a config the dial path could not honour, with the reason
// spelled out — a save-time check, so the error lands next to the form.
func (p ProxyConfig) Validate() error {
	if !p.Enabled() {
		return nil
	}
	if _, err := NormalizeProxyType(p.Type); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(p.Addr))
	if err != nil || host == "" || port == "" {
		return xerrors.Errorf("proxy address must be host:port, got %q", p.Addr)
	}
	if p.Type == ProxySocks4 && p.Password != "" {
		return xerrors.New("SOCKS4 has no password authentication — only an ident username; use SOCKS5 for credentials")
	}
	return nil
}

// DialContext opens a TCP connection to target (host:port) through the proxy.
// The hostname is always handed to the proxy unresolved (socks5 domain
// addressing / socks4a / CONNECT host form): the operator put the proxy in
// the path, so DNS belongs on its side of the fence.
func (p ProxyConfig) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, xerrors.Errorf("a %s proxy carries TCP only, not %s", p.Type, network)
	}
	switch p.Type {
	case ProxySocks5:
		return p.dialSocks5(ctx, target, nil)
	case ProxySocks5TLS:
		tlsCfg, err := p.proxyTLS()
		if err != nil {
			return nil, err
		}
		return p.dialSocks5(ctx, target, tlsCfg)
	case ProxySocks4:
		return p.dialSocks4(ctx, target)
	case ProxyHTTP:
		return p.dialConnect(ctx, target, nil)
	case ProxyHTTPS:
		tlsCfg, err := p.proxyTLS()
		if err != nil {
			return nil, err
		}
		return p.dialConnect(ctx, target, tlsCfg)
	}
	return nil, xerrors.Errorf("unknown proxy type %q", p.Type)
}

// proxyTLS is the client TLS config for the encrypted hop TO THE PROXY
// (socks5-tls / https): SNI = the proxy's own host, roots = the pinned CA
// when given, the system pool otherwise. Never insecure — an egress proxy
// an operator cannot authenticate is not protection.
func (p ProxyConfig) proxyTLS() (*tls.Config, error) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(p.Addr))
	if err != nil {
		return nil, xerrors.Errorf("proxy address %q: %w", p.Addr, err)
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if len(p.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(p.CAPEM) {
			return nil, xerrors.New("proxy CA: no certificate found in the PEM")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// rawDial opens the transport to the proxy itself — plain TCP, or TLS when
// the type calls for an encrypted hop.
func (p ProxyConfig) rawDial(ctx context.Context, tlsCfg *tls.Config) (net.Conn, error) {
	if tlsCfg != nil {
		td := &tls.Dialer{Config: tlsCfg}
		c, err := td.DialContext(ctx, "tcp", p.Addr)
		if err != nil {
			return nil, xerrors.Errorf("dial proxy %s (tls): %w", p.Addr, err)
		}
		return c, nil
	}
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", p.Addr)
	if err != nil {
		return nil, xerrors.Errorf("dial proxy %s: %w", p.Addr, err)
	}
	return c, nil
}

// --- SOCKS5 (RFC 1928/1929) ---------------------------------------------------

// tlsForward lets x/net/proxy's SOCKS5 dialer reach the proxy over an
// already-encrypted hop: its "forward" dial to the proxy address returns a
// fresh TLS connection, and the SOCKS5 dialogue runs inside it.
type tlsForward struct {
	p      ProxyConfig
	tlsCfg *tls.Config
}

func (f tlsForward) Dial(network, addr string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, addr)
}

func (f tlsForward) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, xerrors.Errorf("proxy forward: tcp only, not %s", network)
	}
	return f.p.rawDial(ctx, f.tlsCfg)
}

func (p ProxyConfig) dialSocks5(ctx context.Context, target string, tlsCfg *tls.Config) (net.Conn, error) {
	var auth *proxy.Auth
	if p.Username != "" || p.Password != "" {
		auth = &proxy.Auth{User: p.Username, Password: p.Password}
	}
	var forward proxy.Dialer = proxy.Direct
	if tlsCfg != nil {
		forward = tlsForward{p: p, tlsCfg: tlsCfg}
	}
	d, err := proxy.SOCKS5("tcp", p.Addr, auth, forward)
	if err != nil {
		return nil, xerrors.Errorf("socks5 %s: %w", p.Addr, err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		c, err := cd.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, xerrors.Errorf("socks5 %s → %s: %w", p.Addr, target, err)
		}
		return c, nil
	}
	c, err := d.Dial("tcp", target)
	if err != nil {
		return nil, xerrors.Errorf("socks5 %s → %s: %w", p.Addr, target, err)
	}
	return c, nil
}

// --- SOCKS4 / SOCKS4a -----------------------------------------------------------

func (p ProxyConfig) dialSocks4(ctx context.Context, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, xerrors.Errorf("socks4 target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 0xffff {
		return nil, xerrors.Errorf("socks4 target port %q", portStr)
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		return nil, xerrors.New("SOCKS4 cannot address IPv6 — use SOCKS5")
	}

	conn, err := p.rawDial(ctx, nil)
	if err != nil {
		return nil, err
	}
	abort := func(e error) (net.Conn, error) { _ = conn.Close(); return nil, e }
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// VN CD DSTPORT(2) DSTIP(4) USERID NUL [4a: HOSTNAME NUL]
	req := []byte{4, 1, byte(port >> 8), byte(port)}
	if v4 := ip.To4(); v4 != nil {
		req = append(req, v4...)
	} else {
		req = append(req, 0, 0, 0, 1) // 0.0.0.x — the 4a marker: hostname follows
	}
	req = append(req, []byte(p.Username)...)
	req = append(req, 0)
	if ip == nil {
		req = append(req, []byte(host)...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		return abort(xerrors.Errorf("socks4 %s: write: %w", p.Addr, err))
	}

	var resp [8]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return abort(xerrors.Errorf("socks4 %s: read reply: %w", p.Addr, err))
	}
	// Historical servers answer VN=0; some echo 4. The verdict is CD.
	switch resp[1] {
	case 0x5a:
	case 0x5b:
		return abort(xerrors.Errorf("socks4 %s: request rejected or failed", p.Addr))
	case 0x5c, 0x5d:
		return abort(xerrors.Errorf("socks4 %s: rejected by ident policy (code %#x)", p.Addr, resp[1]))
	default:
		return abort(xerrors.Errorf("socks4 %s: malformed reply (code %#x)", p.Addr, resp[1]))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// --- HTTP CONNECT (http / https) --------------------------------------------------

func (p ProxyConfig) dialConnect(ctx context.Context, target string, tlsCfg *tls.Config) (net.Conn, error) {
	conn, err := p.rawDial(ctx, tlsCfg)
	if err != nil {
		return nil, err
	}
	abort := func(e error) (net.Conn, error) { _ = conn.Close(); return nil, e }
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.Username != "" || p.Password != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return abort(xerrors.Errorf("proxy %s: CONNECT write: %w", p.Addr, err))
	}

	// Read the response head only — the reader must not buffer past the blank
	// line, because everything after it belongs to the tunneled protocol.
	br := bufio.NewReaderSize(&headOnlyReader{c: conn}, 4096)
	status, err := br.ReadString('\n')
	if err != nil {
		return abort(xerrors.Errorf("proxy %s: CONNECT response: %w", p.Addr, err))
	}
	parts := strings.SplitN(strings.TrimSpace(status), " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return abort(xerrors.Errorf("proxy %s: not an HTTP CONNECT proxy (%q)", p.Addr, strings.TrimSpace(status)))
	}
	code, _ := strconv.Atoi(parts[1])
	for { // drain headers to the blank line
		line, err := br.ReadString('\n')
		if err != nil {
			return abort(xerrors.Errorf("proxy %s: CONNECT headers: %w", p.Addr, err))
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	switch {
	case code == http.StatusOK:
	case code == http.StatusProxyAuthRequired:
		return abort(xerrors.Errorf("proxy %s: authentication required (407) — check the proxy username/password", p.Addr))
	default:
		return abort(xerrors.Errorf("proxy %s: CONNECT %s refused: %s", p.Addr, target, strings.TrimSpace(status)))
	}
	if br.Buffered() > 0 {
		// Bytes past the blank line inside our buffer would be stolen from the
		// tunnel. headOnlyReader's 1-byte reads make this impossible; guard anyway.
		return abort(xerrors.Errorf("proxy %s: CONNECT over-read %d tunneled bytes", p.Addr, br.Buffered()))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// headOnlyReader reads one byte at a time so the bufio reader can never
// swallow tunneled bytes that follow the CONNECT response head.
type headOnlyReader struct{ c net.Conn }

func (r *headOnlyReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.c.Read(b)
}
