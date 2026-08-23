/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relayclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mailnite/mailrelay/pki"
)

/*
Each fake speaks its protocol's real wire against our dialers, records what
the proxy SAW (the target it was asked to reach, the credentials offered)
and then echoes bytes — so a test proves the handshake, the auth and the
transparency of the resulting pipe in one pass.
*/

type proxySeen struct {
	mu     sync.Mutex
	target string
	user   string
	pass   string
}

func (s *proxySeen) set(target, user, pass string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.target, s.user, s.pass = target, user, pass
}

func (s *proxySeen) get() (string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target, s.user, s.pass
}

// echoAfterHandshake pipes the connection back at itself.
func echoAfterHandshake(c net.Conn) { _, _ = io.Copy(c, c) }

// assertEcho proves the pipe carries payload bytes untouched both ways.
func assertEcho(t *testing.T, c net.Conn) {
	t.Helper()
	msg := []byte("through-the-proxy")
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write through proxy: %v", err)
	}
	buf := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("pipe corrupted: %q", buf)
	}
}

// --- fake SOCKS5 (RFC 1928 + 1929) -------------------------------------------

func fakeSocks5(t *testing.T, wantUser, wantPass string, seen *proxySeen) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if !socks5Handshake(c, wantUser, wantPass, seen) {
					return
				}
				echoAfterHandshake(c)
			}(c)
		}
	}()
	return lis
}

func socks5Handshake(c net.Conn, wantUser, wantPass string, seen *proxySeen) bool {
	br := bufio.NewReader(c)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return false
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return false
	}
	needAuth := wantUser != ""
	if needAuth {
		has := false
		for _, m := range methods {
			if m == 2 {
				has = true
			}
		}
		if !has {
			_, _ = c.Write([]byte{5, 0xff})
			return false
		}
		if _, err := c.Write([]byte{5, 2}); err != nil {
			return false
		}
		// RFC 1929: VER ULEN UNAME PLEN PASSWD
		ah := make([]byte, 2)
		if _, err := io.ReadFull(br, ah); err != nil || ah[0] != 1 {
			return false
		}
		user := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(br, user); err != nil {
			return false
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(br, pl); err != nil {
			return false
		}
		pass := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(br, pass); err != nil {
			return false
		}
		if string(user) != wantUser || string(pass) != wantPass {
			_, _ = c.Write([]byte{1, 1}) // denied
			return false
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return false
		}
		seen.set("", string(user), string(pass))
	} else {
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return false
		}
	}
	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	rh := make([]byte, 4)
	if _, err := io.ReadFull(br, rh); err != nil || rh[0] != 5 || rh[1] != 1 {
		return false
	}
	var host string
	switch rh[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return false
		}
		host = net.IP(ip).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return false
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return false
		}
		host = string(b)
	default:
		return false
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return false
	}
	port := binary.BigEndian.Uint16(pb)
	_, u, p := seen.get()
	seen.set(net.JoinHostPort(host, intToStr(int(port))), u, p)
	_, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestProxySocks5AuthAndPipe(t *testing.T) {
	var seen proxySeen
	lis := fakeSocks5(t, "alice", "s3cret", &seen)
	defer lis.Close()

	p := ProxyConfig{Type: ProxySocks5, Addr: lis.Addr().String(), Username: "alice", Password: "s3cret"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, "tcp", "relay.example.test:8443")
	if err != nil {
		t.Fatalf("socks5 dial: %v", err)
	}
	defer c.Close()
	target, user, _ := seen.get()
	if target != "relay.example.test:8443" {
		t.Fatalf("proxy must be handed the UNRESOLVED relay target, saw %q", target)
	}
	if user != "alice" {
		t.Fatalf("RFC 1929 credentials must be offered, saw user %q", user)
	}
	assertEcho(t, c)
}

func TestProxySocks5WrongPassword(t *testing.T) {
	var seen proxySeen
	lis := fakeSocks5(t, "alice", "s3cret", &seen)
	defer lis.Close()

	p := ProxyConfig{Type: ProxySocks5, Addr: lis.Addr().String(), Username: "alice", Password: "wrong"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.DialContext(ctx, "tcp", "relay.example.test:8443"); err == nil {
		t.Fatal("a rejected password must fail the dial")
	}
}

// --- fake SOCKS4/4a -------------------------------------------------------------

func fakeSocks4(t *testing.T, seen *proxySeen) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				head := make([]byte, 8)
				if _, err := io.ReadFull(br, head); err != nil || head[0] != 4 || head[1] != 1 {
					return
				}
				port := binary.BigEndian.Uint16(head[2:4])
				user, err := br.ReadString(0)
				if err != nil {
					return
				}
				user = strings.TrimSuffix(user, "\x00")
				var host string
				if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] != 0 { // 4a marker
					h, err := br.ReadString(0)
					if err != nil {
						return
					}
					host = strings.TrimSuffix(h, "\x00")
				} else {
					host = net.IPv4(head[4], head[5], head[6], head[7]).String()
				}
				seen.set(net.JoinHostPort(host, intToStr(int(port))), user, "")
				if _, err := c.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0}); err != nil {
					return
				}
				echoAfterHandshake(c)
			}(c)
		}
	}()
	return lis
}

func TestProxySocks4aHostname(t *testing.T) {
	var seen proxySeen
	lis := fakeSocks4(t, &seen)
	defer lis.Close()

	p := ProxyConfig{Type: ProxySocks4, Addr: lis.Addr().String(), Username: "ident-user"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, "tcp", "relay.example.test:8443")
	if err != nil {
		t.Fatalf("socks4a dial: %v", err)
	}
	defer c.Close()
	target, user, _ := seen.get()
	if target != "relay.example.test:8443" {
		t.Fatalf("4a must carry the hostname to the proxy, saw %q", target)
	}
	if user != "ident-user" {
		t.Fatalf("the ident field must carry the username, saw %q", user)
	}
	assertEcho(t, c)
}

func TestProxySocks4LiteralIP(t *testing.T) {
	var seen proxySeen
	lis := fakeSocks4(t, &seen)
	defer lis.Close()

	p := ProxyConfig{Type: ProxySocks4, Addr: lis.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, "tcp", "192.0.2.7:8443")
	if err != nil {
		t.Fatalf("socks4 dial: %v", err)
	}
	defer c.Close()
	if target, _, _ := seen.get(); target != "192.0.2.7:8443" {
		t.Fatalf("classic v4 addressing broken, saw %q", target)
	}
	assertEcho(t, c)
}

// --- fake HTTP CONNECT (plain and TLS) --------------------------------------------

func connectHandler(wantAuth string, seen *proxySeen) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(req, "CONNECT ") {
			return
		}
		target := strings.Fields(req)[1]
		var auth string
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Proxy-Authorization: Basic "); ok {
				auth = v
			}
		}
		if wantAuth != "" && auth != wantAuth {
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\n\r\n"))
			return
		}
		user := ""
		if auth != "" {
			if dec, err := base64.StdEncoding.DecodeString(auth); err == nil {
				user, _, _ = strings.Cut(string(dec), ":")
			}
		}
		seen.set(target, user, "")
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		echoAfterHandshake(c)
	}
}

func serveConns(lis net.Listener, handle func(net.Conn)) {
	for {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}

func TestProxyHTTPConnectBasicAuth(t *testing.T) {
	var seen proxySeen
	want := base64.StdEncoding.EncodeToString([]byte("bob:pw"))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go serveConns(lis, connectHandler(want, &seen))

	p := ProxyConfig{Type: ProxyHTTP, Addr: lis.Addr().String(), Username: "bob", Password: "pw"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, "tcp", "relay.example.test:8443")
	if err != nil {
		t.Fatalf("http connect: %v", err)
	}
	defer c.Close()
	if target, _, _ := seen.get(); target != "relay.example.test:8443" {
		t.Fatalf("CONNECT target wrong: %q", target)
	}
	assertEcho(t, c)

	// And without credentials the 407 must surface as a clear error.
	bad := ProxyConfig{Type: ProxyHTTP, Addr: lis.Addr().String()}
	if _, err := bad.DialContext(ctx, "tcp", "relay.example.test:8443"); err == nil || !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "authentication required") {
		t.Fatalf("407 must fail with the auth reason, got %v", err)
	}
}

// --- TLS-wrapped flavors: https CONNECT and socks5-tls ------------------------------

// proxyTLSListener wraps a fresh listener in TLS with a throwaway CA issued
// for 127.0.0.1, returning the listener and the CA PEM the client pins.
func proxyTLSListener(t *testing.T) (net.Listener, []byte) {
	t.Helper()
	ca, err := pki.GenerateCA("proxy-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.IssueServerCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	return lis, ca.CertPEM
}

func TestProxyHTTPSConnect(t *testing.T) {
	var seen proxySeen
	lis, caPEM := proxyTLSListener(t)
	defer lis.Close()
	go serveConns(lis, connectHandler("", &seen))

	p := ProxyConfig{Type: ProxyHTTPS, Addr: lis.Addr().String(), CAPEM: caPEM}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, "tcp", "relay.example.test:8443")
	if err != nil {
		t.Fatalf("https connect: %v", err)
	}
	defer c.Close()
	if target, _, _ := seen.get(); target != "relay.example.test:8443" {
		t.Fatalf("CONNECT target wrong: %q", target)
	}
	assertEcho(t, c)

	// The hop is authenticated: without the CA the dial must refuse.
	noCA := ProxyConfig{Type: ProxyHTTPS, Addr: lis.Addr().String()}
	if _, err := noCA.DialContext(ctx, "tcp", "relay.example.test:8443"); err == nil {
		t.Fatal("an unverifiable TLS proxy must refuse, never fall back to insecure")
	}
}

func TestProxySocks5OverTLS(t *testing.T) {
	var seen proxySeen
	lis, caPEM := proxyTLSListener(t)
	defer lis.Close()
	go serveConns(lis, func(c net.Conn) {
		defer c.Close()
		if socks5Handshake(c, "alice", "s3cret", &seen) {
			echoAfterHandshake(c)
		}
	})

	p := ProxyConfig{Type: ProxySocks5TLS, Addr: lis.Addr().String(), Username: "alice", Password: "s3cret", CAPEM: caPEM}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.DialContext(ctx, "tcp", "relay.example.test:8443")
	if err != nil {
		t.Fatalf("socks5-tls dial: %v", err)
	}
	defer c.Close()
	target, user, _ := seen.get()
	if target != "relay.example.test:8443" || user != "alice" {
		t.Fatalf("socks5 dialogue inside TLS broken: target=%q user=%q", target, user)
	}
	assertEcho(t, c)
}

// --- config-level guards ------------------------------------------------------------

func TestProxyQUICRefused(t *testing.T) {
	_, err := newClient(Config{Transport: "quic", Addr: "r:8443", Proxy: ProxyConfig{Type: ProxySocks5, Addr: "p:1080"}})
	if err == nil || !strings.Contains(err.Error(), "QUIC") {
		t.Fatalf("quic+proxy must refuse with the reason, got %v", err)
	}
}

func TestProxyValidate(t *testing.T) {
	if err := (ProxyConfig{}).Validate(); err != nil {
		t.Fatalf("off must validate: %v", err)
	}
	if err := (ProxyConfig{Type: ProxySocks4, Addr: "p:1080", Password: "x"}).Validate(); err == nil {
		t.Fatal("socks4+password must be refused (no such auth in the protocol)")
	}
	if err := (ProxyConfig{Type: ProxySocks5, Addr: "no-port"}).Validate(); err == nil {
		t.Fatal("a proxy address without a port must be refused")
	}
	if _, err := NormalizeProxyType("socks6"); err == nil {
		t.Fatal("socks6 is a dead draft — it must be named unknown, not silently accepted")
	}
}
