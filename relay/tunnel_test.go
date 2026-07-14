/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relay_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mailnite/mailrelay/pki"
	"github.com/mailnite/mailrelay/protocol"
	"github.com/mailnite/mailrelay/relay"
	"github.com/mailnite/mailrelay/relayclient"
	"go.arpabet.com/value"
	"go.arpabet.com/value-rpc/valueclient"
	"go.arpabet.com/value-rpc/valueserver"
	"go.uber.org/zap"
)

// TestTunnelRoundTrip exercises the whole architecture over the tls transport: a
// relay binds an (ephemeral) public port; a mailnite-side reverse listener serves
// an echo on it; a public TCP client connects to the relay's public port and must
// get its bytes echoed back — proving the accept event, the conn chat byte pump
// and mutual TLS all work end to end.
func TestTunnelRoundTrip(t *testing.T) {
	log := zap.NewNop()

	ca, err := pki.GenerateCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.IssueServerCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := ca.IssueClientCert("mailnite")
	if err != nil {
		t.Fatal(err)
	}

	// Relay side: a mutual-TLS value-rpc server hosting the tunnel.
	srvTLS, err := pki.ServerTLSConfig(server.CertPEM, server.KeyPEM, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	if err := tun.Register(srv); err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	relayAddr := srv.Addr().String()

	// mailnite side: dial the relay and ask it to bind a public port.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := relayclient.Dial(ctx, relayclient.Config{
		Transport:     protocol.TransportTCP,
		Addr:          relayAddr,
		ServerName:    "127.0.0.1",
		CAPEM:         ca.CertPEM,
		ClientCertPEM: client.CertPEM,
		ClientKeyPEM:  client.KeyPEM,
	}, log)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sess.Close()

	listeners, binds, err := sess.Bind(ctx, []protocol.PortSpec{{Name: "echo", Port: 0, Proto: "tcp"}})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	ln := listeners["echo"]
	if ln == nil || len(binds) != 1 || !binds[0].OK {
		t.Fatalf("bind not ready: %+v", binds)
	}

	// Serve an echo on the reverse listener (this is what a mail server's
	// Serve(listener) does, minus the protocol).
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	// A public client connects to the relay's public port.
	_, port, err := net.SplitHostPort(binds[0].PublicAddr)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial public port: %v", err)
	}
	defer pub.Close()

	msg := []byte("hello through the tunnel\n")
	if _, err := pub.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	pub.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(pub, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// TestTunnelMultiTenant proves one relay serves several independent clients: two
// separate sessions each bind their own public port and both work at once, and
// closing one leaves the other running.
func TestTunnelMultiTenant(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	srvCert, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	cliCert, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(srvCert.CertPEM, srvCert.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	dial := func() *relayclient.Session {
		s, err := relayclient.Dial(context.Background(), relayclient.Config{
			Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
			CAPEM: ca.CertPEM, ClientCertPEM: cliCert.CertPEM, ClientKeyPEM: cliCert.KeyPEM,
		}, log)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return s
	}

	// Client A and client B are two independent tunnels through the one relay.
	a, b := dial(), dial()
	defer b.Close()
	la, ba, err := a.Bind(context.Background(), []protocol.PortSpec{{Name: "svcA", Port: 0, Proto: "tcp"}})
	if err != nil || !ba[0].OK {
		t.Fatalf("A bind: %v %+v", err, ba)
	}
	lb, bb, err := b.Bind(context.Background(), []protocol.PortSpec{{Name: "svcB", Port: 0, Proto: "tcp"}})
	if err != nil || !bb[0].OK {
		t.Fatalf("B bind: %v %+v", err, bb)
	}
	go serveEcho(la["svcA"])
	go serveEcho(lb["svcB"])

	// Both public ports work simultaneously.
	echoOK(t, ba[0].PublicAddr, "hello-from-A")
	echoOK(t, bb[0].PublicAddr, "hello-from-B")

	// Closing A must not disturb B.
	a.Close()
	echoOK(t, bb[0].PublicAddr, "B-still-alive")
}

// TestTunnelConnSecretRejected checks that a client cannot attach to a connection
// without the capability secret the relay handed the owning client — the shared-
// relay isolation guarantee.
func TestTunnelConnSecretRejected(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	srvCert, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	cliCert, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(srvCert.CertPEM, srvCert.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	cliTLS, _ := pki.ClientTLSConfig(ca.CertPEM, cliCert.CertPEM, cliCert.KeyPEM, "127.0.0.1")
	cli := valueclient.NewTLSClient(srv.Addr().String(), cliTLS)
	if err := cli.ConnectContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// A conn chat with a bogus id/secret must be refused (no such authorized conn).
	args, _ := protocol.Encode(protocol.ConnArgs{ConnID: 999999, Secret: "bogus"})
	put := make(chan value.Value)
	readC, _, err := cli.Chat(context.Background(), protocol.FnConn, args, 1, put)
	if err != nil {
		close(put)
		return // rejected at open — good
	}
	// Otherwise the stream must close immediately with nothing delivered.
	close(put)
	if v, ok := <-readC; ok {
		t.Fatalf("expected rejection, got data %v", v)
	}
}

// TestTunnelTokenAuth exercises the key-authenticated ("just a key") mode: the
// relay presents a self-signed cert (no CA), the client dials with only a shared
// token and skips cert verification, and the tunnel works.
func TestTunnelTokenAuth(t *testing.T) {
	log := zap.NewNop()
	const token = "shared-secret-key-123"

	kp, err := pki.GenerateSelfSigned([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, err := pki.ServerTLSConfig(kp.CertPEM, kp.KeyPEM, nil) // no client cert required
	if err != nil {
		t.Fatal(err)
	}
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, token) // session-token check gates binding
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	// Client: token only, no CA/cert — relayclient uses InsecureSkipVerify.
	sess, err := relayclient.Dial(context.Background(), relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		Token: token,
	}, log)
	if err != nil {
		t.Fatalf("dial (token mode): %v", err)
	}
	defer sess.Close()

	ls, binds, err := sess.Bind(context.Background(), []protocol.PortSpec{{Name: "svc", Port: 0, Proto: "tcp"}})
	if err != nil || !binds[0].OK {
		t.Fatalf("bind: %v %+v", err, binds)
	}
	go serveEcho(ls["svc"])
	echoOK(t, binds[0].PublicAddr, "key-authenticated hello")

	// A wrong token must be refused at the session.
	bad, err := relayclient.Dial(context.Background(), relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		Token: "wrong",
	}, log)
	if err != nil {
		return // rejected at connect — fine
	}
	defer bad.Close()
	if _, _, err := bad.Bind(context.Background(), []protocol.PortSpec{{Name: "x", Port: 0, Proto: "tcp"}}); err == nil {
		t.Fatal("expected a wrong token to be rejected")
	}
}

func serveEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
	}
}

func echoOK(t *testing.T, publicAddr, msg string) {
	t.Helper()
	_, port, err := net.SplitHostPort(publicAddr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial %s: %v", publicAddr, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// TestTunnelConcurrent runs many public connections through one bind in parallel,
// each writing a payload, reading the echo and closing — stressing the conn-chat
// byte pump, the accept path and the Write/Close teardown together.
func TestTunnelConcurrent(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	server, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	client, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(server.CertPEM, server.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := relayclient.Dial(ctx, relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		CAPEM: ca.CertPEM, ClientCertPEM: client.CertPEM, ClientKeyPEM: client.KeyPEM,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	listeners, binds, err := sess.Bind(ctx, []protocol.PortSpec{{Name: "echo", Port: 0, Proto: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	ln := listeners["echo"]
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()

	_, port, _ := net.SplitHostPort(binds[0].PublicAddr)
	target := net.JoinHostPort("127.0.0.1", port)

	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.Dial("tcp", target)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			msg := []byte("conn-" + strconv.Itoa(i) + "-payload")
			if _, err := c.Write(msg); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(msg))
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(c, got); err != nil {
				errs <- err
				return
			}
			if string(got) != string(msg) {
				errs <- errUnexpected(string(got), string(msg))
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

type mismatch struct{ got, want string }

func (m mismatch) Error() string           { return "echo = " + m.got + ", want " + m.want }
func errUnexpected(got, want string) error { return mismatch{got, want} }

// TestBindOnlyOnce: a Session carries exactly one session chat. A second Bind
// must be refused loudly — silently opening a second chat would orphan the
// first one's server-side listeners (Close would only tear down the newest).
func TestBindOnlyOnce(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	server, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	client, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(server.CertPEM, server.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := relayclient.Dial(ctx, relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		CAPEM: ca.CertPEM, ClientCertPEM: client.CertPEM, ClientKeyPEM: client.KeyPEM,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if _, _, err := sess.Bind(ctx, []protocol.PortSpec{{Name: "a", Port: 0, Proto: "tcp"}}); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	if _, _, err := sess.Bind(ctx, []protocol.PortSpec{{Name: "b", Port: 0, Proto: "tcp"}}); err == nil {
		t.Fatal("second Bind on one session must be refused")
	}
}

// TestTunnelInfo: the relay reports its version/build over the info RPC, so a
// connected mailnite can show which relay binary it tunnels through.
func TestTunnelInfo(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	server, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	client, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(server.CertPEM, server.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.SetInfo("v9.9.9", "2026-07-11")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := relayclient.Dial(ctx, relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		CAPEM: ca.CertPEM, ClientCertPEM: client.CertPEM, ClientKeyPEM: client.KeyPEM,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	info, err := sess.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.Version != "v9.9.9" || info.Build != "2026-07-11" {
		t.Fatalf("info = %+v, want {v9.9.9 2026-07-11}", info)
	}
}

// TestPrivilegedBindReported checks that a sub-1024 bind failure comes back as a
// structured, actionable result rather than an opaque error, so onboarding can
// show the setcap/sysctl remedy. (Run as non-root, port 443 is unbindable.)
func TestPrivilegedBindReported(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	server, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	client, _ := ca.IssueClientCert("mailnite")

	srvTLS, _ := pki.ServerTLSConfig(server.CertPEM, server.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := relayclient.Dial(ctx, relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		CAPEM: ca.CertPEM, ClientCertPEM: client.CertPEM, ClientKeyPEM: client.KeyPEM,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	_, binds, err := sess.Bind(ctx, []protocol.PortSpec{{Name: "https", Port: 443, Proto: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(binds) != 1 {
		t.Fatalf("want 1 bind result, got %d", len(binds))
	}
	if binds[0].OK {
		t.Skip("running as root: port 443 bound, nothing to assert")
	}
	if !binds[0].Privileged {
		t.Fatalf("expected Privileged=true for a failed :443 bind, got %+v", binds[0])
	}
}

// TestTunnelDialOut exercises the OUTBOUND path: the relay dials an external
// host on mailnite's behalf (the egress fix for an ISP that blocks port 25) and
// pumps bytes both ways. An in-process "MX" on an allowed mail port stands in
// for a real one; the relay dials it, and the mailnite-side net.Conn must carry
// the peer-speaks-first banner and echo, proving the byte pump runs both ways.
func TestTunnelDialOut(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	srvCert, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	cliCert, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(srvCert.CertPEM, srvCert.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	// A stand-in MX on an allowed mail port (2525 is unprivileged; skip if the
	// port is already taken so the test never flakes on a busy machine). It
	// speaks first (like SMTP's 220 banner), then echoes.
	mx, err := net.Listen("tcp", "127.0.0.1:2525")
	if err != nil {
		t.Skipf("mail port 2525 unavailable for the stand-in MX: %v", err)
	}
	defer mx.Close()
	go func() {
		c, err := mx.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("220 relay-egress ESMTP\r\n"))
		io.Copy(c, c)
	}()

	sess, err := relayclient.Dial(context.Background(), relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		CAPEM: ca.CertPEM, ClientCertPEM: cliCert.CertPEM, ClientKeyPEM: cliCert.KeyPEM,
	}, log)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer sess.Close()

	// Dial the external MX THROUGH the relay — no Bind/session listeners needed.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := sess.DialOut(ctx, "127.0.0.1", 2525)
	if err != nil {
		t.Fatalf("dial out: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// The peer speaks first: the banner must arrive over the tunnel.
	banner := make([]byte, len("220 relay-egress ESMTP\r\n"))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(banner) != "220 relay-egress ESMTP\r\n" {
		t.Fatalf("banner mismatch: %q", banner)
	}
	// And our bytes reach the MX and echo back.
	msg := []byte("EHLO mailnite\r\n")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// TestTunnelDialOutPortRejected proves the relay refuses to dial a non-mail
// port, so a leaked token cannot turn the tunnel into a general TCP proxy.
func TestTunnelDialOutPortRejected(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("test-ca")
	srvCert, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	cliCert, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(srvCert.CertPEM, srvCert.KeyPEM, ca.CertPEM)
	srv, _ := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	sess, err := relayclient.Dial(context.Background(), relayclient.Config{
		Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
		CAPEM: ca.CertPEM, ClientCertPEM: cliCert.CertPEM, ClientKeyPEM: cliCert.KeyPEM,
	}, log)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Port 80 is not a mail port: the relay must reject the dial. A rejected
	// chat surfaces either as an open error or an immediately-closed stream.
	conn, err := sess.DialOut(ctx, "127.0.0.1", 80)
	if err != nil {
		return // rejected at open — the expected, cleanest outcome
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err == nil && n > 0 {
		t.Fatal("expected the relay to refuse dialing a non-mail port, but bytes flowed")
	}
}

// freeTCPPort reserves an ephemeral port and releases it, so a test can hand a
// concrete port number to two competing sessions. The tiny reuse race is fine
// on loopback in tests.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// relayHarness stands up a mutual-TLS relay and returns a dialer for clients —
// the shared setup of the takeover/heartbeat tests.
func relayHarness(t *testing.T) (dial func() *relayclient.Session, addr string, ca *pki.CA, cleanup func()) {
	t.Helper()
	log := zap.NewNop()
	ca, _ = pki.GenerateCA("test-ca")
	srvCert, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	cliCert, _ := ca.IssueClientCert("mailnite")
	srvTLS, _ := pki.ServerTLSConfig(srvCert.CertPEM, srvCert.KeyPEM, ca.CertPEM)
	srv, err := valueserver.NewTLSServer("127.0.0.1:0", srvTLS, log)
	if err != nil {
		t.Fatal(err)
	}
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	dial = func() *relayclient.Session {
		s, err := relayclient.Dial(context.Background(), relayclient.Config{
			Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1",
			CAPEM: ca.CertPEM, ClientCertPEM: cliCert.CertPEM, ClientKeyPEM: cliCert.KeyPEM,
		}, log)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		return s
	}
	return dial, srv.Addr().String(), ca, func() { srv.Close(); tun.Close() }
}

// TestTakeoverReclaimsPreviousSessionPort is the slept-laptop scenario: a
// previous session still holds a public port (the relay has not noticed it is
// dead), and the SAME client reconnects. The successor must evict the old
// session and bind on the first try — not wait for keepalive to reap it.
func TestTakeoverReclaimsPreviousSessionPort(t *testing.T) {
	dial, _, _, cleanup := relayHarness(t)
	defer cleanup()
	port := freeTCPPort(t)
	spec := []protocol.PortSpec{{Name: "svc", Port: port, Proto: "tcp"}}

	a := dial()
	defer a.Close()
	la, ba, err := a.Bind(context.Background(), spec)
	if err != nil || !ba[0].OK {
		t.Fatalf("first session bind: %v %+v", err, ba)
	}

	// The successor (relayclient always requests takeover) reclaims the port.
	b := dial()
	defer b.Close()
	lb, bb, err := b.Bind(context.Background(), spec)
	if err != nil {
		t.Fatalf("successor bind: %v", err)
	}
	if !bb[0].OK {
		t.Fatalf("successor did not take the port over: %+v", bb)
	}
	go serveEcho(lb["svc"])
	echoOK(t, bb[0].PublicAddr, "hello-through-the-successor")

	// The evicted session's reverse listener must die (its stream was closed).
	dead := make(chan struct{})
	go func() {
		for {
			if _, err := la["svc"].Accept(); err != nil {
				close(dead)
				return
			}
		}
	}()
	select {
	case <-dead:
	case <-time.After(5 * time.Second):
		t.Fatal("evicted session's listener still accepting after takeover")
	}
}

// TestTakeoverNeverEvictsForForeignPorts: a port held by another PROCESS (not a
// relay session) must still fail honestly — takeover can only reclaim what the
// relay itself holds.
func TestTakeoverNeverEvictsForForeignPorts(t *testing.T) {
	dial, _, _, cleanup := relayHarness(t)
	defer cleanup()

	// Hold the WILDCARD address, like a real squatter (nginx on :443) — on BSD
	// a specific-address holder would legally coexist with the relay's :port.
	hold, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	port := hold.Addr().(*net.TCPAddr).Port

	s := dial()
	defer s.Close()
	_, binds, err := s.Bind(context.Background(), []protocol.PortSpec{{Name: "svc", Port: port, Proto: "tcp"}})
	if err != nil {
		t.Fatalf("bind call: %v", err)
	}
	if binds[0].OK {
		t.Fatal("bind reported OK for a port held by a foreign process")
	}
	if binds[0].Error == "" {
		t.Fatal("expected the foreign-holder bind error to be reported")
	}
	// The foreign holder must still own the port.
	if c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		c.Close()
	} else {
		t.Fatalf("foreign holder lost its port: %v", err)
	}
}

// TestHeartbeatReapsSilentSession: a session that PROMISES beats and then goes
// silent is reaped after ~3 intervals — its public port is released without
// waiting for the transport to notice the dead peer.
func TestHeartbeatReapsSilentSession(t *testing.T) {
	_, addr, ca, cleanup := relayHarness(t)
	defer cleanup()
	cliCert, _ := ca.IssueClientCert("mailnite-raw")
	cliTLS, _ := pki.ClientTLSConfig(ca.CertPEM, cliCert.CertPEM, cliCert.KeyPEM, "127.0.0.1")
	cli := valueclient.NewTLSClient(addr, cliTLS)
	if err := cli.ConnectContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	port := freeTCPPort(t)
	args, _ := protocol.Encode(protocol.SessionRequest{
		Version:      protocol.Version,
		Binds:        []protocol.PortSpec{{Name: "svc", Port: port, Proto: "tcp"}},
		HeartbeatSec: 1, // promise beats every second — then send none
	})
	put := make(chan value.Value)
	events, _, err := cli.Chat(context.Background(), protocol.FnSession, args, 16, put)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	first, ok := <-events
	if !ok {
		t.Fatal("no ready event")
	}
	var ready protocol.Event
	if err := protocol.Decode(first, &ready); err != nil || !ready.Binds[0].OK {
		t.Fatalf("bind not ready: %v %+v", err, ready)
	}

	// Silence. The relay must end the session (stream closes) within ~3s+slack.
	deadline := time.After(8 * time.Second)
	for {
		select {
		case _, open := <-events:
			if !open {
				goto reaped
			}
		case <-deadline:
			t.Fatal("silent session was not reaped")
		}
	}
reaped:
	// The public port must be free again.
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("port still held after reap: %v", err)
	}
	ln.Close()
	close(put)
}

// TestHeartbeatKeepsSessionAlive: beats re-arm the reaper — a session beating
// on schedule lives well past the silence window.
func TestHeartbeatKeepsSessionAlive(t *testing.T) {
	_, addr, ca, cleanup := relayHarness(t)
	defer cleanup()
	cliCert, _ := ca.IssueClientCert("mailnite-raw")
	cliTLS, _ := pki.ClientTLSConfig(ca.CertPEM, cliCert.CertPEM, cliCert.KeyPEM, "127.0.0.1")
	cli := valueclient.NewTLSClient(addr, cliTLS)
	if err := cli.ConnectContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	args, _ := protocol.Encode(protocol.SessionRequest{
		Version:      protocol.Version,
		Binds:        []protocol.PortSpec{{Name: "svc", Port: 0, Proto: "tcp"}},
		HeartbeatSec: 1, // window = 3s
	})
	put := make(chan value.Value)
	events, _, err := cli.Chat(context.Background(), protocol.FnSession, args, 16, put)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if _, ok := <-events; !ok {
		t.Fatal("no ready event")
	}

	// Beat every 500ms for 5s (past the 3s window) — the stream must stay open.
	stop := time.After(5 * time.Second)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			select {
			case put <- value.Utf8(protocol.Heartbeat):
			default:
				t.Fatal("relay stopped draining beats")
			}
		case _, open := <-events:
			if !open {
				t.Fatal("beating session was reaped")
			}
		case <-stop:
			close(put) // clean teardown
			return
		}
	}
}
