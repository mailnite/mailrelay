/*
 * Copyright 2022-present Mailnite LLC.
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
