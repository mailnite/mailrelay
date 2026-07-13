/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relay

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mailnite/mailrelay/pki"
	"github.com/mailnite/mailrelay/protocol"
	"go.arpabet.com/value"
	valuequic "go.arpabet.com/value-rpc/quic"
	"go.arpabet.com/value-rpc/valuerpc"
	"go.arpabet.com/value-rpc/valueserver"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// Config is everything the relay needs to serve the tunnel on a VDS.
type Config struct {
	Transport string // tcp | ws | quic (protocol.Transport*; tls = legacy alias of tcp)
	BindAddr  string // host:port the relay listens on, e.g. 0.0.0.0:8443
	Path      string // ws only: the upgrade path (default /relay)

	CAPEM   []byte // the tunnel CA (pins the mailnite client cert for tcp/quic)
	CertPEM []byte // the relay's server certificate
	KeyPEM  []byte // the relay's server private key

	// Token, when set, must be presented by mailnite in the handshake and echoed
	// in the session request. It is the client-auth factor for ws (whose TLS is
	// server-authenticated only); optional belt-and-braces for tcp/quic.
	Token string

	// Version and Build identify this relay binary; reported to a connected
	// mailnite over the info RPC so its dashboard can show the relay it tunnels
	// through. Empty is fine (shown as unknown).
	Version string
	Build   string
}

// ConfigSource supplies the relay Server bean its configuration. The serve
// command implements it (CLI flags are the configuration source there), so the
// config flows to the server through injection like every other dependency.
type ConfigSource interface {
	RelayConfig() (Config, error)
}

// StaticConfig adapts an in-hand Config to a ConfigSource, for embedders and
// tests that construct the server without a container.
type StaticConfig Config

func (c StaticConfig) RelayConfig() (Config, error) { return Config(c), nil }

// Server is the relay server as a glue bean: dependencies are injected, the
// configuration is pulled from the injected ConfigSource, validation happens in
// PostConstruct (fail at wiring time), and Destroy guarantees the public ports
// and sessions are released when the container that owns the bean closes —
// even if the caller's teardown path never runs.
//
// Lifecycle: PostConstruct → Serve(ctx) (blocking, once) → Shutdown/Destroy.
type Server struct {
	Log    *zap.Logger  `inject:""`
	Source ConfigSource `inject:""`

	cfg Config
	tun *Tunnel

	mu      sync.Mutex
	cancel  context.CancelFunc // cancels a running Serve
	addr    net.Addr           // control address once Serve bound it
	stopped bool
}

// NewServer creates the bean; the container (or the Serve helper) wires and
// initializes it.
func NewServer() *Server { return &Server{} }

// PostConstruct resolves and validates the configuration and builds the tunnel.
// The listening socket is not bound here — bind errors belong to Serve, where
// the command reports them as command failures rather than wiring failures.
func (t *Server) PostConstruct() error {
	cfg, err := t.Source.RelayConfig()
	if err != nil {
		return err
	}
	if cfg.Path == "" {
		cfg.Path = "/relay"
	}
	// Key-authenticated ("just a key") mode: no server certificate supplied, so
	// generate a self-signed one and rely on the shared token for client auth.
	if len(cfg.CertPEM) == 0 {
		if cfg.Token == "" {
			return xerrors.New("provide a token (key-authenticated mode) or a cert/key (mutual TLS)")
		}
		kp, err := pki.GenerateSelfSigned(nil)
		if err != nil {
			return err
		}
		cfg.CertPEM, cfg.KeyPEM, cfg.CAPEM = kp.CertPEM, kp.KeyPEM, nil
		t.Log.Info("RelaySelfSigned", zap.String("mode", "key-authenticated"))
	}
	switch tr := protocol.NormalizeTransport(cfg.Transport); tr {
	case protocol.TransportTCP, protocol.TransportQUIC:
	case protocol.TransportWS:
		if cfg.Token == "" {
			return xerrors.New("ws transport requires a token (its TLS cannot authenticate the client)")
		}
	default:
		return xerrors.Errorf("unknown transport %q (want tcp, ws or quic)", cfg.Transport)
	}
	// Refuse to run wide open: without a CA (mutual TLS) and without a token
	// there is nothing authenticating clients, and anyone could bind this VDS's
	// public ports through the relay.
	if len(cfg.CAPEM) == 0 && cfg.Token == "" {
		return xerrors.New("no client authentication configured: provide --ca (mutual TLS) and/or --token")
	}
	t.cfg = cfg
	t.tun = New(t.Log, cfg.Token)
	t.tun.SetInfo(cfg.Version, cfg.Build)
	return nil
}

// sessionRetention bounds how long the value-rpc layer keeps a DISCONNECTED
// client's session alive for a transport reconnect. The default (2 minutes) is
// tuned for ordinary RPC state; here a session holds this VDS's PUBLIC MAIL
// PORTS, and the mailnite supervisor never resumes a dead session — it always
// dials a fresh one and rebinds. Every second of retention is therefore a
// second a crashed/redeployed mailnite's zombie session keeps :25/:443/:465
// bound, answering EADDRINUSE to its own successor. Keep it just long enough
// to ride out a genuine transport blip.
const sessionRetention = 10 * time.Second

// Serve binds the configured transport and runs the relay until ctx is
// cancelled or Shutdown/Destroy is called. It always releases the tunnel's
// public listeners and sessions on the way out.
func (t *Server) Serve(ctx context.Context) error {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return xerrors.New("relay server is shut down")
	}
	ctx, cancel := context.WithCancel(ctx)
	t.cancel = cancel
	t.mu.Unlock()
	defer cancel()
	defer t.Shutdown()

	switch protocol.NormalizeTransport(t.cfg.Transport) {
	case protocol.TransportTCP:
		tlsCfg, err := pki.ServerTLSConfig(t.cfg.CertPEM, t.cfg.KeyPEM, t.cfg.CAPEM)
		if err != nil {
			return err
		}
		srv, err := valueserver.NewTLSServer(t.cfg.BindAddr, tlsCfg, t.Log,
			valueserver.WithSessionRetention(sessionRetention))
		if err != nil {
			return err
		}
		t.setBoundAddr(srv.Addr())
		return t.serveVRPC(ctx, srv)

	case protocol.TransportQUIC:
		tlsCfg, err := pki.ServerTLSConfig(t.cfg.CertPEM, t.cfg.KeyPEM, t.cfg.CAPEM)
		if err != nil {
			return err
		}
		// valuequic.NewServer does not plumb server options; compose the listener
		// and server directly so the session retention applies here too.
		lis, err := valuequic.NewListener(t.cfg.BindAddr, tlsCfg, valueserver.DefaultTimeout)
		if err != nil {
			return err
		}
		srv, err := valueserver.NewServerWithListener(lis, t.Log,
			valueserver.WithSessionRetention(sessionRetention))
		if err != nil {
			return err
		}
		t.setBoundAddr(srv.Addr())
		return t.serveVRPC(ctx, srv)

	default: // protocol.TransportWS, validated in PostConstruct
		return t.serveWSS(ctx)
	}
}

// BoundAddr reports the control address Serve bound, or nil before the bind —
// how an embedder (or test) binding ":0" learns the actual port.
func (t *Server) BoundAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addr
}

func (t *Server) setBoundAddr(a net.Addr) {
	t.mu.Lock()
	t.addr = a
	t.mu.Unlock()
}

// Shutdown stops a running Serve and tears every session down. Idempotent and
// safe from any goroutine.
func (t *Server) Shutdown() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	cancel := t.cancel
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if t.tun != nil {
		t.tun.Close()
	}
}

// Destroy implements glue.DisposableBean: closing the container that owns the
// server is the guaranteed release of the VDS's public ports.
func (t *Server) Destroy() error {
	t.Shutdown()
	return nil
}

// Serve runs a relay for cfg until ctx is cancelled — the plain-function entry
// point for embedders and tests that do not run a container.
func Serve(ctx context.Context, cfg Config, log *zap.Logger) error {
	srv := NewServer()
	srv.Log = log
	srv.Source = StaticConfig(cfg)
	if err := srv.PostConstruct(); err != nil {
		return err
	}
	defer srv.Shutdown()
	return srv.Serve(ctx)
}

// serveVRPC wires auth + handlers on a value-rpc server (tcp/quic) and runs it.
func (t *Server) serveVRPC(ctx context.Context, srv valueserver.Server) error {
	if t.cfg.Token != "" {
		srv.SetAuthenticator(tokenAuth(t.cfg.Token))
	}
	if err := t.tun.Register(srv); err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Run() }()
	t.Log.Info("RelayServing", zap.String("transport", t.cfg.Transport), zap.String("bind", t.cfg.BindAddr))
	select {
	case <-ctx.Done():
		return srv.Close()
	case err := <-errc:
		return err
	}
}

// serveWSS serves the tunnel over wss on the relay's own TLS http.Server. The
// TLS here is server-authenticated (the relay cert); the mailnite client is
// authenticated by the handshake token, since the value-rpc WebSocket client
// dials with the system roots and cannot present a client certificate.
func (t *Server) serveWSS(ctx context.Context) error {
	tlsCfg, err := pki.ServerTLSConfig(t.cfg.CertPEM, t.cfg.KeyPEM, nil)
	if err != nil {
		return err
	}
	srv, handler, err := valueserver.NewWebSocketHandler(t.Log,
		valueserver.WithSessionRetention(sessionRetention))
	if err != nil {
		return err
	}
	srv.SetAuthenticator(tokenAuth(t.cfg.Token))
	if err := t.tun.Register(srv); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", t.cfg.BindAddr)
	if err != nil {
		return err
	}
	t.setBoundAddr(ln.Addr())

	mux := http.NewServeMux()
	mux.Handle(t.cfg.Path, handler)
	httpSrv := &http.Server{
		Handler:   mux,
		TLSConfig: tlsCfg,
		// The only legitimate request is a websocket upgrade, whose headers
		// arrive immediately — cut off slow-header (slowloris) connections.
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 2)
	go func() { errc <- srv.Run() }()
	go func() {
		// Certs come from TLSConfig, so the file arguments are empty.
		if e := httpSrv.ServeTLS(ln, "", ""); e != nil && e != http.ErrServerClosed {
			errc <- e
		}
	}()
	t.Log.Info("RelayServing", zap.String("transport", "ws"), zap.String("bind", t.cfg.BindAddr), zap.String("path", t.cfg.Path))

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	_ = srv.Close()
	return err
}

// tokenAuth validates the handshake credential against the configured token in
// constant time (like the session-level check), so the comparison cannot be
// used as a timing oracle against the shared key.
func tokenAuth(token string) valueserver.Authenticator {
	return func(_ valuerpc.MsgConn, credential value.Value) (string, error) {
		if credential == nil || credential.Kind() != value.STRING {
			return "", xerrors.New("relay token required")
		}
		presented := credential.(value.String).String()
		if subtle.ConstantTimeCompare([]byte(presented), []byte(token)) != 1 {
			return "", xerrors.New("invalid relay token")
		}
		return "mailnite", nil
	}
}
