/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package relayclient is the mailnite-side of the tunnel. mailnite imports it,
// dials its relay, and gets back a net.Listener per public port — so the mail and
// web servers keep calling Serve(listener) exactly as they do for a local
// net.Listen, and mailnite binds nothing on its own host. That is the whole point
// behind NAT: the listener's connections arrive over an OUTBOUND value-rpc
// connection to the relay, so mailnite needs no inbound reachability at all.
package relayclient

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/mailnite/mailrelay/pki"
	"github.com/mailnite/mailrelay/protocol"
	"go.arpabet.com/value"
	valuequic "go.arpabet.com/value-rpc/quic"
	"go.arpabet.com/value-rpc/valueclient"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// Config tells the client how to reach and authenticate to the relay.
type Config struct {
	Transport  string // tls | ws | quic
	Addr       string // host:port of the relay (the VDS public IP/domain)
	Path       string // ws only: upgrade path (default /relay)
	ServerName string // expected relay cert SAN (tls/quic); defaults to Addr's host

	CAPEM         []byte // the tunnel CA (to verify the relay)
	ClientCertPEM []byte // mailnite's client cert (mTLS for tls/quic)
	ClientKeyPEM  []byte // mailnite's client key
	Token         string // handshake token (required for ws)
}

// Session is a live tunnel: the value-rpc connection to the relay plus the
// listeners it is serving.
type Session struct {
	cfg  Config
	log  *zap.Logger
	cli  valueclient.Client
	ctl  chan value.Value // session control channel; closed on Close (relay teardown)
	once sync.Once

	mu        sync.Mutex
	listeners map[string]*reverseListener
}

// Dial builds the value-rpc client for the configured transport and connects.
func Dial(ctx context.Context, cfg Config, log *zap.Logger) (*Session, error) {
	if cfg.Path == "" {
		cfg.Path = "/relay"
	}
	cli, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Token != "" {
		cli.SetCredential(value.Utf8(cfg.Token))
	}
	if err := cli.ConnectContext(ctx); err != nil {
		return nil, xerrors.Errorf("dial relay %s: %w", cfg.Addr, err)
	}
	return &Session{cfg: cfg, log: log, cli: cli, listeners: make(map[string]*reverseListener)}, nil
}

func newClient(cfg Config) (valueclient.Client, error) {
	switch protocol.NormalizeTransport(cfg.Transport) {
	case protocol.TransportTCP:
		tlsCfg, err := clientTLS(cfg)
		if err != nil {
			return nil, err
		}
		return valueclient.NewTLSClient(cfg.Addr, tlsCfg), nil
	case protocol.TransportQUIC:
		tlsCfg, err := clientTLS(cfg)
		if err != nil {
			return nil, err
		}
		return valuequic.NewClient(cfg.Addr, tlsCfg), nil
	case protocol.TransportWS:
		if cfg.Token == "" {
			return nil, xerrors.New("ws transport requires a token")
		}
		return valueclient.NewWebSocketClient("wss://" + cfg.Addr + cfg.Path), nil
	default:
		return nil, xerrors.Errorf("unknown transport %q", cfg.Transport)
	}
}

// clientTLS builds the tls.Config for the tls/quic transports. With no CA
// configured it is key-authenticated mode: the relay's self-signed certificate
// is not verified (the shared token authenticates, and the mail protocols keep
// their own end-to-end TLS through the tunnel). With a CA it is mutual TLS.
func clientTLS(cfg Config) (*tls.Config, error) {
	if len(cfg.CAPEM) == 0 {
		return &tls.Config{InsecureSkipVerify: true, ServerName: serverName(cfg), MinVersion: tls.VersionTLS12}, nil
	}
	return pki.ClientTLSConfig(cfg.CAPEM, cfg.ClientCertPEM, cfg.ClientKeyPEM, serverName(cfg))
}

func serverName(cfg Config) string {
	if cfg.ServerName != "" {
		return cfg.ServerName
	}
	if host, _, err := net.SplitHostPort(cfg.Addr); err == nil {
		return host
	}
	return cfg.Addr
}

// Bind asks the relay to open the given public ports and returns a net.Listener
// per successfully bound port, keyed by PortSpec.Name. A port that could not be
// bound (e.g. a privileged port lacking the capability) is absent from the map
// and described in the returned BindResults, so the caller can surface the exact
// remedy. The tunnel lives until Close (or the process exits).
func (s *Session) Bind(ctx context.Context, specs []protocol.PortSpec) (map[string]net.Listener, []protocol.BindResult, error) {
	s.ctl = make(chan value.Value)
	req, err := protocol.EncodeJSON(protocol.SessionRequest{
		Version: protocol.Version,
		Token:   s.cfg.Token,
		Binds:   specs,
	})
	if err != nil {
		return nil, nil, err
	}
	events, _, err := s.cli.Chat(ctx, protocol.FnSession, req, 64, s.ctl)
	if err != nil {
		return nil, nil, xerrors.Errorf("open session: %w", err)
	}

	first, ok := <-events
	if !ok {
		return nil, nil, xerrors.New("relay closed the session before it was ready")
	}
	var ready protocol.Event
	if err := protocol.DecodeJSON(first, &ready); err != nil {
		return nil, nil, err
	}
	if ready.Type != protocol.EventReady {
		return nil, nil, xerrors.Errorf("expected ready event, got %q", ready.Type)
	}

	out := make(map[string]net.Listener)
	s.mu.Lock()
	for _, b := range ready.Binds {
		if !b.OK {
			continue
		}
		l := newReverseListener(b.Name, protocol.Addr{Net: "tcp", Str: b.PublicAddr})
		s.listeners[b.Name] = l
		out[b.Name] = l
	}
	s.mu.Unlock()

	go s.pump(ctx, events)
	return out, ready.Binds, nil
}

// pump routes accept events into per-listener queues, opening a conn chat (the
// byte pipe) for each. It ends when the relay closes the event stream, at which
// point every listener is closed so the mail servers' Accept loops unwind.
func (s *Session) pump(ctx context.Context, events <-chan value.Value) {
	defer s.closeListeners()
	for ev := range events {
		var e protocol.Event
		if err := protocol.DecodeJSON(ev, &e); err != nil {
			continue
		}
		switch e.Type {
		case protocol.EventAccept:
			s.mu.Lock()
			l := s.listeners[e.Name]
			s.mu.Unlock()
			if l == nil {
				continue
			}
			conn, err := s.openConn(ctx, e.ConnID, e.Secret, e.RemoteAddr)
			if err != nil {
				s.log.Warn("RelayConnOpenFailed", zap.Int64("connId", e.ConnID), zap.Error(err))
				continue
			}
			l.deliver(conn)
		case protocol.EventError:
			s.log.Warn("RelayEvent", zap.String("message", e.Message))
		}
	}
}

// openConn opens the conn chat for one accepted connection and wraps it as a
// net.Conn carrying the public client's address. The secret proves this client
// owns the connection (the relay only sent it on this client's session stream).
func (s *Session) openConn(ctx context.Context, connID int64, secret, remoteAddr string) (net.Conn, error) {
	put := make(chan value.Value, 16)
	args, err := protocol.EncodeJSON(protocol.ConnArgs{ConnID: connID, Secret: secret})
	if err != nil {
		return nil, err
	}
	readC, _, err := s.cli.Chat(ctx, protocol.FnConn, args, 16, put)
	if err != nil {
		return nil, err
	}
	return protocol.NewChanConn(put, readC, protocol.Addr{Net: "tcp", Str: remoteAddr}), nil
}

// Ping verifies the relay is reachable and answering.
func (s *Session) Ping(ctx context.Context) error {
	_, err := s.cli.CallFunction(ctx, protocol.FnPing, value.Utf8(""))
	return err
}

// Close tears down the tunnel: closing the control channel tells the relay to
// drop the public listeners, then the local listeners are closed and the
// connection shut.
func (s *Session) Close() error {
	s.once.Do(func() {
		if s.ctl != nil {
			close(s.ctl)
		}
		s.closeListeners()
		_ = s.cli.Close()
	})
	return nil
}

func (s *Session) closeListeners() {
	s.mu.Lock()
	ls := s.listeners
	s.listeners = make(map[string]*reverseListener)
	s.mu.Unlock()
	for _, l := range ls {
		_ = l.Close()
	}
}

// reverseListener is a net.Listener whose connections arrive from the relay.
type reverseListener struct {
	name     string
	addr     net.Addr
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

var _ net.Listener = (*reverseListener)(nil)

func newReverseListener(name string, addr net.Addr) *reverseListener {
	return &reverseListener{
		name:     name,
		addr:     addr,
		incoming: make(chan net.Conn, 64),
		closed:   make(chan struct{}),
	}
}

func (l *reverseListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *reverseListener) deliver(c net.Conn) {
	select {
	case l.incoming <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

func (l *reverseListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *reverseListener) Addr() net.Addr { return l.addr }
