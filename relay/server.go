/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relay

import (
	"context"
	"net/http"
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
	Transport string // tls | ws | quic (protocol.Transport*)
	BindAddr  string // host:port the relay listens on, e.g. 0.0.0.0:8443
	Path      string // ws only: the upgrade path (default /relay)

	CAPEM   []byte // the tunnel CA (pins the mailnite client cert for tls/quic)
	CertPEM []byte // the relay's server certificate
	KeyPEM  []byte // the relay's server private key

	// Token, when set, must be presented by mailnite in the handshake and echoed
	// in the session request. It is the client-auth factor for ws (whose TLS is
	// server-authenticated only); optional belt-and-braces for tls/quic.
	Token string
}

// Serve runs the relay until ctx is cancelled. The transport is chosen at
// runtime so one binary covers all three deployments.
func Serve(ctx context.Context, cfg Config, log *zap.Logger) error {
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
		log.Info("RelaySelfSigned", zap.String("mode", "key-authenticated"))
	}
	tun := New(log, cfg.Token)
	defer tun.Close()

	switch protocol.NormalizeTransport(cfg.Transport) {
	case protocol.TransportTCP:
		tlsCfg, err := pki.ServerTLSConfig(cfg.CertPEM, cfg.KeyPEM, cfg.CAPEM)
		if err != nil {
			return err
		}
		srv, err := valueserver.NewTLSServer(cfg.BindAddr, tlsCfg, log)
		if err != nil {
			return err
		}
		return serveVRPC(ctx, srv, tun, cfg, log)

	case protocol.TransportQUIC:
		tlsCfg, err := pki.ServerTLSConfig(cfg.CertPEM, cfg.KeyPEM, cfg.CAPEM)
		if err != nil {
			return err
		}
		srv, err := valuequic.NewServer(cfg.BindAddr, tlsCfg, log)
		if err != nil {
			return err
		}
		return serveVRPC(ctx, srv, tun, cfg, log)

	case protocol.TransportWS:
		return serveWSS(ctx, cfg, tun, log)

	default:
		return xerrors.Errorf("unknown transport %q (want tls, ws or quic)", cfg.Transport)
	}
}

// serveVRPC wires auth + handlers on a value-rpc server (tls/quic) and runs it.
func serveVRPC(ctx context.Context, srv valueserver.Server, tun *Tunnel, cfg Config, log *zap.Logger) error {
	if cfg.Token != "" {
		srv.SetAuthenticator(tokenAuth(cfg.Token))
	}
	if err := tun.Register(srv); err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Run() }()
	log.Info("RelayServing", zap.String("transport", cfg.Transport), zap.String("bind", cfg.BindAddr))
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
func serveWSS(ctx context.Context, cfg Config, tun *Tunnel, log *zap.Logger) error {
	if cfg.Token == "" {
		return xerrors.New("ws transport requires a token (its TLS cannot authenticate the client)")
	}
	tlsCfg, err := pki.ServerTLSConfig(cfg.CertPEM, cfg.KeyPEM, nil)
	if err != nil {
		return err
	}
	srv, handler, err := valueserver.NewWebSocketHandler(log)
	if err != nil {
		return err
	}
	srv.SetAuthenticator(tokenAuth(cfg.Token))
	if err := tun.Register(srv); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Path, handler)
	httpSrv := &http.Server{Addr: cfg.BindAddr, Handler: mux, TLSConfig: tlsCfg}

	errc := make(chan error, 2)
	go func() { errc <- srv.Run() }()
	go func() {
		// Certs come from TLSConfig, so the file arguments are empty.
		if e := httpSrv.ListenAndServeTLS("", ""); e != nil && e != http.ErrServerClosed {
			errc <- e
		}
	}()
	log.Info("RelayServing", zap.String("transport", "ws"), zap.String("bind", cfg.BindAddr), zap.String("path", cfg.Path))

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

// tokenAuth validates the handshake credential against the configured token.
func tokenAuth(token string) valueserver.Authenticator {
	return func(_ valuerpc.MsgConn, credential value.Value) (string, error) {
		if credential == nil || credential.Kind() != value.STRING {
			return "", xerrors.New("relay token required")
		}
		if credential.(value.String).String() != token {
			return "", xerrors.New("invalid relay token")
		}
		return "mailnite", nil
	}
}
