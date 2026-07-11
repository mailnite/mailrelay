/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mailnite/mailrelay/relay"
	"go.arpabet.com/cligo"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// ServeCommand runs the relay on the VDS. It is the only long-lived command; the
// rest of the CLI is one-shot key/cert/deploy tooling.
type ServeCommand struct {
	Parent cligo.CliGroup `cli:"group=cli"`
	Log    *zap.Logger    `inject:""`

	Transport string `cli:"option=transport,default=tcp,env=MAILRELAY_TRANSPORT,help=transport the tunnel rides: tcp | ws | quic (all under TLS; tls accepted as a legacy alias of tcp)"`
	Bind      string `cli:"option=bind,default=0.0.0.0:8443,env=MAILRELAY_BIND,help=host:port the relay listens on"`
	Path      string `cli:"option=path,default=/relay,env=MAILRELAY_PATH,help=ws upgrade path"`

	CACert    string `cli:"option=ca,default=,env=MAILRELAY_CA,help=tunnel CA certificate PEM (tls/quic mutual TLS)"`
	Cert      string `cli:"option=cert,default=,env=MAILRELAY_CERT,help=relay server certificate PEM"`
	Key       string `cli:"option=key,default=,env=MAILRELAY_KEY,help=relay server private key PEM"`
	Token     string `cli:"option=token,default=,env=MAILRELAY_TOKEN,help=handshake token (required for ws)"`
	TokenFile string `cli:"option=token-file,default=,env=MAILRELAY_TOKEN_FILE,help=file containing the handshake token"`
}

func (t *ServeCommand) Command() string { return "serve" }

func (t *ServeCommand) Help() (string, string) {
	return "run the relay: bind public ports on this VDS and tunnel them to mailnite", ""
}

func (t *ServeCommand) Run(ctx context.Context) error {
	cfg := relay.Config{
		Transport: t.Transport,
		BindAddr:  t.Bind,
		Path:      t.Path,
	}
	var err error
	if cfg.Token, err = resolveToken(t.Token, t.TokenFile); err != nil {
		return err
	}
	// Two modes: with --cert/--key the relay presents that certificate and (with
	// --ca) enforces mutual TLS; without them it runs key-authenticated — a
	// self-signed cert plus the shared --token, which is the simple default.
	if t.Cert != "" && t.Key != "" {
		if cfg.CertPEM, err = os.ReadFile(t.Cert); err != nil {
			return xerrors.Errorf("read cert: %w", err)
		}
		if cfg.KeyPEM, err = os.ReadFile(t.Key); err != nil {
			return xerrors.Errorf("read key: %w", err)
		}
		if t.CACert != "" {
			if cfg.CAPEM, err = os.ReadFile(t.CACert); err != nil {
				return xerrors.Errorf("read ca: %w", err)
			}
		}
	} else if cfg.Token == "" {
		return xerrors.New("provide --token (key-authenticated mode) or --cert/--key (mutual TLS)")
	}

	// Translate SIGINT/SIGTERM into ctx cancellation so systemd stop / Ctrl-C
	// unbinds the ports cleanly.
	sctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	t.Log.Info("RelayStart", zap.String("transport", cfg.Transport), zap.String("bind", cfg.BindAddr))
	return relay.Serve(sctx, cfg, t.Log)
}

func resolveToken(token, tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", xerrors.Errorf("read token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(token), nil
}
