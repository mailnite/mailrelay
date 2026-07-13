/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mailnite/mailrelay/protocol"
	"github.com/mailnite/mailrelay/relayclient"
	"go.arpabet.com/cligo"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// PingCommand dials a relay the way mailnite does and reports whether it is
// reachable and the token (or mutual-TLS bundle) authenticates — the CLI
// counterpart of the admin console's "Test connectivity". Use it to check a
// relay end to end without a full mailnite behind it.
type PingCommand struct {
	Parent cligo.CliGroup `cli:"group=cli"`
	Log    *zap.Logger    `inject:""`

	Addr       string `cli:"option=addr,default=127.0.0.1:8443,env=MAILRELAY_ADDR,help=relay control address to dial (host:port)"`
	Transport  string `cli:"option=transport,default=tcp,env=MAILRELAY_TRANSPORT,help=transport: tcp | ws | quic (tls = legacy alias of tcp)"`
	Path       string `cli:"option=path,default=/relay,help=ws upgrade path"`
	ServerName string `cli:"option=server-name,default=,help=expected relay cert SAN (tls/quic); defaults to the addr host"`

	Token     string `cli:"option=token,default=,env=MAILRELAY_TOKEN,help=handshake token (must match the relay)"`
	TokenFile string `cli:"option=token-file,default=,env=MAILRELAY_TOKEN_FILE,help=file with the handshake token"`

	CACert   string `cli:"option=ca,default=,help=tunnel CA cert PEM (mutual TLS); omit for key-authenticated mode"`
	Cert     string `cli:"option=cert,default=,help=client cert PEM (mutual TLS)"`
	Key      string `cli:"option=key,default=,help=client key PEM (mutual TLS)"`
	BindTest int    `cli:"option=bind-test,default=0,help=also open this public port on the relay to exercise the session, then release it"`
}

func (t *PingCommand) Command() string { return "ping" }

func (t *PingCommand) Help() (string, string) {
	return "dial a relay and check it is reachable and the token authenticates", ""
}

func (t *PingCommand) Run(ctx context.Context) error {
	cfg := relayclient.Config{
		Transport:  t.Transport,
		Addr:       t.Addr,
		Path:       t.Path,
		ServerName: t.ServerName,
	}
	var err error
	if cfg.Token, err = resolveToken(t.Token, t.TokenFile); err != nil {
		return err
	}
	// Mutual-TLS material is optional: with a CA the dial verifies the relay cert
	// and presents the client cert; without it, key-authenticated mode (the token
	// authenticates, the self-signed relay cert is not verified).
	if t.CACert != "" {
		if cfg.CAPEM, err = os.ReadFile(t.CACert); err != nil {
			return xerrors.Errorf("read ca: %w", err)
		}
	}
	if t.Cert != "" {
		if cfg.ClientCertPEM, err = os.ReadFile(t.Cert); err != nil {
			return xerrors.Errorf("read cert: %w", err)
		}
	}
	if t.Key != "" {
		if cfg.ClientKeyPEM, err = os.ReadFile(t.Key); err != nil {
			return xerrors.Errorf("read key: %w", err)
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	sess, err := relayclient.Dial(dialCtx, cfg, t.Log)
	if err != nil {
		return xerrors.Errorf("dial %s: %w", t.Addr, err)
	}
	defer sess.Close()

	if err := sess.Ping(dialCtx); err != nil {
		return xerrors.Errorf("ping %s (reachable, but the token may not match): %w", t.Addr, err)
	}

	transport := protocol.NormalizeTransport(t.Transport)
	if t.BindTest > 0 {
		_, binds, err := sess.Bind(dialCtx, []protocol.PortSpec{{Name: "ping-test", Port: t.BindTest, Proto: "tcp"}})
		if err != nil {
			return xerrors.Errorf("session bind test on :%d: %w", t.BindTest, err)
		}
		if len(binds) == 0 || !binds[0].OK {
			reason := "unknown"
			if len(binds) > 0 && binds[0].Error != "" {
				reason = binds[0].Error
			}
			return xerrors.Errorf("relay could not bind public port %d: %s", t.BindTest, reason)
		}
		fmt.Printf("✓ relay %s reachable and authenticated over %s; bound public port %s\n", t.Addr, transport, binds[0].PublicAddr)
		return nil
	}

	fmt.Printf("✓ relay %s reachable and authenticated over %s\n", t.Addr, transport)
	return nil
}
