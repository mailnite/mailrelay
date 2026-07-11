/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command mailrelay is the public-facing half of a mailnite deployment behind
// NAT. It runs on a cheap VDS that has only two things mailnite lacks there: a
// public IP and the ability to bind low ports. It stores no mail and terminates
// no application TLS — it binds the requested public ports and reverse-tunnels
// their raw bytes to a mailnite instance over a mutually-authenticated value-rpc
// connection that mailnite dials outbound.
//
// Subcommands:
//
//	mailrelay serve        run the relay (on the VDS)
//	mailrelay gen-ca       generate the tunnel certificate authority
//	mailrelay gen-certs    issue relay + mailnite certs and a token from the CA
//	mailrelay gen-ssh-key  generate the SSH keypair used to deploy
//	mailrelay deploy       ship the relay to a VDS over SSH and start it
package main

import (
	"github.com/mailnite/mailrelay/cmd"
	"go.arpabet.com/cligo"
	"go.arpabet.com/servion"
)

var (
	Version string
	Build   string
)

func main() {
	// Hand the ldflags-stamped version/build to the serve command so it can
	// report them to a connected mailnite over the info RPC (shown in the admin
	// dashboard beside mailnite's own version).
	cmd.Version, cmd.Build = Version, Build
	cligo.Main(
		cligo.Name("mailrelay"),
		cligo.Title("Mailnite reverse relay"),
		cligo.Version(Version),
		cligo.Build(Build),
		cligo.Beans(
			// A production zap logger, injected into the serve and ping commands
			// (and, through the serve command's child container, into the relay
			// server bean).
			servion.ZapLogFactory(false),
			&cmd.ServeCommand{},
			&cmd.PingCommand{},
			&cmd.GenCACommand{},
			&cmd.GenCertsCommand{},
			&cmd.GenSSHKeyCommand{},
			&cmd.DeployCommand{},
		),
	)
}
