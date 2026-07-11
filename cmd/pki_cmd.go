/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mailnite/mailrelay/deploy"
	"github.com/mailnite/mailrelay/pki"
	"go.arpabet.com/cligo"
	"golang.org/x/xerrors"
)

// GenCACommand creates the tunnel CA. In production onboarding does this in
// process; the command exists for manual setups and for tests.
type GenCACommand struct {
	Parent cligo.CliGroup `cli:"group=cli"`
	CN     string         `cli:"option=cn,default=Mailnite Relay CA,help=CA common name"`
	Out    string         `cli:"option=out,default=.,help=output directory"`
}

func (t *GenCACommand) Command() string { return "gen-ca" }
func (t *GenCACommand) Help() (string, string) {
	return "generate the tunnel certificate authority", ""
}

func (t *GenCACommand) Run(_ context.Context) error {
	ca, err := pki.GenerateCA(t.CN)
	if err != nil {
		return err
	}
	if err := writeFile(t.Out, "ca.crt", ca.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(t.Out, "ca.key", ca.KeyPEM, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", filepath.Join(t.Out, "ca.crt"), filepath.Join(t.Out, "ca.key"))
	fmt.Println("keep ca.key secret — it is the trust root for the whole tunnel")
	return nil
}

// GenCertsCommand issues the relay server cert, the mailnite client cert and a
// handshake token from an existing CA.
type GenCertsCommand struct {
	Parent      cligo.CliGroup `cli:"group=cli"`
	CACert      string         `cli:"option=ca-cert,default=ca.crt,help=CA certificate PEM"`
	CAKey       string         `cli:"option=ca-key,default=ca.key,help=CA private key PEM"`
	ServerHosts string         `cli:"option=hosts,default=,help=comma-separated DNS names/IPs the relay is reachable at"`
	ClientCN    string         `cli:"option=client-cn,default=mailnite,help=mailnite client certificate common name"`
	Out         string         `cli:"option=out,default=.,help=output directory"`
}

func (t *GenCertsCommand) Command() string { return "gen-certs" }
func (t *GenCertsCommand) Help() (string, string) {
	return "issue relay + mailnite certs and a token from the CA", ""
}

func (t *GenCertsCommand) Run(_ context.Context) error {
	if strings.TrimSpace(t.ServerHosts) == "" {
		return xerrors.New("--hosts is required (the address(es) mailnite will dial the relay at)")
	}
	caCertPEM, err := os.ReadFile(t.CACert)
	if err != nil {
		return xerrors.Errorf("read ca cert: %w", err)
	}
	caKeyPEM, err := os.ReadFile(t.CAKey)
	if err != nil {
		return xerrors.Errorf("read ca key: %w", err)
	}
	ca, err := pki.LoadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}

	hosts := splitCSV(t.ServerHosts)
	server, err := ca.IssueServerCert(hosts)
	if err != nil {
		return err
	}
	client, err := ca.IssueClientCert(t.ClientCN)
	if err != nil {
		return err
	}
	token, err := pki.RandomToken()
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"relay.crt":           server.CertPEM,
		"relay.key":           server.KeyPEM,
		"mailnite-client.crt": client.CertPEM,
		"mailnite-client.key": client.KeyPEM,
		"token":               []byte(token + "\n"),
	}
	for name, data := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") || name == "token" {
			mode = 0o600
		}
		if err := writeFile(t.Out, name, data, mode); err != nil {
			return err
		}
	}
	fmt.Printf("issued relay server cert for %v and a mailnite client cert in %s\n", hosts, t.Out)
	fmt.Printf("relay files:    ca.crt relay.crt relay.key token\n")
	fmt.Printf("mailnite files: ca.crt mailnite-client.crt mailnite-client.key token\n")
	return nil
}

// GenSSHKeyCommand creates the deploy SSH keypair and prints the public line the
// operator adds to the VDS, matching the onboarding "add this key" step.
type GenSSHKeyCommand struct {
	Parent  cligo.CliGroup `cli:"group=cli"`
	Comment string         `cli:"option=comment,default=mailnite-relay,help=key comment"`
	Out     string         `cli:"option=out,default=.,help=output directory"`
}

func (t *GenSSHKeyCommand) Command() string { return "gen-ssh-key" }
func (t *GenSSHKeyCommand) Help() (string, string) {
	return "generate the SSH keypair used to deploy the relay", ""
}

func (t *GenSSHKeyCommand) Run(_ context.Context) error {
	priv, pub, err := deploy.GenerateSSHKey(t.Comment)
	if err != nil {
		return err
	}
	if err := writeFile(t.Out, "id_ed25519", priv, 0o600); err != nil {
		return err
	}
	if err := writeFile(t.Out, "id_ed25519.pub", []byte(pub+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (private) and %s (public)\n\n", filepath.Join(t.Out, "id_ed25519"), filepath.Join(t.Out, "id_ed25519.pub"))
	fmt.Println("add this line to the VDS user's ~/.ssh/authorized_keys:")
	fmt.Printf("\n%s\n", pub)
	return nil
}

func writeFile(dir, name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), data, mode)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
