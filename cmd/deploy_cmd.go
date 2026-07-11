/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/mailnite/mailrelay/deploy"
	"go.arpabet.com/cligo"
	"golang.org/x/xerrors"
)

// DeployCommand ships a locally-built relay binary and the tunnel certificates
// to a VDS over SSH and starts it as a service. It is the scriptable form of the
// onboarding "provision my relay" button: give it an SSH login, a public
// address and the cert bundle, and the VDS is serving the tunnel.
type DeployCommand struct {
	Parent cligo.CliGroup `cli:"group=cli"`

	Host          string `cli:"option=host,default=,help=VDS public IP or domain"`
	Port          int    `cli:"option=port,default=22,help=SSH port"`
	User          string `cli:"option=user,default=root,help=SSH user (root or a sudoer)"`
	SSHKey        string `cli:"option=ssh-key,default=,help=SSH private key file; default: ssh-agent then ~/.ssh/id_*"`
	KeyPassphrase string `cli:"option=ssh-key-passphrase,default=,help=passphrase for an encrypted --ssh-key"`
	Password      string `cli:"option=password,default=,help=SSH/sudo password (fallback; key auth is preferred)"`
	NoAgent       bool   `cli:"option=no-agent,help=do not use ssh-agent even if SSH_AUTH_SOCK is set"`
	NoDefaultKeys bool   `cli:"option=no-default-keys,help=do not fall back to ~/.ssh/id_* identity files"`
	HostKey       string `cli:"option=host-key,default=,help=expected SSH host key (authorized_keys form); empty = trust on first use"`
	Binary        string `cli:"option=binary,default=mailrelay,help=path to the linux mailrelay binary to ship"`
	RemoteDir     string `cli:"option=remote-dir,default=/opt/mailrelay,help=install directory on the VDS"`

	Transport  string `cli:"option=transport,default=tcp,help=transport the tunnel rides: tcp | ws | quic (tls accepted as a legacy alias of tcp)"`
	Bind       string `cli:"option=bind,default=0.0.0.0:8443,help=address the relay listens on"`
	Path       string `cli:"option=path,default=/relay,help=ws upgrade path"`
	CACert     string `cli:"option=ca,default=ca.crt,help=tunnel CA cert PEM"`
	Cert       string `cli:"option=cert,default=relay.crt,help=relay server cert PEM"`
	Key        string `cli:"option=key,default=relay.key,help=relay server key PEM"`
	Token      string `cli:"option=token-file,default=,help=handshake token file (ws)"`
	Privileged bool   `cli:"option=privileged,help=grant the binary the ability to bind ports below 1024 (mail needs 25/465/993)"`
	Sysctl     bool   `cli:"option=sysctl,help=use the unprivileged-port sysctl instead of setcap"`
}

func (t *DeployCommand) Command() string { return "deploy" }

func (t *DeployCommand) Help() (string, string) {
	return "deploy the relay to a VDS over SSH and start it", ""
}

func (t *DeployCommand) Run(ctx context.Context) error {
	if t.Host == "" {
		return xerrors.New("--host is required")
	}
	bin, err := os.ReadFile(t.Binary)
	if err != nil {
		return xerrors.Errorf("read relay binary %q: %w", t.Binary, err)
	}
	files, serveArgs, err := t.deployPlan()
	if err != nil {
		return err
	}

	opts := deploy.Options{
		Host:            t.Host,
		Port:            t.Port,
		User:            t.User,
		Password:        t.Password,
		NoAgent:         t.NoAgent,
		NoDefaultKeys:   t.NoDefaultKeys,
		HostKey:         t.HostKey,
		BinaryPath:      bin,
		RemoteDir:       t.RemoteDir,
		Files:           files,
		ServeArgs:       serveArgs,
		PrivilegedPorts: t.Privileged,
		Sysctl:          t.Sysctl,
	}
	if t.SSHKey != "" {
		if opts.PrivateKeyPEM, err = os.ReadFile(t.SSHKey); err != nil {
			return xerrors.Errorf("read ssh key: %w", err)
		}
	}
	if t.KeyPassphrase != "" {
		opts.KeyPassphrase = []byte(t.KeyPassphrase)
	}

	log, err := deploy.Deploy(ctx, opts)
	fmt.Print(log)
	if err != nil {
		return err
	}
	fmt.Printf("\nrelay is running on %s — mailnite can now dial %s over %s\n", t.Host, t.Bind, t.Transport)
	return nil
}

// deployPlan resolves which files ship to the VDS and the `serve` arguments
// that reference them, mirroring serve's two modes: mutual TLS when the cert
// files are present, key-authenticated when only a token is. With a token, the
// cert flags' default filenames are allowed to be absent (a token-only deploy);
// a cert path that exists — or was explicitly required by having no token — is
// read and shipped.
func (t *DeployCommand) deployPlan() (map[string][]byte, string, error) {
	files := map[string][]byte{}
	certOptional := t.Token != "" // key-authenticated mode needs no cert bundle

	haveCA, err := addFile(files, "ca.pem", t.CACert, certOptional)
	if err != nil {
		return nil, "", err
	}
	haveCert, err := addFile(files, "relay.crt", t.Cert, certOptional)
	if err != nil {
		return nil, "", err
	}
	haveKey, err := addFile(files, "relay.key", t.Key, certOptional)
	if err != nil {
		return nil, "", err
	}
	if haveCert != haveKey {
		return nil, "", xerrors.Errorf("--cert and --key go together (%s without its pair)", t.Cert)
	}
	if !haveCert && t.Token == "" {
		return nil, "", xerrors.New("provide --token-file (key-authenticated mode) or --cert/--key (mutual TLS)")
	}
	if !haveCA && t.Token == "" {
		return nil, "", xerrors.New("a cert without --ca or a token would run an unauthenticated relay; ship the CA (mutual TLS) and/or a --token-file")
	}

	serveArgs := fmt.Sprintf("--transport %s --bind %s", t.Transport, t.Bind)
	if haveCA {
		serveArgs += fmt.Sprintf(" --ca %s/ca.pem", t.RemoteDir)
	}
	if haveCert {
		serveArgs += fmt.Sprintf(" --cert %s/relay.crt --key %s/relay.key", t.RemoteDir, t.RemoteDir)
	}
	if t.Token != "" {
		if _, err := addFile(files, "token", t.Token, false); err != nil {
			return nil, "", err
		}
		serveArgs += fmt.Sprintf(" --token-file %s/token", t.RemoteDir)
	}
	if t.Transport == "ws" {
		serveArgs += " --path " + t.Path
	}
	return files, serveArgs, nil
}

// addFile reads path into files under name. A missing file is tolerated when
// optional (reported as absent); any other read error is always fatal.
func addFile(files map[string][]byte, name, path string, optional bool) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return false, nil
		}
		return false, xerrors.Errorf("read %s: %w", path, err)
	}
	files[name] = data
	return true, nil
}
