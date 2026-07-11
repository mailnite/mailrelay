/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package deploy pushes a mailrelay to a bare VDS over SSH: it ships the binary
// and the tunnel's CA + server certificate, grants the binary the one privilege
// it needs (binding ports below 1024), installs a systemd unit and starts it.
// The design goal is that the operator only ever has to provide an SSH login and
// a public IP — everything else (keys, certs, service) is generated here.
package deploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/xerrors"
)

// GenerateSSHKey creates an ed25519 SSH keypair. The private key (OpenSSH PEM) is
// what the installer authenticates with; the returned authorized-key line is what
// the operator adds to the VDS user's ~/.ssh/authorized_keys — the only manual
// step the whole flow asks of them.
func GenerateSSHKey(comment string) (privatePEM []byte, authorizedKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return pem.EncodeToMemory(blk), line, nil
}

// Options describes the target host and what to install.
type Options struct {
	Host string // public IP or domain of the VDS
	Port int    // SSH port (default 22)
	User string // SSH user; "root" or a sudoer

	PrivateKeyPEM []byte // SSH auth key (preferred)
	Password      string // or a password (also used for sudo -S when User != root)

	// HostKey, if set, is the expected server host key (authorized_keys form); the
	// connection is rejected on mismatch. Empty means trust-on-first-use: the key
	// is accepted and its fingerprint reported in the log for the operator to note.
	HostKey string

	BinaryPath []byte            // the mailrelay binary bytes to ship
	RemoteDir  string            // install dir (default /opt/mailrelay)
	Files      map[string][]byte // extra files to drop in RemoteDir (ca.pem, relay.crt, relay.key)
	ServeArgs  string            // arguments appended to `mailrelay serve`

	// PrivilegedPorts grants the binary the ability to bind ports < 1024. Setcap
	// is the least-privilege choice (capability on the file); Sysctl flips the
	// host-wide unprivileged-port floor instead, for kernels where setcap is
	// unavailable.
	PrivilegedPorts bool
	Sysctl          bool
}

// Deploy connects and installs, returning a human-readable transcript of every
// remote step (also on error, so a partial failure is diagnosable).
func Deploy(ctx context.Context, o Options) (string, error) {
	if o.Port == 0 {
		o.Port = 22
	}
	if o.RemoteDir == "" {
		o.RemoteDir = "/opt/mailrelay"
	}
	var log bytes.Buffer

	auth, err := authMethods(o)
	if err != nil {
		return "", err
	}
	hostKeyCb, noteFP := hostKeyCallback(o.HostKey)

	client, err := dial(ctx, o, auth, hostKeyCb)
	if err != nil {
		return log.String(), xerrors.Errorf("ssh dial %s: %w", o.Host, err)
	}
	defer client.Close()
	if fp := noteFP(); fp != "" {
		fmt.Fprintf(&log, "host key %s (trust-on-first-use)\n", fp)
	}

	bin := o.RemoteDir + "/mailrelay"
	steps := []struct {
		desc string
		run  func() error
	}{
		{"create install dir", func() error { return run(client, o, &log, "mkdir -p "+shellQuote(o.RemoteDir)) }},
		{"upload binary", func() error { return upload(client, o, &log, bin, o.BinaryPath, "0755") }},
		{"upload config", func() error { return uploadFiles(client, o, &log, o.RemoteDir) }},
		{"privileged ports", func() error { return grantPorts(client, o, &log, bin) }},
		{"install service", func() error { return installService(client, o, &log, bin) }},
		{"start service", func() error { return startService(client, o, &log) }},
	}
	for _, s := range steps {
		fmt.Fprintf(&log, "==> %s\n", s.desc)
		if err := s.run(); err != nil {
			return log.String(), xerrors.Errorf("%s: %w", s.desc, err)
		}
	}
	fmt.Fprintln(&log, "==> done")
	return log.String(), nil
}

func authMethods(o Options) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(o.PrivateKeyPEM) > 0 {
		signer, err := ssh.ParsePrivateKey(o.PrivateKeyPEM)
		if err != nil {
			return nil, xerrors.Errorf("parse deploy key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if o.Password != "" {
		methods = append(methods, ssh.Password(o.Password))
	}
	if len(methods) == 0 {
		return nil, xerrors.New("no SSH credentials: provide a private key or a password")
	}
	return methods, nil
}

// hostKeyCallback pins the expected key when provided, else accepts the first key
// seen and exposes its fingerprint through the returned accessor.
func hostKeyCallback(expected string) (ssh.HostKeyCallback, func() string) {
	var seen string
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if expected != "" {
			if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expected)); err == nil {
				if ssh.FingerprintSHA256(pub) != fp {
					return xerrors.Errorf("host key mismatch: got %s", fp)
				}
				return nil
			}
			return xerrors.New("could not parse expected host key")
		}
		seen = fp
		return nil
	}
	return cb, func() string { return seen }
}

func dial(ctx context.Context, o Options, auth []ssh.AuthMethod, cb ssh.HostKeyCallback) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            o.User,
		Auth:            auth,
		HostKeyCallback: cb,
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// run executes one remote command, streaming its output into the transcript.
// Commands are wrapped with sudo when the login is not root.
func run(client *ssh.Client, o Options, log *bytes.Buffer, cmd string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	full := maybeSudo(o, cmd)
	sess.Stdout = log
	sess.Stderr = log
	if err := sess.Run(full); err != nil {
		return xerrors.Errorf("remote `%s`: %w", cmd, err)
	}
	return nil
}

// upload streams data to a remote path with the given octal mode.
func upload(client *ssh.Client, o Options, log *bytes.Buffer, path string, data []byte, mode string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	sess.Stdout = log
	sess.Stderr = log
	// tee to the file (sudo-aware), then set the mode.
	cmd := maybeSudo(o, "tee "+shellQuote(path)+" > /dev/null") + " && " + maybeSudo(o, "chmod "+mode+" "+shellQuote(path))
	if err := sess.Run(cmd); err != nil {
		return xerrors.Errorf("upload %s: %w", path, err)
	}
	fmt.Fprintf(log, "wrote %s (%d bytes)\n", path, len(data))
	return nil
}

func uploadFiles(client *ssh.Client, o Options, log *bytes.Buffer, dir string) error {
	for name, data := range o.Files {
		mode := "0644"
		if strings.HasSuffix(name, ".key") {
			mode = "0600"
		}
		if err := upload(client, o, log, dir+"/"+name, data, mode); err != nil {
			return err
		}
	}
	return nil
}

func grantPorts(client *ssh.Client, o Options, log *bytes.Buffer, bin string) error {
	if !o.PrivilegedPorts {
		fmt.Fprintln(log, "skipped (no ports below 1024 requested)")
		return nil
	}
	if o.Sysctl {
		conf := "net.ipv4.ip_unprivileged_port_start=0\n"
		if err := upload(client, o, log, "/etc/sysctl.d/15-mailrelay-unprivileged.conf", []byte(conf), "0644"); err != nil {
			return err
		}
		return run(client, o, log, "sysctl --system")
	}
	return run(client, o, log, "setcap cap_net_bind_service=+eip "+shellQuote(bin))
}

func installService(client *ssh.Client, o Options, log *bytes.Buffer, bin string) error {
	unit := fmt.Sprintf(`[Unit]
Description=Mailnite reverse relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s serve %s
Restart=always
RestartSec=3
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, bin, o.ServeArgs)
	if err := upload(client, o, log, "/etc/systemd/system/mailrelay.service", []byte(unit), "0644"); err != nil {
		return err
	}
	return run(client, o, log, "systemctl daemon-reload")
}

func startService(client *ssh.Client, o Options, log *bytes.Buffer) error {
	return run(client, o, log, "systemctl enable --now mailrelay.service")
}

// maybeSudo prefixes sudo when the login is not root, feeding the password to
// sudo -S when one is available.
func maybeSudo(o Options, cmd string) string {
	if o.User == "root" {
		return cmd
	}
	if o.Password != "" {
		return "echo " + shellQuote(o.Password) + " | sudo -S -p '' sh -c " + shellQuote(cmd)
	}
	return "sudo sh -c " + shellQuote(cmd)
}

// shellQuote single-quotes a string for safe use in a remote shell command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
