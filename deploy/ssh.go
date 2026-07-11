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
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

	// SSH authentication. The preferred path is a private key; a password is a
	// fallback (and is also fed to sudo -S when User != root). authMethods tries,
	// in order: an explicit PrivateKeyPEM, then a running ssh-agent
	// (SSH_AUTH_SOCK), then the default ~/.ssh identity files — so `deploy --host X`
	// authenticates with the operator's existing key setup and no password at all.
	PrivateKeyPEM []byte // explicit SSH private key PEM (from --ssh-key)
	KeyPassphrase []byte // passphrase for an encrypted PrivateKeyPEM (optional)
	Password      string // password auth fallback / sudo credential
	NoAgent       bool   // do not consult ssh-agent even if SSH_AUTH_SOCK is set
	NoDefaultKeys bool   // do not fall back to ~/.ssh/id_* identity files

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

// authMethods assembles the SSH auth methods to offer, preferring public-key
// auth over a password. Order of preference:
//
//  1. an explicit private key (--ssh-key), passphrase-decrypted if needed;
//  2. a running ssh-agent (SSH_AUTH_SOCK) — the common "my key, no file" path;
//  3. the default ~/.ssh identity files (id_ed25519, id_ecdsa, id_rsa);
//  4. a password, if one was given, as a last-resort fallback.
//
// So a bare `deploy --host X` uses the operator's existing key setup with no
// password at all; a password is never required and only used if provided.
func authMethods(o Options) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	var notes []string // why the key paths didn't contribute, for a good final error

	if len(o.PrivateKeyPEM) > 0 {
		signer, err := parseKey(o.PrivateKeyPEM, o.KeyPassphrase)
		if err != nil {
			// An explicit key that won't parse is a hard error — the operator
			// named it, so silently falling through would hide their mistake.
			return nil, xerrors.Errorf("parse ssh key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if !o.NoAgent {
		if signers, err := agentSigners(); err != nil {
			notes = append(notes, "ssh-agent: "+err.Error())
		} else if len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		}
	}

	if !o.NoDefaultKeys {
		signers, note := defaultKeySigners(o.KeyPassphrase)
		if len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		}
		if note != "" {
			notes = append(notes, note)
		}
	}

	if o.Password != "" {
		methods = append(methods, ssh.Password(o.Password))
	}

	if len(methods) == 0 {
		msg := "no SSH credentials: pass --ssh-key, start an ssh-agent, put a key at ~/.ssh/id_ed25519, or pass --password"
		if len(notes) > 0 {
			msg += " (" + strings.Join(notes, "; ") + ")"
		}
		return nil, xerrors.New(msg)
	}
	return methods, nil
}

// parseKey parses a private key PEM, transparently handling passphrase-encrypted
// keys: it tries an unencrypted parse first, and only if the key is encrypted
// does it require (and use) the passphrase.
func parseKey(pemBytes, passphrase []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if xerrors.As(err, &missing) {
		if len(passphrase) == 0 {
			return nil, xerrors.New("key is passphrase-protected; supply --ssh-key-passphrase (or add it to your ssh-agent)")
		}
		return ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
	}
	return nil, err
}

// agentSigners returns the signers a running ssh-agent offers, or (nil, nil)
// when no agent is available. The agent connection is intentionally left open
// for the process lifetime: its signers sign lazily during the SSH handshake.
func agentSigners() ([]ssh.Signer, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	return agent.NewClient(conn).Signers()
}

// defaultKeySigners loads the standard ~/.ssh identity files, mirroring what the
// ssh client tries by default. Missing files are skipped silently; a file that
// exists but is encrypted without a supplied passphrase is skipped with a note
// (it may still be covered by the agent).
func defaultKeySigners(passphrase []byte) ([]ssh.Signer, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, ""
	}
	var signers []ssh.Signer
	var notes []string
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		path := filepath.Join(home, ".ssh", name)
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			continue // no such default key — normal
		}
		signer, err := parseKey(pemBytes, passphrase)
		if err != nil {
			notes = append(notes, name+": "+err.Error())
			continue
		}
		signers = append(signers, signer)
	}
	return signers, strings.Join(notes, "; ")
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
	full, stdin := sudoWrap(o, cmd, nil)
	sess.Stdin = stdin
	sess.Stdout = log
	sess.Stderr = log
	if err := sess.Run(full); err != nil {
		return xerrors.Errorf("remote `%s`: %w", cmd, err)
	}
	return nil
}

// upload streams data to a remote path with the given octal mode. tee and chmod
// run inside ONE sudo so the data on stdin flows to tee untouched (see sudoWrap
// for why the password must not ride a pipe in front of it).
func upload(client *ssh.Client, o Options, log *bytes.Buffer, path string, data []byte, mode string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	cmd := "tee " + shellQuote(path) + " > /dev/null && chmod " + mode + " " + shellQuote(path)
	full, stdin := sudoWrap(o, cmd, bytes.NewReader(data))
	sess.Stdin = stdin
	sess.Stdout = log
	sess.Stderr = log
	if err := sess.Run(full); err != nil {
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

// sudoWrap prepares a remote command and its stdin for the login's privilege
// level. Non-root logins run under sudo; a password is delivered to `sudo -S`
// by PREPENDING it to the command's stdin (sudo consumes exactly the first
// line), never via `echo <pw> |` — a pipe in front of sudo both exposes the
// password in the remote process list and, fatally for uploads, becomes the
// wrapped command's stdin: tee would read the drained pipe instead of the
// session stdin and write an empty file.
func sudoWrap(o Options, cmd string, stdin io.Reader) (string, io.Reader) {
	if o.User == "root" {
		return cmd, stdin
	}
	if o.Password != "" {
		pw := strings.NewReader(o.Password + "\n")
		if stdin != nil {
			stdin = io.MultiReader(pw, stdin)
		} else {
			stdin = pw
		}
		return "sudo -S -p '' sh -c " + shellQuote(cmd), stdin
	}
	return "sudo sh -c " + shellQuote(cmd), stdin
}

// shellQuote single-quotes a string for safe use in a remote shell command.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
