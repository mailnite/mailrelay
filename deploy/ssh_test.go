/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package deploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newKeyPEM(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blk *pem.Block
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk)
}

// TestParseKeyUnencrypted: a plain key parses with no passphrase.
func TestParseKeyUnencrypted(t *testing.T) {
	if _, err := parseKey(newKeyPEM(t, ""), nil); err != nil {
		t.Fatalf("parse unencrypted key: %v", err)
	}
}

// TestParseKeyEncrypted: an encrypted key needs its passphrase — a clear error
// without one, success with the right one, failure with the wrong one.
func TestParseKeyEncrypted(t *testing.T) {
	pemBytes := newKeyPEM(t, "s3cret")

	if _, err := parseKey(pemBytes, nil); err == nil {
		t.Fatal("encrypted key without a passphrase must error")
	}
	if _, err := parseKey(pemBytes, []byte("s3cret")); err != nil {
		t.Fatalf("encrypted key with the right passphrase: %v", err)
	}
	if _, err := parseKey(pemBytes, []byte("wrong")); err == nil {
		t.Fatal("encrypted key with the wrong passphrase must error")
	}
}

// TestAuthMethodsExplicitKey: an explicit key contributes a method; a bad
// explicit key is a hard error (not silently skipped), since the operator named
// it. Agent and default keys are disabled to isolate the explicit path.
func TestAuthMethodsExplicitKey(t *testing.T) {
	m, err := authMethods(Options{PrivateKeyPEM: newKeyPEM(t, ""), NoAgent: true, NoDefaultKeys: true})
	if err != nil || len(m) != 1 {
		t.Fatalf("explicit key: methods=%d err=%v", len(m), err)
	}

	if _, err := authMethods(Options{PrivateKeyPEM: []byte("not a key"), NoAgent: true, NoDefaultKeys: true}); err == nil {
		t.Fatal("a malformed explicit key must be a hard error")
	}
}

// TestAuthMethodsPasswordFallback: with key sources disabled, a password still
// yields a method; nothing at all is a clear, actionable error.
func TestAuthMethodsPasswordFallback(t *testing.T) {
	m, err := authMethods(Options{Password: "pw", NoAgent: true, NoDefaultKeys: true})
	if err != nil || len(m) != 1 {
		t.Fatalf("password fallback: methods=%d err=%v", len(m), err)
	}

	// No agent, no default keys (HOME redirected to an empty dir), no explicit
	// key, no password → a helpful error.
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir())
	if _, err := authMethods(Options{}); err == nil {
		t.Fatal("no credentials at all must error")
	}
}

// TestDefaultKeySigners: a key at ~/.ssh/id_ed25519 is discovered automatically,
// so `deploy --host X` works with no credential flags.
func TestDefaultKeySigners(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), newKeyPEM(t, ""), 0o600); err != nil {
		t.Fatal(err)
	}

	signers, note := defaultKeySigners(nil)
	if len(signers) != 1 {
		t.Fatalf("expected the default id_ed25519 to be found, got %d (%s)", len(signers), note)
	}

	// Wired end to end: authMethods picks it up with no explicit key or password.
	t.Setenv("SSH_AUTH_SOCK", "")
	m, err := authMethods(Options{NoAgent: true})
	if err != nil || len(m) != 1 {
		t.Fatalf("default-key auth: methods=%d err=%v", len(m), err)
	}
}
