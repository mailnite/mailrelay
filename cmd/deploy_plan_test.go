/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newDeploy(dir string) *DeployCommand {
	return &DeployCommand{
		Transport: "tcp",
		Bind:      "0.0.0.0:8443",
		Path:      "/relay",
		RemoteDir: "/opt/mailrelay",
		CACert:    filepath.Join(dir, "ca.crt"),
		Cert:      filepath.Join(dir, "relay.crt"),
		Key:       filepath.Join(dir, "relay.key"),
	}
}

// TestDeployPlanTokenOnly: the key-authenticated mode serve supports (and
// install.sh uses) must be deployable — no cert files needed when a token is
// shipped, and the serve args must not reference certs that were not uploaded.
func TestDeployPlanTokenOnly(t *testing.T) {
	dir := t.TempDir()
	d := newDeploy(dir)
	d.Token = writeTemp(t, dir, "token", "shared-key\n")

	files, args, err := d.deployPlan()
	if err != nil {
		t.Fatalf("token-only plan: %v", err)
	}
	if _, ok := files["token"]; !ok {
		t.Fatal("token file not shipped")
	}
	for _, name := range []string{"ca.pem", "relay.crt", "relay.key"} {
		if _, ok := files[name]; ok {
			t.Fatalf("%s shipped despite not existing", name)
		}
	}
	if strings.Contains(args, "--ca") || strings.Contains(args, "--cert") {
		t.Fatalf("serve args reference certs that were not shipped: %q", args)
	}
	if !strings.Contains(args, "--token-file /opt/mailrelay/token") {
		t.Fatalf("serve args missing token file: %q", args)
	}
}

// TestDeployPlanMutualTLS: with the cert bundle on disk the full mTLS deploy
// works exactly as before.
func TestDeployPlanMutualTLS(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "ca.crt", "ca")
	writeTemp(t, dir, "relay.crt", "crt")
	writeTemp(t, dir, "relay.key", "key")
	d := newDeploy(dir)

	files, args, err := d.deployPlan()
	if err != nil {
		t.Fatalf("mTLS plan: %v", err)
	}
	for _, name := range []string{"ca.pem", "relay.crt", "relay.key"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("%s not shipped", name)
		}
	}
	for _, want := range []string{"--ca /opt/mailrelay/ca.pem", "--cert /opt/mailrelay/relay.crt", "--key /opt/mailrelay/relay.key"} {
		if !strings.Contains(args, want) {
			t.Fatalf("serve args missing %q: %q", want, args)
		}
	}
}

// TestDeployPlanRejectsUnauthenticated: no token and no certs is a clear error;
// a cert without its key is too; and a cert bundle without a CA or token would
// be an unauthenticated relay and must be refused.
func TestDeployPlanRejectsUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := newDeploy(dir).deployPlan(); err == nil {
		t.Fatal("no token, no certs: want error")
	}

	dir2 := t.TempDir()
	writeTemp(t, dir2, "relay.crt", "crt")
	writeTemp(t, dir2, "relay.key", "key")
	if _, _, err := newDeploy(dir2).deployPlan(); err == nil {
		t.Fatal("cert+key without CA or token: want error (unauthenticated relay)")
	}

	dir3 := t.TempDir()
	writeTemp(t, dir3, "ca.crt", "ca")
	writeTemp(t, dir3, "relay.crt", "crt")
	d3 := newDeploy(dir3)
	d3.Token = writeTemp(t, dir3, "token", "k")
	if _, _, err := d3.deployPlan(); err == nil {
		t.Fatal("cert without key: want error")
	}
}

// TestDeployPlanWSPath: the ws transport carries its upgrade path through.
func TestDeployPlanWSPath(t *testing.T) {
	dir := t.TempDir()
	d := newDeploy(dir)
	d.Transport = "ws"
	d.Token = writeTemp(t, dir, "token", "k")

	_, args, err := d.deployPlan()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(args, "--path /relay") {
		t.Fatalf("ws serve args missing path: %q", args)
	}
}
