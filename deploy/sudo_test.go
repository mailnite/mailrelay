/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package deploy

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestSudoWrapRoot: root runs the command as-is with untouched stdin.
func TestSudoWrapRoot(t *testing.T) {
	data := strings.NewReader("payload")
	cmd, stdin := sudoWrap(Options{User: "root"}, "tee '/x' > /dev/null", data)
	if cmd != "tee '/x' > /dev/null" {
		t.Fatalf("cmd = %q", cmd)
	}
	if stdin != io.Reader(data) {
		t.Fatal("stdin must pass through unchanged for root")
	}
}

// TestSudoWrapPasswordStdin: the password must reach sudo -S as the FIRST stdin
// line — never on the command line where the remote process list would show it —
// and the payload must follow intact so tee writes the real bytes (the
// echo-pipe form used to hand tee a drained pipe and produce empty files).
func TestSudoWrapPasswordStdin(t *testing.T) {
	payload := []byte("\x00binary\nfile bytes")
	cmd, stdin := sudoWrap(
		Options{User: "deploy", Password: "s3cret"},
		"tee '/x' > /dev/null && chmod 0755 '/x'",
		bytes.NewReader(payload),
	)

	if strings.Contains(cmd, "s3cret") {
		t.Fatalf("password leaked into the command line: %q", cmd)
	}
	if !strings.HasPrefix(cmd, "sudo -S -p '' sh -c ") {
		t.Fatalf("cmd = %q", cmd)
	}

	all, err := io.ReadAll(stdin)
	if err != nil {
		t.Fatal(err)
	}
	want := "s3cret\n" + string(payload)
	if string(all) != want {
		t.Fatalf("stdin = %q, want %q", all, want)
	}
}

// TestSudoWrapNoPassword: a passwordless sudoer gets plain sudo (NOPASSWD path)
// and stdin passes through for tee.
func TestSudoWrapNoPassword(t *testing.T) {
	data := strings.NewReader("payload")
	cmd, stdin := sudoWrap(Options{User: "deploy"}, "systemctl daemon-reload", data)
	if cmd != "sudo sh -c 'systemctl daemon-reload'" {
		t.Fatalf("cmd = %q", cmd)
	}
	all, _ := io.ReadAll(stdin)
	if string(all) != "payload" {
		t.Fatalf("stdin = %q", all)
	}
}

// TestSudoWrapRunWithoutStdin: run()-style calls (nil stdin) still deliver the
// password line to sudo -S.
func TestSudoWrapRunWithoutStdin(t *testing.T) {
	cmd, stdin := sudoWrap(Options{User: "deploy", Password: "pw"}, "systemctl daemon-reload", nil)
	if !strings.HasPrefix(cmd, "sudo -S -p '' sh -c ") {
		t.Fatalf("cmd = %q", cmd)
	}
	all, _ := io.ReadAll(stdin)
	if string(all) != "pw\n" {
		t.Fatalf("stdin = %q", all)
	}
}
