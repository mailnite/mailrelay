/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relay_test

import (
	"context"
	"testing"
	"time"

	"github.com/mailnite/mailrelay/protocol"
	"github.com/mailnite/mailrelay/relay"
	"github.com/mailnite/mailrelay/relayclient"
	"go.arpabet.com/glue"
	"go.uber.org/zap"
)

// TestServerBeanLifecycle proves the DI composition end to end: a glue
// container wires the Server bean (logger + ConfigSource injected),
// PostConstruct validates the config, Serve serves a real token-authenticated
// tunnel, and closing the container (Destroy) is sufficient to stop it.
func TestServerBeanLifecycle(t *testing.T) {
	srv := relay.NewServer()
	ctn, err := glue.New(
		zap.NewNop(),
		relay.StaticConfig{Transport: protocol.TransportTCP, BindAddr: "127.0.0.1:0", Token: "bean-key"},
		srv,
	)
	if err != nil {
		t.Fatalf("container: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()

	deadline := time.Now().Add(5 * time.Second)
	for srv.BoundAddr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("server never bound")
		}
		time.Sleep(10 * time.Millisecond)
	}

	sess, err := relayclient.Dial(context.Background(), relayclient.Config{
		Transport: protocol.TransportTCP,
		Addr:      srv.BoundAddr().String(),
		Token:     "bean-key",
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := sess.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	sess.Close()

	// Destroy (via container close) must stop the serving loop.
	if err := ctn.Close(); err != nil {
		t.Fatalf("container close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop when the container closed")
	}
}

// TestServerBeanRejectsBadConfigAtWiring: an unusable configuration (no client
// auth at all) fails CONTAINER CREATION — the bean's PostConstruct is the
// single validation point, so a misconfigured serve never half-starts.
func TestServerBeanRejectsBadConfigAtWiring(t *testing.T) {
	_, err := glue.New(
		zap.NewNop(),
		relay.StaticConfig{Transport: protocol.TransportTCP, BindAddr: "127.0.0.1:0"},
		relay.NewServer(),
	)
	if err == nil {
		t.Fatal("container creation must fail: neither token nor certificate configured")
	}
}
