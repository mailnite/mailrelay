/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relayclient

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mailnite/mailrelay/protocol"
)

// fakeConn is a net.Conn stub that records Close.
type fakeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

// TestReverseListenerShedsWhenFull: a server that stopped accepting must not
// pin unbounded tunneled connections — once the accept queue is full, deliver
// refuses (closes) the conn like a full kernel backlog, and reports it.
func TestReverseListenerShedsWhenFull(t *testing.T) {
	l := newReverseListener("smtp", protocol.Addr{Net: "tcp", Str: "203.0.113.7:25"})

	queued := make([]*fakeConn, 0, cap(l.incoming))
	for i := 0; i < cap(l.incoming); i++ {
		c := &fakeConn{}
		if !l.deliver(c) {
			t.Fatalf("deliver #%d refused below capacity", i)
		}
		queued = append(queued, c)
	}

	overflow := &fakeConn{}
	if l.deliver(overflow) {
		t.Fatal("deliver above capacity must shed")
	}
	if !overflow.closed.Load() {
		t.Fatal("shed conn must be closed")
	}

	// Accept drains one slot; delivery works again.
	if _, err := l.Accept(); err != nil {
		t.Fatal(err)
	}
	if !l.deliver(&fakeConn{}) {
		t.Fatal("deliver after Accept must succeed")
	}

	// Close refuses the queued backlog promptly and unblocks Accept.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for _, c := range queued[1:] { // queued[0] was accepted above
		for !c.closed.Load() {
			if time.Now().After(deadline) {
				t.Fatal("queued conns not refused on Close")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if _, err := l.Accept(); err != net.ErrClosed {
		t.Fatalf("Accept after Close: %v", err)
	}
}

/*
TestConnFailStreak pins the redial trigger's whole contract: scattered
failures interleaved with successes never trip (normal noise — an expired
claim from a vanished scanner); a consecutive run trips exactly once at the
threshold (the stale-session burst); and nothing re-trips afterwards — the
session is already closing, so stragglers from the same backlog must not
stack redials.
*/
func TestConnFailStreak(t *testing.T) {
	var s connFailStreak

	// Interleaved noise: fail/fail/ok forever stays below the threshold.
	for i := 0; i < 3*connFailRedialThreshold; i++ {
		if s.fail() {
			t.Fatal("streak tripped despite successes in between")
		}
		if i%2 == 1 {
			s.ok()
		}
	}
	s.ok()

	// A consecutive run: silent until the threshold, trips exactly there.
	for i := 1; i < connFailRedialThreshold; i++ {
		if s.fail() {
			t.Fatalf("tripped early at %d", i)
		}
	}
	if !s.fail() {
		t.Fatalf("must trip at %d consecutive failures", connFailRedialThreshold)
	}

	// One-shot: neither more failures nor a late ok re-arm it.
	for i := 0; i < connFailRedialThreshold+1; i++ {
		if s.fail() {
			t.Fatal("re-tripped after the one-shot")
		}
	}
	s.ok()
	if s.fail() {
		t.Fatal("ok after the trip must not re-arm the streak")
	}
}
