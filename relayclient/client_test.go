/*
 * Copyright 2022-present Mailnite LLC.
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
