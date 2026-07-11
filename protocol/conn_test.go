/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package protocol

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"go.arpabet.com/value"
)

func newTestConn(outCap, inCap int) (*ChanConn, chan value.Value, chan value.Value) {
	out := make(chan value.Value, outCap)
	in := make(chan value.Value, inCap)
	c := NewChanConn(out, in, Addr{Net: "tcp", Str: "192.0.2.1:12345"})
	return c, out, in
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestChanConnReadWrite: bytes flow both ways, oversized chunks are consumed
// across multiple Reads without loss.
func TestChanConnReadWrite(t *testing.T) {
	c, out, in := newTestConn(4, 4)

	in <- value.Raw([]byte("hello world"), false)
	buf := make([]byte, 5)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("read 1: %q %v", buf[:n], err)
	}
	rest := make([]byte, 16)
	if n, err := c.Read(rest); err != nil || string(rest[:n]) != " world" {
		t.Fatalf("read 2: %q %v", rest[:n], err)
	}

	if n, err := c.Write([]byte("reply")); err != nil || n != 5 {
		t.Fatalf("write: %d %v", n, err)
	}
	v := <-out
	if string(v.(value.String).Raw()) != "reply" {
		t.Fatalf("wrote %q", v.(value.String).Raw())
	}
}

// TestChanConnDeadlineInterruptsBlockedRead pins the net.Conn contract: a read
// deadline set AFTER a Read has already blocked must wake it with a timeout —
// mail servers abort stuck connections exactly this way.
func TestChanConnDeadlineInterruptsBlockedRead(t *testing.T) {
	c, _, _ := newTestConn(1, 1)

	got := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := c.Read(buf)
		got <- err
	}()

	time.Sleep(50 * time.Millisecond) // let the Read block with no deadline armed
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if !isTimeout(err) {
			t.Fatalf("want timeout, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Read was not interrupted by SetReadDeadline")
	}
}

// TestChanConnDeadlineInterruptsBlockedWrite: same contract for Write (the put
// channel is full, the writer is parked).
func TestChanConnDeadlineInterruptsBlockedWrite(t *testing.T) {
	c, out, _ := newTestConn(1, 1)
	out <- value.Raw([]byte("fill"), false) // occupy the only slot

	got := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("blocked"))
		got <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if !isTimeout(err) {
			t.Fatalf("want timeout, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Write was not interrupted by SetWriteDeadline")
	}
}

// TestChanConnPastDeadline: an already-expired deadline fails immediately, and
// clearing it (zero time) makes the conn usable again.
func TestChanConnPastDeadline(t *testing.T) {
	c, _, in := newTestConn(1, 1)

	c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := c.Read(make([]byte, 4)); !isTimeout(err) {
		t.Fatalf("want immediate timeout, got %v", err)
	}

	c.SetReadDeadline(time.Time{}) // clear
	in <- value.Raw([]byte("ok"), false)
	buf := make([]byte, 4)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read after clearing deadline: %q %v", buf[:n], err)
	}
}

// TestChanConnDeadlineExtendWhileBlocked: re-arming a deadline further into the
// future while a Read is blocked keeps the SAME expiry channel live, so the
// Read still times out — at the extended time, not the original.
func TestChanConnDeadlineExtendWhileBlocked(t *testing.T) {
	c, _, _ := newTestConn(1, 1)
	c.SetReadDeadline(time.Now().Add(60 * time.Millisecond))

	got := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 4))
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	c.SetReadDeadline(time.Now().Add(150 * time.Millisecond)) // extend before expiry

	start := time.Now()
	select {
	case err := <-got:
		if !isTimeout(err) {
			t.Fatalf("want timeout, got %v", err)
		}
		if time.Since(start) < 80*time.Millisecond {
			t.Fatalf("read timed out at the ORIGINAL deadline despite the extension (after %v)", time.Since(start))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read never timed out")
	}
}

// TestChanConnCloseSemantics: Close ends blocked Writes with ErrClosedPipe,
// makes Reads return EOF, closes the put channel exactly once, and a racing
// Write never panics on the closed channel.
func TestChanConnCloseSemantics(t *testing.T) {
	c, out, _ := newTestConn(1, 1)
	out <- value.Raw([]byte("fill"), false)

	got := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("blocked"))
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err != io.ErrClosedPipe {
		t.Fatalf("blocked write after Close: %v", err)
	}
	if _, err := c.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("read after Close: %v", err)
	}
	if _, err := c.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("write after Close: %v", err)
	}
	if err := c.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
	// The put channel must be closed (stream end) with the fill still readable.
	if v, ok := <-out; !ok || string(v.(value.String).Raw()) != "fill" {
		t.Fatalf("fill lost: %v %v", v, ok)
	}
	if _, ok := <-out; ok {
		t.Fatal("out not closed after Close")
	}
}
