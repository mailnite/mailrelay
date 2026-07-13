/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package protocol

import (
	"io"
	"net"
	"sync"
	"time"

	"go.arpabet.com/value"
)

// Addr is a lightweight net.Addr carrying the public peer address the relay
// reported for a tunneled connection, so mailnite's mail servers log and
// rate-limit against the real client IP rather than the tunnel.
type Addr struct {
	Net string
	Str string
}

func (a Addr) Network() string { return a.Net }
func (a Addr) String() string  { return a.Str }

// ChanConn adapts the two directions of a value-rpc conn chat into a net.Conn.
// It is the mailnite-side endpoint of one tunneled TCP connection: reads pull
// byte chunks the relay forwards from the public client, writes push byte chunks
// back to the relay to send to that client. Closing it closes the send side of
// the chat, which the relay observes as the connection's end.
//
// A single value.Raw chunk may be larger than the caller's Read buffer, so a
// leftover slice is retained between Reads. Deadlines follow the full net.Conn
// contract: setting one interrupts Reads/Writes that are ALREADY blocked (mail
// servers abort stuck connections by setting a past deadline from another
// goroutine), and each deadline re-arms a single persistent timer instead of
// allocating one per operation.
type ChanConn struct {
	out    chan value.Value   // mailnite -> relay (owned; closed on Close)
	in     <-chan value.Value // relay -> mailnite (the chat's receive channel)
	local  net.Addr
	remote net.Addr

	readMu  sync.Mutex
	readBuf []byte

	readDL  connDeadline
	writeDL connDeadline

	// out is closed exactly once, only after every in-flight Write has left its
	// send — value-rpc's stream contract requires closing the put channel to end
	// the stream, and a mail server may Close from a different goroutine than
	// Write, so this guards against a send on a closed channel.
	closeMu  sync.Mutex
	isClosed bool
	writers  sync.WaitGroup
	closed   chan struct{}
}

var _ net.Conn = (*ChanConn)(nil)

// NewChanConn wires a conn chat's send channel (out) and receive channel (in)
// into a net.Conn reporting remote as its peer address. out is the put channel
// mailnite handed to Client.Chat; ChanConn owns closing it.
func NewChanConn(out chan value.Value, in <-chan value.Value, remote net.Addr) *ChanConn {
	return &ChanConn{
		out:     out,
		in:      in,
		local:   Addr{Net: "mailrelay", Str: "tunnel"},
		remote:  remote,
		readDL:  makeConnDeadline(),
		writeDL: makeConnDeadline(),
		closed:  make(chan struct{}),
	}
}

func (c *ChanConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) == 0 {
		if isClosedChan(c.closed) {
			return 0, io.EOF
		}
		cancel := c.readDL.wait()
		if isClosedChan(cancel) {
			return 0, timeoutError{}
		}
		select {
		case v, ok := <-c.in:
			if !ok {
				return 0, io.EOF
			}
			if v == nil || v.Kind() != value.STRING {
				return 0, io.EOF
			}
			c.readBuf = v.(value.String).Raw()
		case <-c.closed:
			return 0, io.EOF
		case <-cancel:
			return 0, timeoutError{}
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *ChanConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// value.Raw retains the slice; copy so a caller reusing its buffer is safe.
	b := make([]byte, len(p))
	copy(b, p)

	// Register as an in-flight writer so Close waits for this send to finish
	// before closing the channel.
	c.closeMu.Lock()
	if c.isClosed {
		c.closeMu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.writers.Add(1)
	c.closeMu.Unlock()
	defer c.writers.Done()

	cancel := c.writeDL.wait()
	if isClosedChan(cancel) {
		return 0, timeoutError{}
	}
	select {
	case c.out <- value.Raw(b, false):
		return len(p), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case <-cancel:
		return 0, timeoutError{}
	}
}

// Close closes the send side of the chat exactly once, after in-flight writes
// drain. Closing the put channel is how value-rpc ends the stream, which the
// relay observes as the connection's end.
func (c *ChanConn) Close() error {
	c.closeMu.Lock()
	if c.isClosed {
		c.closeMu.Unlock()
		return nil
	}
	c.isClosed = true
	close(c.closed) // wakes any Write blocked in its select
	c.closeMu.Unlock()

	c.writers.Wait() // no writer will touch c.out after this
	close(c.out)
	return nil
}

func (c *ChanConn) LocalAddr() net.Addr  { return c.local }
func (c *ChanConn) RemoteAddr() net.Addr { return c.remote }

func (c *ChanConn) SetDeadline(t time.Time) error {
	c.readDL.set(t)
	c.writeDL.set(t)
	return nil
}

func (c *ChanConn) SetReadDeadline(t time.Time) error {
	c.readDL.set(t)
	return nil
}

func (c *ChanConn) SetWriteDeadline(t time.Time) error {
	c.writeDL.set(t)
	return nil
}

// connDeadline signals deadline expiry by closing a channel, so a blocked Read
// or Write wakes the moment the deadline passes — including a deadline set
// AFTER the operation blocked. One timer per direction is re-armed in place on
// every SetDeadline (no per-operation allocation). Same construction as the
// standard library's net.Pipe deadline.
type connDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // closed when the deadline passes; replaced on re-arm
}

func makeConnDeadline() connDeadline {
	return connDeadline{cancel: make(chan struct{})}
}

// set arms the deadline: zero disarms, a past time fires immediately, a future
// time (re)schedules the timer. Safe to call concurrently with wait().
func (d *connDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // the timer callback fired between Stop and the lock; let it finish
	}
	d.timer = nil

	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel) // deadline already passed: expire pending and future ops now
	}
}

// wait returns the channel that closes when the current deadline expires.
func (d *connDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// timeoutError satisfies net.Error with Timeout()==true, so go-smtp/go-imap treat
// a deadline the same as a real socket timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "mailrelay: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
