/*
 * Copyright 2022-present Mailnite LLC.
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
// leftover slice is retained between Reads. Deadlines are honored so idle-timeout
// logic in go-smtp / go-imap behaves as it would on a real socket.
type ChanConn struct {
	out    chan value.Value   // mailnite -> relay (owned; closed on Close)
	in     <-chan value.Value // relay -> mailnite (the chat's receive channel)
	local  net.Addr
	remote net.Addr

	readMu  sync.Mutex
	readBuf []byte

	deadlineMu sync.Mutex
	readDL     time.Time
	writeDL    time.Time

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
		out:    out,
		in:     in,
		local:  Addr{Net: "mailrelay", Str: "tunnel"},
		remote: remote,
		closed: make(chan struct{}),
	}
}

func (c *ChanConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) == 0 {
		var timer <-chan time.Time
		if dl := c.readDeadline(); !dl.IsZero() {
			t := time.NewTimer(time.Until(dl))
			defer t.Stop()
			timer = t.C
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
		case <-timer:
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

	var timer <-chan time.Time
	if dl := c.writeDeadline(); !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timer = t.C
	}
	select {
	case c.out <- value.Raw(b, false):
		return len(p), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case <-timer:
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
	c.deadlineMu.Lock()
	c.readDL, c.writeDL = t, t
	c.deadlineMu.Unlock()
	return nil
}

func (c *ChanConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDL = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *ChanConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDL = t
	c.deadlineMu.Unlock()
	return nil
}

func (c *ChanConn) readDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDL
}

func (c *ChanConn) writeDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDL
}

// timeoutError satisfies net.Error with Timeout()==true, so go-smtp/go-imap treat
// a deadline the same as a real socket timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "mailrelay: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
