/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package relayclient

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"go.arpabet.com/value"
	"go.arpabet.com/value-rpc/valueclient"
	"go.arpabet.com/value-rpc/valuerpc"
	"golang.org/x/xerrors"
)

/*
Proxied transports. value-rpc's stock dialers own their sockets, so a proxy
in the path means building the connection ourselves and handing the library
a valuerpc.Dialer:

  - TCP: proxy CONNECT/SOCKS to the relay, TCP keepalive on the raw socket,
    the tunnel's own TLS handshaken THROUGH the proxy, then the library's
    stream framing (NewMsgConn) on top — byte-identical wire to the stock
    TLS dialer.
  - WS: the websocket upgrade rides an http.Client whose transport dials
    through the proxy; frames are then adapted to MsgConn with the same
    msgpack-in-binary-frames wire and ping keepalive the library uses.
  - QUIC is UDP — a TCP proxy cannot carry it; newClient refuses the
    combination with the reason spelled out.
*/

// proxiedTLSDialer dials the relay through the proxy and runs the tunnel's
// TLS on top. writeTimeout/maxFrameSize mirror the library's defaults so a
// proxied connection behaves exactly like a direct one.
type proxiedTLSDialer struct {
	proxy  ProxyConfig
	addr   string
	tlsCfg *tls.Config
}

func (d *proxiedTLSDialer) Dial(ctx context.Context) (valuerpc.MsgConn, error) {
	raw, err := d.proxy.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(valueclient.KeepAlivePeriod)
	}
	tlsConn := tls.Client(raw, d.tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, xerrors.Errorf("relay tls through %s proxy %s: %w", d.proxy.Type, d.proxy.Addr, err)
	}
	return valuerpc.NewMsgConn(tlsConn, valueclient.DefaultTimeout, valuerpc.MaxFrameSize), nil
}

// proxiedWSDialer performs the wss:// upgrade through the proxy.
type proxiedWSDialer struct {
	proxy ProxyConfig
	url   string
}

// proxiedWSDialTimeout mirrors the library's ws dial default: applied only
// when the caller's context carries no deadline of its own.
const proxiedWSDialTimeout = 30 * time.Second

func (d *proxiedWSDialer) Dial(ctx context.Context) (valuerpc.MsgConn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, proxiedWSDialTimeout)
		defer cancel()
	}
	tr := &http.Transport{
		Proxy:       nil, // the environment's proxy vars must not stack on ours
		DialContext: d.proxy.DialContext,
	}
	c, _, err := websocket.Dial(ctx, d.url, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: tr},
	})
	if err != nil {
		return nil, xerrors.Errorf("relay ws through %s proxy %s: %w", d.proxy.Type, d.proxy.Addr, err)
	}
	return newProxiedWSMsgConn(c, d.url), nil
}

/*
proxiedWSMsgConn adapts a websocket connection to valuerpc.MsgConn with the
library's exact wire: one msgpack-encoded value.Map per BINARY frame, ping
keepalive, close tears the context so blocked reads unwind. (The library's
own adapter is unexported; this mirror stays wire-compatible because the
framing is frozen by every deployed relay.)
*/
type proxiedWSMsgConn struct {
	conn       *websocket.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	remoteAddr string

	writeMu   sync.Mutex
	readDL    atomic.Pointer[time.Time]
	closeOnce sync.Once
	done      chan struct{}
}

func newProxiedWSMsgConn(c *websocket.Conn, remoteAddr string) *proxiedWSMsgConn {
	ctx, cancel := context.WithCancel(context.Background())
	t := &proxiedWSMsgConn{conn: c, ctx: ctx, cancel: cancel, remoteAddr: remoteAddr, done: make(chan struct{})}
	go t.pinger()
	return t
}

func (t *proxiedWSMsgConn) ReadMessage() (value.Map, error) {
	ctx := t.ctx
	if dl := t.readDL.Load(); dl != nil && !dl.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(t.ctx, *dl)
		defer cancel()
	}
	typ, data, err := t.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, xerrors.Errorf("expected a binary websocket frame, got %v", typ)
	}
	return valuerpc.MsgpackWireCodec.Decode(data)
}

func (t *proxiedWSMsgConn) WriteMessage(msg value.Map) error {
	payload, err := valuerpc.MsgpackWireCodec.Encode(msg)
	if err != nil {
		return xerrors.Errorf("msgpack encode: %w", err)
	}
	ctx, cancel := context.WithTimeout(t.ctx, valueclient.DefaultTimeout)
	defer cancel()
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.conn.Write(ctx, websocket.MessageBinary, payload)
}

func (t *proxiedWSMsgConn) SetReadDeadline(deadline time.Time) error {
	t.readDL.Store(&deadline)
	return nil
}

func (t *proxiedWSMsgConn) RemoteAddr() string { return t.remoteAddr }

func (t *proxiedWSMsgConn) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		t.cancel()
		_ = t.conn.Close(websocket.StatusNormalClosure, "")
	})
	return nil
}

// pinger keeps NAT/proxy idle timers from silently killing the tunnel — the
// exact half-dead-session signature connFailStreak exists for.
func (t *proxiedWSMsgConn) pinger() {
	ticker := time.NewTicker(valueclient.KeepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(t.ctx, valueclient.KeepAlivePeriod)
			err := t.conn.Ping(ctx)
			cancel()
			if err != nil {
				_ = t.Close()
				return
			}
		}
	}
}
