/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package relay is the VDS-side reverse tunnel: it holds the public listeners and
// pumps their bytes to mailnite clients over value-rpc. It stores nothing — no
// mail, no keys beyond the TLS material it needs to authenticate the tunnel — so
// the only asset on the VDS is a public IP and the ability to bind ports.
//
// One relay serves MANY clients. Each client that opens a session chat gets its
// own independent set of public listeners, so several mailnite instances can
// share a single relay — one binding :25, another :110, and so on. Public ports
// are first-come-first-served (a second client requesting a port another already
// holds is told the bind failed); everything else is isolated per session. A
// per-connection capability secret (only ever sent to the owning client) keeps
// one client from attaching to another's tunneled connections.
package relay

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mailnite/mailrelay/protocol"
	"go.arpabet.com/value"
	"go.arpabet.com/value-rpc/valuerpc"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

// connClaimTimeout reaps an accepted public connection that a client never
// attaches a conn chat to (it died between the accept event and the chat), so a
// stalled handshake can't pin a file descriptor forever.
const connClaimTimeout = 15 * time.Second

// Tunnel is the relay's value-rpc service, shared by every connected client.
type Tunnel struct {
	log   *zap.Logger
	token string // when set, required in the session request (ws transport auth)

	connSeq int64

	mu       sync.Mutex
	pending  map[int64]*pendingConn // accepted public conns awaiting their conn chat
	sessions map[*session]struct{}  // every open client session
}

// pendingConn is an accepted public connection plus the capability secret the
// owning client must present to attach its byte pipe.
type pendingConn struct {
	conn   net.Conn
	secret string
}

// New builds a Tunnel. token may be empty when mutual TLS already authenticates
// clients (tls/quic); for ws it is the shared secret each session must echo.
func New(log *zap.Logger, token string) *Tunnel {
	return &Tunnel{
		log:      log,
		token:    token,
		pending:  make(map[int64]*pendingConn),
		sessions: make(map[*session]struct{}),
	}
}

// Register installs the tunnel's handlers on a value-rpc endpoint (the relay
// server, or in tests a client that serves reverse calls).
func (t *Tunnel) Register(r valuerpc.Registrar) error {
	if err := r.AddFunction(protocol.FnPing, valuerpc.Any, valuerpc.String, t.ping); err != nil {
		return err
	}
	if err := r.AddFunction(protocol.FnProbe, valuerpc.Any, valuerpc.Any, t.probe); err != nil {
		return err
	}
	if err := r.AddChat(protocol.FnSession, valuerpc.Any, t.session); err != nil {
		return err
	}
	return r.AddChat(protocol.FnConn, valuerpc.Any, t.conn)
}

func (t *Tunnel) ping(_ context.Context, _ value.Value) (value.Value, error) {
	return value.Utf8("pong"), nil
}

// probe is a unary bindability check: for each requested port it binds and
// immediately releases the listener, returning the outcome. Because nothing
// stays bound, a caller can probe the public ports (25/443/…) repeatedly with no
// risk of occupying or leaking them — unlike opening a session, whose listeners
// live for the session's lifetime.
func (t *Tunnel) probe(_ context.Context, arg value.Value) (value.Value, error) {
	var req protocol.ProbeRequest
	if err := protocol.Decode(arg, &req); err != nil {
		return nil, xerrors.Errorf("probe request: %w", err)
	}
	var res protocol.ProbeResult
	for _, port := range req.Ports {
		p := protocol.PortProbe{Port: port}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			p.Error = err.Error()
			if port < 1024 && errors.Is(err, syscall.EACCES) {
				p.Privileged = true
			}
		} else {
			p.OK = true
			_ = ln.Close() // release immediately — the probe never holds the port
		}
		res.Ports = append(res.Ports, p)
	}
	return protocol.Encode(res)
}

// session is one client's control chat. It authenticates, opens that client's
// requested public listeners, streams a ready event and then one accept event
// per inbound connection, and tears only THIS client's listeners down when the
// chat ends — other clients are unaffected.
func (t *Tunnel) session(ctx context.Context, args value.Value, inC <-chan value.Value) (<-chan value.Value, error) {
	var req protocol.SessionRequest
	if err := protocol.Decode(args, &req); err != nil {
		return nil, xerrors.Errorf("session request: %w", err)
	}
	if req.Version != protocol.Version {
		return nil, xerrors.Errorf("protocol version %q not supported (relay speaks %q)", req.Version, protocol.Version)
	}
	if t.token != "" && subtle.ConstantTimeCompare([]byte(req.Token), []byte(t.token)) != 1 {
		return nil, xerrors.New("invalid relay token")
	}

	s := &session{outC: make(chan value.Value, 64), stop: make(chan struct{})}
	s.onClose = func() { t.removeSession(s) }
	t.addSession(s)

	// Open the listeners and send the ready event BEFORE any accept loop runs, so
	// the ready event is always the first message the client reads (an early
	// inbound connection must not jump ahead of it in the stream).
	results, bound := t.openListeners(&req, s)
	ready, err := protocol.Encode(protocol.Event{Type: protocol.EventReady, Binds: results})
	if err != nil {
		s.shutdown()
		return nil, err
	}
	s.outC <- ready // buffered; the first thing the client reads

	for _, bp := range bound {
		s.wg.Add(1)
		go t.acceptLoop(bp.spec, bp.ln, s)
	}

	// Two teardown triggers: the client cancels/streams-out (ctx) or half-closes
	// its send side (inC drains to close). Either ends the session exactly once.
	go func() {
		for range inC {
			// control channel: reserved for future heartbeats; drain to detect close.
		}
		s.shutdown()
	}()
	go func() {
		<-ctx.Done()
		s.shutdown()
	}()

	t.log.Info("RelaySessionOpen", zap.Int("binds", len(results)), zap.Int("sessions", t.sessionCount()))
	return s.outC, nil
}

// boundPort pairs an opened listener with the spec that requested it, so its
// accept loop can be started after the ready event is sent.
type boundPort struct {
	spec protocol.PortSpec
	ln   net.Listener
}

// openListeners opens a public listener per PortSpec (no accept loops yet) and
// records each on the session for teardown. A port another client already holds
// fails with EADDRINUSE (reported, not fatal); a sub-1024 permission failure is
// reported with Privileged=true so onboarding can show the setcap / sysctl remedy
// rather than a bare errno.
func (t *Tunnel) openListeners(req *protocol.SessionRequest, s *session) ([]protocol.BindResult, []boundPort) {
	results := make([]protocol.BindResult, 0, len(req.Binds))
	var bound []boundPort
	for _, spec := range req.Binds {
		res := protocol.BindResult{Name: spec.Name, Port: spec.Port}
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(spec.Port))
		if err != nil {
			res.Error = err.Error()
			if spec.Port < 1024 && errors.Is(err, syscall.EACCES) {
				res.Privileged = true
			}
			t.log.Warn("RelayBindFailed", zap.String("name", spec.Name), zap.Int("port", spec.Port), zap.Error(err))
			results = append(results, res)
			continue
		}
		res.OK = true
		res.PublicAddr = ln.Addr().String()
		s.listeners = append(s.listeners, ln)
		bound = append(bound, boundPort{spec: spec, ln: ln})
		t.log.Info("RelayBound", zap.String("name", spec.Name), zap.String("addr", res.PublicAddr))
		results = append(results, res)
	}
	return results, bound
}

// acceptLoop accepts public connections on one bound port, stashes each with a
// capability secret so its conn chat can claim it, and emits an accept event. It
// exits when the listener is closed (session teardown) or the session stops.
func (t *Tunnel) acceptLoop(spec protocol.PortSpec, ln net.Listener, s *session) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		id, secret := t.stash(c)
		ev, encErr := protocol.Encode(protocol.Event{
			Type:       protocol.EventAccept,
			ConnID:     id,
			Secret:     secret,
			Name:       spec.Name,
			Port:       spec.Port,
			RemoteAddr: c.RemoteAddr().String(),
		})
		if encErr != nil {
			t.reap(id)
			continue
		}
		select {
		case s.outC <- ev:
		case <-s.stop:
			t.reap(id)
			return
		}
	}
}

// conn is the byte pump for one tunneled connection. It claims the accepted
// public conn by id (verifying the capability secret) and shuttles bytes both
// ways until either side closes.
func (t *Tunnel) conn(ctx context.Context, args value.Value, inC <-chan value.Value) (<-chan value.Value, error) {
	var ca protocol.ConnArgs
	if err := protocol.Decode(args, &ca); err != nil {
		return nil, xerrors.Errorf("conn args: %w", err)
	}
	pc := t.claim(ca.ConnID, ca.Secret)
	if pc == nil {
		return nil, xerrors.Errorf("unknown, expired, or unauthorized conn %d", ca.ConnID)
	}

	outC := make(chan value.Value, 16)
	var once sync.Once
	closeConn := func() { once.Do(func() { pc.Close() }) }

	// relay -> client: the public client's bytes.
	go func() {
		defer close(outC)
		defer closeConn()
		buf := make([]byte, 32*1024)
		for {
			n, err := pc.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				select {
				case outC <- value.Raw(b, false):
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// client -> relay: the client's reply bytes. inC closing means the client
	// closed its end of the connection.
	go func() {
		defer closeConn()
		for v := range inC {
			if v == nil || v.Kind() != value.STRING {
				continue
			}
			if _, err := pc.Write(v.(value.String).Raw()); err != nil {
				return
			}
		}
	}()

	return outC, nil
}

// stash records an accepted conn under a fresh id + capability secret and arms a
// reaper for the case where no conn chat ever claims it.
func (t *Tunnel) stash(c net.Conn) (int64, string) {
	id := atomic.AddInt64(&t.connSeq, 1)
	secret := randomSecret()
	t.mu.Lock()
	t.pending[id] = &pendingConn{conn: c, secret: secret}
	t.mu.Unlock()
	time.AfterFunc(connClaimTimeout, func() { t.reap(id) })
	return id, secret
}

// claim removes and returns the accepted conn for id only if secret matches (so
// a client cannot attach to a conn it was never told the secret for).
func (t *Tunnel) claim(id int64, secret string) net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	pc := t.pending[id]
	if pc == nil || subtle.ConstantTimeCompare([]byte(pc.secret), []byte(secret)) != 1 {
		return nil
	}
	delete(t.pending, id)
	return pc.conn
}

// reap drops and closes an unclaimed pending conn (secret not required — internal).
func (t *Tunnel) reap(id int64) {
	t.mu.Lock()
	pc := t.pending[id]
	delete(t.pending, id)
	t.mu.Unlock()
	if pc != nil {
		pc.conn.Close()
	}
}

func (t *Tunnel) addSession(s *session) {
	t.mu.Lock()
	t.sessions[s] = struct{}{}
	t.mu.Unlock()
}

func (t *Tunnel) removeSession(s *session) {
	t.mu.Lock()
	delete(t.sessions, s)
	t.mu.Unlock()
}

func (t *Tunnel) sessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// Close tears down every open session (used on relay shutdown).
func (t *Tunnel) Close() {
	t.mu.Lock()
	all := make([]*session, 0, len(t.sessions))
	for s := range t.sessions {
		all = append(all, s)
	}
	t.mu.Unlock()
	for _, s := range all {
		s.shutdown()
	}
}

// session is one client control connection's server-side state.
type session struct {
	outC      chan value.Value
	stop      chan struct{}
	wg        sync.WaitGroup
	listeners []net.Listener
	once      sync.Once
	onClose   func() // called once on shutdown (deregisters the session)
}

// shutdown stops accepting, closes this session's listeners, waits for its accept
// loops to finish (so no loop sends on outC after it is closed), then closes outC
// and deregisters the session.
func (s *session) shutdown() {
	s.once.Do(func() {
		close(s.stop)
		for _, ln := range s.listeners {
			_ = ln.Close()
		}
		s.wg.Wait()
		close(s.outC)
		if s.onClose != nil {
			s.onClose()
		}
	})
}

func randomSecret() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal-grade; fall back to a time-seeded value so
		// the relay keeps working rather than handing out an empty (guessable) one.
		return hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 16)))
	}
	return hex.EncodeToString(b[:])
}
