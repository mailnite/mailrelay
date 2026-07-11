/*
 * Copyright 2022-present Mailnite LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package protocol defines the wire contract between a mailnite instance (behind
// NAT) and a mailrelay running on a public VDS. mailnite is the value-rpc
// CLIENT — it dials OUT to the relay, so no inbound reachability to mailnite is
// required — and the relay is the value-rpc SERVER on the public IP.
//
// Three RPCs carry everything (see the const block):
//
//   - ping    unary   — liveness / a cheap "are you the relay I think you are".
//   - session chat     — the control channel: mailnite opens ONE session chat,
//     naming the public ports it wants bound; the relay opens those listeners on
//     the VDS and streams back a `ready` event (per-port results) followed by one
//     `accept` event per inbound public connection. The chat's lifetime IS the
//     session: when it ends (mailnite disconnects or cancels) the relay drops
//     every public listener, so a dead mailnite never leaves ports bound.
//   - conn    chat     — one per tunneled connection. After an `accept` event
//     mailnite opens conn(connId); the two directions of the chat carry the raw
//     bytes of that TCP connection (relay->mailnite = the public client's bytes;
//     mailnite->relay = mailnite's reply bytes). Each value on the wire is a
//     value.Raw byte chunk.
//
// Control messages (session/conn arguments and session events) are small JSON
// documents carried in a value.String, so the contract is human-readable and
// versionable; only the high-rate conn byte path uses value.Raw directly.
package protocol

import (
	"encoding/json"

	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

// RPC names registered on the relay's value-rpc server.
const (
	FnPing    = "ping"
	FnSession = "session"
	FnConn    = "conn"
)

// Version is the protocol revision mailnite announces in SessionRequest; the
// relay rejects a mismatch so an old client meets a clear error, not a silent
// wire break.
const Version = "1"

// Transport names selectable at both ends — the CARRIER the tunnel rides:
// plain TCP, QUIC, or WebSocket. All three run under TLS (that's why "tls" is
// not a transport name); tcp/quic add mutual-TLS client-certificate auth
// against the shared CA, ws (wss) relies on the handshake token (its
// convenience client trusts the system roots).
const (
	TransportTCP  = "tcp"
	TransportWS   = "ws"
	TransportQUIC = "quic"

	// transportTLSAlias is the pre-release name of the TCP transport, still
	// accepted by NormalizeTransport so older configs and printed commands work.
	transportTLSAlias = "tls"
)

// NormalizeTransport canonicalizes a transport name: the default and the
// legacy "tls" spelling both mean TCP. Unknown names pass through so the
// caller's switch can reject them with a precise error.
func NormalizeTransport(s string) string {
	switch s {
	case "", transportTLSAlias, TransportTCP:
		return TransportTCP
	default:
		return s
	}
}

// PortSpec is one public port the relay should bind on the VDS and reverse-proxy
// to mailnite. Proto is "tcp" (the only mail/web transport that needs binding);
// it is carried explicitly so udp/other can be added without a wire change.
type PortSpec struct {
	Name  string `json:"name"`  // logical id: smtp, submission, imaps, pop3s, http, https
	Port  int    `json:"port"`  // public TCP port on the VDS, e.g. 25, 465, 993, 443
	Proto string `json:"proto"` // "tcp"
}

// SessionRequest is the argument of the session chat.
type SessionRequest struct {
	Version string     `json:"version"`
	Token   string     `json:"token,omitempty"` // handshake token echo (ws); ignored under mTLS
	Binds   []PortSpec `json:"binds"`
}

// Event types streamed back on the session chat.
const (
	EventReady  = "ready"  // first message: the outcome of every requested bind
	EventAccept = "accept" // a public client connected to a bound port
	EventError  = "error"  // a non-fatal problem the operator should see
)

// BindResult reports the outcome of one PortSpec.
type BindResult struct {
	Name       string `json:"name"`
	Port       int    `json:"port"`
	OK         bool   `json:"ok"`
	PublicAddr string `json:"publicAddr,omitempty"`
	Error      string `json:"error,omitempty"`
	// Privileged is set when a sub-1024 bind failed for lack of capability, so the
	// onboarding UI can surface the setcap / sysctl remedy instead of a raw errno.
	Privileged bool `json:"privileged,omitempty"`
}

// Event is one message on the session stream. Only the fields relevant to Type
// are populated.
type Event struct {
	Type       string       `json:"type"`
	Binds      []BindResult `json:"binds,omitempty"`      // ready
	ConnID     int64        `json:"connId,omitempty"`     // accept
	Secret     string       `json:"secret,omitempty"`     // accept: capability for the conn chat
	Name       string       `json:"name,omitempty"`       // accept: which bind
	Port       int          `json:"port,omitempty"`       // accept
	RemoteAddr string       `json:"remoteAddr,omitempty"` // accept: the public client
	Message    string       `json:"message,omitempty"`    // error
}

// ConnArgs is the argument of the conn chat: which accepted connection this chat
// is the byte pipe for. Secret is the unguessable capability the relay put in the
// accept event and only sent to the owning client's session stream — so on a
// shared relay one client cannot attach to another client's connection.
type ConnArgs struct {
	ConnID int64  `json:"connId"`
	Secret string `json:"secret"`
}

// EncodeJSON packs any control document into a value.String for the wire.
func EncodeJSON(v any) (value.Value, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return value.Raw(b, false), nil
}

// DecodeJSON unpacks a control document previously produced by EncodeJSON. It
// accepts either a value.String (the normal case) so callers can pass the raw
// handler argument straight through.
func DecodeJSON(val value.Value, out any) error {
	if val == nil || val.Kind() != value.STRING {
		return xerrors.Errorf("expected a JSON string argument, got %v", kindOf(val))
	}
	return json.Unmarshal(val.(value.String).Raw(), out)
}

func kindOf(val value.Value) value.Kind {
	if val == nil {
		return value.NULL
	}
	return val.Kind()
}
