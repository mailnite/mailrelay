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
// Everything on the wire is a NATIVE value message — control documents
// (session/conn arguments, session events) are value maps marshaled straight
// from the tagged structs below (value.Marshal / value.Unmarshal, the same
// mechanics the rest of the stack persists with), and the high-rate conn byte
// path is untagged value.Raw chunks. One msgpack encoding end to end: no JSON,
// no base64, no second serializer inside the first. Codec[T] exposes the same
// mapping as a valuerpc.Codec for typed helpers.
package protocol

import (
	"go.arpabet.com/value"
	"go.arpabet.com/value-rpc/valuerpc"
	"golang.org/x/xerrors"
)

// RPC names registered on the relay's value-rpc server.
const (
	FnPing    = "ping"
	FnSession = "session"
	FnConn    = "conn"
	FnProbe   = "probe"
)

// ProbeRequest asks the relay whether it can bind each public port on the VDS.
// It is a unary probe: the relay binds each port, immediately releases it, and
// returns the outcome — nothing stays bound, so a check never occupies or leaks
// a public port (unlike opening a session, whose listeners persist).
type ProbeRequest struct {
	Ports []int `value:"ports,omitempty"`
}

// PortProbe is the outcome of binding one port during a ProbeRequest.
type PortProbe struct {
	Port       int    `value:"port,omitempty"`
	OK         bool   `value:"ok,omitempty"`
	Error      string `value:"error,omitempty"`
	Privileged bool   `value:"privileged,omitempty"` // sub-1024 bind failed for lack of capability
}

// ProbeResult is the reply to a ProbeRequest — one PortProbe per requested port.
type ProbeResult struct {
	Ports []PortProbe `value:"ports,omitempty"`
}

// Version is the protocol revision mailnite announces in SessionRequest; the
// relay rejects a mismatch so an old client meets a clear error, not a silent
// wire break. Revision 2 switched the control messages from JSON-in-a-string
// to native value maps.
const Version = "2"

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
	Name  string `value:"name,omitempty"`  // logical id: smtp, submission, imaps, pop3s, http, https
	Port  int    `value:"port,omitempty"`  // public TCP port on the VDS, e.g. 25, 465, 993, 443
	Proto string `value:"proto,omitempty"` // "tcp"
}

// SessionRequest is the argument of the session chat.
type SessionRequest struct {
	Version string     `value:"version,omitempty"`
	Token   string     `value:"token,omitempty"` // handshake token echo (ws); ignored under mTLS
	Binds   []PortSpec `value:"binds,omitempty"`
}

// Event types streamed back on the session chat.
const (
	EventReady  = "ready"  // first message: the outcome of every requested bind
	EventAccept = "accept" // a public client connected to a bound port
	EventError  = "error"  // a non-fatal problem the operator should see
)

// BindResult reports the outcome of one PortSpec.
type BindResult struct {
	Name       string `value:"name,omitempty"`
	Port       int    `value:"port,omitempty"`
	OK         bool   `value:"ok,omitempty"`
	PublicAddr string `value:"publicAddr,omitempty"`
	Error      string `value:"error,omitempty"`
	// Privileged is set when a sub-1024 bind failed for lack of capability, so the
	// onboarding UI can surface the setcap / sysctl remedy instead of a raw errno.
	Privileged bool `value:"privileged,omitempty"`
}

// Event is one message on the session stream. Only the fields relevant to Type
// are populated.
type Event struct {
	Type       string       `value:"type,omitempty"`
	Binds      []BindResult `value:"binds,omitempty"`      // ready
	ConnID     int64        `value:"connId,omitempty"`     // accept
	Secret     string       `value:"secret,omitempty"`     // accept: capability for the conn chat
	Name       string       `value:"name,omitempty"`       // accept: which bind
	Port       int          `value:"port,omitempty"`       // accept
	RemoteAddr string       `value:"remoteAddr,omitempty"` // accept: the public client
	Message    string       `value:"message,omitempty"`    // error
}

// ConnArgs is the argument of the conn chat: which accepted connection this chat
// is the byte pipe for. Secret is the unguessable capability the relay put in the
// accept event and only sent to the owning client's session stream — so on a
// shared relay one client cannot attach to another client's connection.
type ConnArgs struct {
	ConnID int64  `value:"connId,omitempty"`
	Secret string `value:"secret,omitempty"`
}

// Encode marshals a control message (one of the tagged structs above) into the
// native value map it travels as — a single msgpack encoding on the wire.
func Encode(v any) (value.Value, error) {
	return value.Marshal(v)
}

// Decode unmarshals a control message previously produced by Encode, verifying
// it is a value map before field mapping so a foreign payload (e.g. a protocol-1
// JSON string) fails with a precise error instead of a zero-value struct.
func Decode(val value.Value, out any) error {
	if val == nil || val.Kind() != value.MAP {
		return xerrors.Errorf("expected a value map, got %v (peer speaking protocol %s?)", kindOf(val), Version)
	}
	return value.Unmarshal(val, out)
}

// Codec exposes the Encode/Decode mapping as a valuerpc.Codec, so control
// messages plug into value-rpc's typed helpers (valueserver.AddUnary,
// valueclient.CallUnary, …) exactly like any other typed message.
func Codec[T any]() valuerpc.Codec[T] {
	return valuerpc.Codec[T]{
		Encode: func(v T) value.Value {
			val, err := value.Marshal(&v)
			if err != nil {
				return value.Null
			}
			return val
		},
		Decode: func(v value.Value) (T, error) {
			var out T
			err := Decode(v, &out)
			return out, err
		},
	}
}

func kindOf(val value.Value) value.Kind {
	if val == nil {
		return value.NULL
	}
	return val.Kind()
}
