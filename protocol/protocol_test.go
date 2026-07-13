/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package protocol

import (
	"testing"

	"go.arpabet.com/value"
)

// TestControlMessagesAreNativeMaps pins the wire contract: a control message
// encodes to a value MAP (msgpack-native, one encoding on the wire), NOT a
// string carrying a nested JSON document. This is the whole point of protocol
// revision 2 — a regression back to JSON-in-a-string would flip the Kind.
func TestControlMessagesAreNativeMaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  any
	}{
		{"SessionRequest", SessionRequest{Version: Version, Binds: []PortSpec{{Name: "smtp", Port: 25, Proto: "tcp"}}}},
		{"Event/ready", Event{Type: EventReady, Binds: []BindResult{{Name: "smtp", Port: 25, OK: true, PublicAddr: "203.0.113.7:25"}}}},
		{"Event/accept", Event{Type: EventAccept, ConnID: 7, Secret: "cafe", Name: "smtp", RemoteAddr: "198.51.100.9:40000"}},
		{"ConnArgs", ConnArgs{ConnID: 7, Secret: "cafe"}},
	} {
		v, err := Encode(tc.msg)
		if err != nil {
			t.Fatalf("%s: Encode: %v", tc.name, err)
		}
		if v.Kind() != value.MAP {
			t.Fatalf("%s: wire Kind = %v, want MAP (a JSON-in-string regression?)", tc.name, v.Kind())
		}
	}
}

func TestSessionRequestRoundTrip(t *testing.T) {
	in := SessionRequest{
		Version: Version,
		Token:   "shared-key",
		Binds: []PortSpec{
			{Name: "smtp", Port: 25, Proto: "tcp"},
			{Name: "imaps", Port: 993, Proto: "tcp"},
		},
	}
	v, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out SessionRequest
	if err := Decode(v, &out); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Version != in.Version || out.Token != in.Token || len(out.Binds) != 2 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.Binds[1].Name != "imaps" || out.Binds[1].Port != 993 {
		t.Fatalf("bind round-trip mismatch: %+v", out.Binds)
	}
}

func TestEventRoundTrip(t *testing.T) {
	in := Event{
		Type:   EventAccept,
		ConnID: 42,
		Secret: "deadbeef",
		Name:   "smtp",
		Port:   25,

		RemoteAddr: "198.51.100.9:40000",
	}
	v, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Event
	if err := Decode(v, &out); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Type != in.Type || out.ConnID != in.ConnID || out.Secret != in.Secret ||
		out.Name != in.Name || out.Port != in.Port || out.RemoteAddr != in.RemoteAddr {
		t.Fatalf("event round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

// TestDecodeRejectsNonMap: a non-map argument (a bare string, a protocol-1 JSON
// blob, a nil) is refused with a clear error rather than silently yielding a
// zero-value struct.
func TestDecodeRejectsNonMap(t *testing.T) {
	for _, bad := range []value.Value{
		value.Utf8(`{"version":"1"}`), // a protocol-1 JSON-in-string request
		value.Raw([]byte("garbage"), false),
		value.Long(5),
		nil,
	} {
		var out SessionRequest
		if err := Decode(bad, &out); err == nil {
			t.Fatalf("Decode accepted a non-map value %v", bad)
		}
	}
}

// TestCodecTyped exercises the valuerpc.Codec adapter used by value-rpc's typed
// helpers.
func TestCodecTyped(t *testing.T) {
	c := Codec[ConnArgs]()
	v := c.Encode(ConnArgs{ConnID: 3, Secret: "s3cr3t"})
	if v.Kind() != value.MAP {
		t.Fatalf("codec Encode Kind = %v, want MAP", v.Kind())
	}
	out, err := c.Decode(v)
	if err != nil {
		t.Fatalf("codec Decode: %v", err)
	}
	if out.ConnID != 3 || out.Secret != "s3cr3t" {
		t.Fatalf("codec round-trip mismatch: %+v", out)
	}
}

// TestDialPortAllowed locks the outbound port allowlist: mail ports plus the
// HTTP(S) ports the remote-image proxy fetches over — and nothing else, so the
// relay never becomes a general TCP proxy.
func TestDialPortAllowed(t *testing.T) {
	for _, p := range []int{25, 465, 587, 2525, 2465, 2587, 80, 443, 8080, 8443} {
		if !DialPortAllowed(p) {
			t.Errorf("DialPortAllowed(%d) = false, want true", p)
		}
	}
	for _, p := range []int{22, 3306, 6379, 8443 + 1, 1, 65535, 0, 8081} {
		if DialPortAllowed(p) {
			t.Errorf("DialPortAllowed(%d) = true, want false (not an allowed egress port)", p)
		}
	}
}
