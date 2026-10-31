/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func fast(t *testing.T) {
	t.Helper()
	was := PollEvery
	PollEvery = 20 * time.Millisecond
	t.Cleanup(func() { PollEvery = was })
}

// collector gathers the notices Watch reports.
type collector struct {
	mu sync.Mutex
	ns []Notice
}

func (c *collector) add(n Notice) {
	c.mu.Lock()
	c.ns = append(c.ns, n)
	c.mu.Unlock()
}

func (c *collector) wait(t *testing.T, n int) []Notice {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := append([]Notice(nil), c.ns...)
		c.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("waited for %d notices, have %+v", n, c.ns)
	return nil
}

// The DMI vendor names the cloud; anything else is no cloud.
func TestVendor(t *testing.T) {
	for dmi, want := range map[string]string{"Google": VendorGoogle, "Amazon EC2": VendorAWS, "Microsoft Corporation": VendorAzure, "QEMU": "", "": ""} {
		if got := VendorOf(dmi); got != want {
			t.Fatalf("%q → %q, want %q", dmi, got, want)
		}
	}
	p := filepath.Join(t.TempDir(), "sys_vendor")
	if err := os.WriteFile(p, []byte("Amazon EC2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	was := DMIVendorPath
	DMIVendorPath = p
	t.Cleanup(func() { DMIVendorPath = was })
	if Vendor() != VendorAWS {
		t.Fatal("the file's vendor")
	}
	DMIVendorPath = filepath.Join(t.TempDir(), "missing")
	if Vendor() != "" {
		t.Fatal("no file: no cloud")
	}
	// an unknown vendor's Watch returns at once
	done := make(chan struct{})
	go func() { Watch(context.Background(), nil, "", func(Notice) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Watch for no cloud must return")
	}
}

// Google: the metadata server answers the blocking request with TRUE once the preemption began — one notice,
// without a deadline (Google does not publish one), said once even though the flag stays TRUE.
func TestGoogleWatch(t *testing.T) {
	fast(t)
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" || r.URL.Path != "/computeMetadata/v1/instance/preempted" || r.URL.Query().Get("wait_for_change") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			time.Sleep(30 * time.Millisecond) // the long poll: nothing changes yet
			_, _ = w.Write([]byte("FALSE"))
			return
		}
		_, _ = w.Write([]byte("TRUE"))
	}))
	defer srv.Close()
	was := GoogleBase
	GoogleBase = srv.URL
	t.Cleanup(func() { GoogleBase = was })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &collector{}
	go Watch(ctx, zap.NewNop(), VendorGoogle, c.add)
	got := c.wait(t, 1)
	if got[0].Why != "preempted" || !got[0].Deadline.IsZero() {
		t.Fatalf("notice: %+v", got[0])
	}
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	n := len(c.ns)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("said once, not %d times", n)
	}
}

// AWS: IMDSv2 — the token first, then the Spot action's JSON (its action and time) and the rebalance
// recommendation; an expired token (401) is replaced.
func TestAWSWatch(t *testing.T) {
	fast(t)
	var mu sync.Mutex
	tokens, action, rebalance := 0, false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			tokens++
			_, _ = w.Write([]byte("tok" + string(rune('0'+tokens))))
		case r.Header.Get("X-aws-ec2-metadata-token") == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Header.Get("X-aws-ec2-metadata-token") == "tok1":
			w.WriteHeader(http.StatusUnauthorized) // the first token expired
		case r.URL.Path == "/latest/meta-data/spot/instance-action":
			if !action {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"action": "terminate", "time": "2026-11-01T08:22:00Z"}`))
		case r.URL.Path == "/latest/meta-data/events/recommendations/rebalance":
			if !rebalance {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"noticeTime": "2026-11-01T08:20:00Z"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	was := AWSBase
	AWSBase = srv.URL
	t.Cleanup(func() { AWSBase = was })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &collector{}
	go Watch(ctx, zap.NewNop(), VendorAWS, c.add)
	time.Sleep(80 * time.Millisecond) // quiet: nothing yet, the token renewed once
	mu.Lock()
	rebalance = true
	mu.Unlock()
	got := c.wait(t, 1)
	if got[0].Why != "rebalance" || !got[0].Deadline.IsZero() {
		t.Fatalf("the recommendation: %+v", got[0])
	}
	mu.Lock()
	action = true
	mu.Unlock()
	got = c.wait(t, 2)
	if got[1].Why != "terminate" || got[1].Deadline.UTC().Format(time.RFC3339) != "2026-11-01T08:22:00Z" {
		t.Fatalf("the action: %+v", got[1])
	}
	mu.Lock()
	tk := tokens
	mu.Unlock()
	if tk < 2 {
		t.Fatalf("the expired token must be replaced: %d tokens", tk)
	}
}

// Azure: scheduled events — a Preempt with its NotBefore; a Reboot is not a leaving; the same event is said once.
func TestAzureWatch(t *testing.T) {
	fast(t)
	var mu sync.Mutex
	preempt := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" || r.URL.Path != "/metadata/scheduledevents" || r.URL.Query().Get("api-version") != "2020-07-01" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !preempt {
			_, _ = w.Write([]byte(`{"DocumentIncarnation": 1, "Events": [{"EventId": "r1", "EventType": "Reboot", "NotBefore": "Mon, 02 Nov 2026 18:29:47 GMT"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"DocumentIncarnation": 2, "Events": [{"EventId": "p1", "EventType": "Preempt", "NotBefore": "Mon, 02 Nov 2026 18:30:17 GMT"}]}`))
	}))
	defer srv.Close()
	was := AzureBase
	AzureBase = srv.URL
	t.Cleanup(func() { AzureBase = was })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &collector{}
	go Watch(ctx, zap.NewNop(), VendorAzure, c.add)
	time.Sleep(80 * time.Millisecond)
	c.mu.Lock()
	n := len(c.ns)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("a reboot is not a leaving: %+v", c.ns)
	}
	mu.Lock()
	preempt = true
	mu.Unlock()
	got := c.wait(t, 1)
	if got[0].Why != "preempt" || got[0].Deadline.UTC().Format(time.RFC1123) != "Mon, 02 Nov 2026 18:30:17 UTC" {
		t.Fatalf("the preempt: %+v", got[0])
	}
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	n = len(c.ns)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("said once, not %d times", n)
	}
}
