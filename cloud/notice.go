/*
 * Copyright 2022-present Karagatan LLC.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
Package cloud is the relay's ear at its cloud: when the machine the relay runs on is about to be taken — a Spot
eviction, a scheduled host event — the cloud says so first on its metadata server, and this package turns that into
one Notice the relay broadcasts to every paired mailnite as a `leaving` event (protocol.EventLeaving), so the
successor can boot while this machine still serves. The cloud is told apart by the DMI system vendor; a machine
that is not at one of the three clouds has no watcher. No dependency beyond the standard library; the metadata
addresses are variables so the tests stand in with their own servers.
*/
package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Notice is one word from the cloud: why the machine goes, and when (the zero time when the cloud named none —
// Google says only that preemption began; a rebalance recommendation is advisory).
type Notice struct {
	Why      string
	Deadline time.Time
}

// The clouds by their DMI vendor string.
const (
	VendorGoogle = "gcp"
	VendorAWS    = "aws"
	VendorAzure  = "azure"
)

// The metadata servers, as variables for the tests.
var (
	DMIVendorPath = "/sys/class/dmi/id/sys_vendor"
	GoogleBase    = "http://metadata.google.internal"
	AWSBase       = "http://169.254.169.254"
	AzureBase     = "http://169.254.169.254"
	// PollEvery paces the AWS and Azure pollers (Google's metadata server blocks until a change).
	PollEvery = 5 * time.Second
)

// Vendor reads the machine's DMI system vendor and names the cloud, "" for anything else.
func Vendor() string {
	b, err := os.ReadFile(DMIVendorPath)
	if err != nil {
		return ""
	}
	return VendorOf(strings.TrimSpace(string(b)))
}

// VendorOf maps a DMI vendor string to a cloud.
func VendorOf(dmi string) string {
	switch {
	case strings.HasPrefix(dmi, "Google"):
		return VendorGoogle
	case strings.HasPrefix(dmi, "Amazon"):
		return VendorAWS
	case strings.HasPrefix(dmi, "Microsoft"):
		return VendorAzure
	}
	return ""
}

// Watch polls the cloud's metadata server until ctx ends and calls notify once per distinct notice (a changed
// deadline is a new notice). vendor is one of the Vendor constants; anything else returns at once.
func Watch(ctx context.Context, log *zap.Logger, vendor string, notify func(Notice)) {
	if log == nil {
		log = zap.NewNop()
	}
	w := &watcher{log: log, notify: notify, client: &http.Client{Timeout: 10 * time.Second}}
	switch vendor {
	case VendorGoogle:
		w.google(ctx)
	case VendorAWS:
		w.aws(ctx)
	case VendorAzure:
		w.azure(ctx)
	default:
		return
	}
}

type watcher struct {
	log    *zap.Logger
	notify func(Notice)
	client *http.Client
	last   Notice
	said   bool
}

// say reports a notice the first time it is seen (why and deadline together).
func (w *watcher) say(n Notice) {
	if w.said && w.last.Why == n.Why && w.last.Deadline.Equal(n.Deadline) {
		return
	}
	w.last, w.said = n, true
	w.log.Warn("CloudLeaving", zap.String("why", n.Why), zap.Time("deadline", n.Deadline))
	if w.notify != nil {
		w.notify(n)
	}
}

func (w *watcher) get(ctx context.Context, url string, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, b, nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// google: the metadata server holds the request until the preempted flag changes (wait_for_change) — TRUE means the
// 30-second (or the preemptionNoticeDuration) countdown began; the deadline is not published, so the notice carries
// none and mailnite applies what it read back at creation.
func (w *watcher) google(ctx context.Context) {
	client := &http.Client{} // no timeout: the request blocks by design (timeout_sec bounds it server-side)
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, GoogleBase+"/computeMetadata/v1/instance/preempted?wait_for_change=true&timeout_sec=300", nil)
		if err != nil {
			return
		}
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil {
			if !sleep(ctx, PollEvery) {
				return
			}
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.EqualFold(strings.TrimSpace(string(b)), "TRUE") {
			w.say(Notice{Why: "preempted"})
			if !sleep(ctx, PollEvery) {
				return
			}
		}
	}
}

// aws: IMDSv2 — a session token, then the Spot instance action (200 = a terminate/stop/hibernate is coming at its
// time) and the rebalance recommendation (advisory: a notice without a deadline, said once).
func (w *watcher) aws(ctx context.Context) {
	var token string
	for ctx.Err() == nil {
		if token == "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, AWSBase+"/latest/api/token", nil)
			if err != nil {
				return
			}
			req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
			if resp, err := w.client.Do(req); err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					token = strings.TrimSpace(string(b))
				}
			}
			if token == "" {
				if !sleep(ctx, PollEvery) {
					return
				}
				continue
			}
		}
		hdr := map[string]string{"X-aws-ec2-metadata-token": token}
		code, body, err := w.get(ctx, AWSBase+"/latest/meta-data/spot/instance-action", hdr)
		switch {
		case err == nil && code == http.StatusUnauthorized:
			token = "" // the token expired: a new one next round
		case err == nil && code == http.StatusOK:
			var action struct {
				Action string `json:"action"`
				Time   string `json:"time"`
			}
			if json.Unmarshal(body, &action) == nil && action.Action != "" {
				n := Notice{Why: action.Action}
				if ts, err := time.Parse(time.RFC3339, action.Time); err == nil {
					n.Deadline = ts
				}
				w.say(n)
			}
		}
		if code, body, err := w.get(ctx, AWSBase+"/latest/meta-data/events/recommendations/rebalance", hdr); err == nil && code == http.StatusOK && len(body) > 0 && !w.said {
			w.say(Notice{Why: "rebalance"})
		}
		if !sleep(ctx, PollEvery) {
			return
		}
	}
}

// azure: the scheduled events endpoint lists what the platform is about to do to the machine; Preempt (Spot),
// Terminate and Redeploy take the machine away, at NotBefore.
func (w *watcher) azure(ctx context.Context) {
	for ctx.Err() == nil {
		code, body, err := w.get(ctx, AzureBase+"/metadata/scheduledevents?api-version=2020-07-01", map[string]string{"Metadata": "true"})
		if err == nil && code == http.StatusOK {
			var doc struct {
				Events []struct {
					EventType string `json:"EventType"`
					NotBefore string `json:"NotBefore"`
				} `json:"Events"`
			}
			if json.Unmarshal(body, &doc) == nil {
				for _, e := range doc.Events {
					switch e.EventType {
					case "Preempt", "Terminate", "Redeploy":
						n := Notice{Why: strings.ToLower(e.EventType)}
						if ts, err := time.Parse(time.RFC1123, e.NotBefore); err == nil {
							n.Deadline = ts
						}
						w.say(n)
					}
				}
			}
		}
		if !sleep(ctx, PollEvery) {
			return
		}
	}
}
