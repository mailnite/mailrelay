package relay_test

import (
	"context"
	"testing"
	"time"

	"github.com/mailnite/mailrelay/pki"
	"github.com/mailnite/mailrelay/protocol"
	"github.com/mailnite/mailrelay/relay"
	"github.com/mailnite/mailrelay/relayclient"
	"go.arpabet.com/value-rpc/valueserver"
	"go.uber.org/zap"
)

// The unary probe must be repeatable with no EADDRINUSE — it binds and releases
// each port, never holding it (the bug that made repeat "Check ports" fail).
func TestProbePortsRepeatable(t *testing.T) {
	log := zap.NewNop()
	ca, _ := pki.GenerateCA("t")
	sc, _ := ca.IssueServerCert([]string{"127.0.0.1"})
	cc, _ := ca.IssueClientCert("m")
	stls, _ := pki.ServerTLSConfig(sc.CertPEM, sc.KeyPEM, ca.CertPEM)
	srv, _ := valueserver.NewTLSServer("127.0.0.1:0", stls, log)
	tun := relay.New(log, "")
	tun.Register(srv)
	go srv.Run()
	defer srv.Close()
	defer tun.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	s, err := relayclient.Dial(ctx, relayclient.Config{Transport: protocol.TransportTCP, Addr: srv.Addr().String(), ServerName: "127.0.0.1", CAPEM: ca.CertPEM, ClientCertPEM: cc.CertPEM, ClientKeyPEM: cc.KeyPEM}, log)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer s.Close()

	// Probe a fixed port five times back to back — every one must succeed.
	for i := 0; i < 5; i++ {
		res, err := s.ProbePorts(ctx, []int{18055})
		if err != nil {
			t.Fatalf("probe #%d: %v", i, err)
		}
		if len(res) != 1 || !res[0].OK {
			t.Fatalf("probe #%d not OK: %+v", i, res)
		}
	}
}
