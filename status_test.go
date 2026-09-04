package nebula

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	cert_test "github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StatusReport_NamesThePathEachPeerIsOn(t *testing.T) {
	pin := netip.MustParseAddr("10.0.0.2")
	relay := netip.MustParseAddr("10.0.0.6")
	remote := netip.MustParseAddrPort("192.0.2.5:4242")

	hosts := []ControlHostInfo{
		// A measured pin is the path, even though a direct remote exists: that
		// is exactly what the send path does, and reporting "direct" here would
		// be a lie that hides the whole point of path probing.
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")},
			CurrentRemote: remote, PinnedRelay: pin, MessageCounter: 7},
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.12")},
			CurrentRemote: remote},
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.13")},
			CurrentRelaysToMe: []netip.Addr{relay}},
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.14")}},
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.15")},
			CurrentRemote: remote, ForwardingFor: []netip.Addr{relay, pin}},
	}

	rep := buildStatusReport(hosts, "1.11.1-test", "5m0s", true, false)

	assert.Equal(t, "relay 10.0.0.2 (measured)", rep.Peers[0].Path)
	assert.Equal(t, "direct", rep.Peers[1].Path)
	assert.Equal(t, "relay 10.0.0.6", rep.Peers[2].Path)
	assert.Equal(t, "unknown", rep.Peers[3].Path, "a peer with no remote and no relay is not on a path")

	assert.Equal(t, 5, rep.Counts.Peers)
	assert.Equal(t, 2, rep.Counts.Direct)
	assert.Equal(t, 2, rep.Counts.Relayed, "the unknown peer counts as neither")
	assert.Equal(t, 1, rep.Counts.Pinned)
	assert.Equal(t, 2, rep.Counts.RelaysThroughMe, "two pairs, and only one end of each is a peer here")
	assert.True(t, rep.AmRelay)
	assert.False(t, rep.AmLighthouse)
}

// Forwarding for a pair leaves a record on both of its ends: on the peer the
// traffic comes from and on the peer it goes to. Adding up the per-peer lists
// therefore reports twice the work this node is doing.
func Test_StatusReport_CountsEachCarriedPairOnce(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.11")
	b := netip.MustParseAddr("10.0.0.12")
	c := netip.MustParseAddr("10.0.0.13")
	remote := netip.MustParseAddrPort("192.0.2.5:4242")

	// This node carries two pairs: a to b, and a to c.
	hosts := []ControlHostInfo{
		{VpnAddrs: []netip.Addr{a}, CurrentRemote: remote, ForwardingFor: []netip.Addr{b, c}},
		{VpnAddrs: []netip.Addr{b}, CurrentRemote: remote, ForwardingFor: []netip.Addr{a}},
		{VpnAddrs: []netip.Addr{c}, CurrentRemote: remote, ForwardingFor: []netip.Addr{a}},
	}

	rep := buildStatusReport(hosts, "v", "1s", true, false)

	assert.Equal(t, 2, rep.Counts.RelaysThroughMe, "two pairs are carried, not four ends")
	// The per-peer lists still show both ends: the page answers "who goes
	// through me" one peer at a time.
	assert.Equal(t, []netip.Addr{b, c}, rep.Peers[0].ForwardingFor)
	assert.Equal(t, []netip.Addr{a}, rep.Peers[1].ForwardingFor)
}

// A peer known by several addresses is still one peer, and the far end of a
// pair may name any of them.
func Test_StatusReport_CountsAPairOnceAcrossPeerAddresses(t *testing.T) {
	a4 := netip.MustParseAddr("10.0.0.11")
	a6 := netip.MustParseAddr("fd00::11")
	b := netip.MustParseAddr("10.0.0.12")

	hosts := []ControlHostInfo{
		{VpnAddrs: []netip.Addr{a4, a6}, ForwardingFor: []netip.Addr{b}},
		{VpnAddrs: []netip.Addr{b}, ForwardingFor: []netip.Addr{a6}},
	}

	rep := buildStatusReport(hosts, "v", "1s", true, false)

	assert.Equal(t, 1, rep.Counts.RelaysThroughMe, "one pair, named by two of the same peer's addresses")
}

func Test_StatusReport_SurvivesJson(t *testing.T) {
	// The endpoint's whole reason to exist is being read by a machine, so the
	// report has to round-trip. Empty relay lists must not appear at all: a
	// reader that sees "relaysToMe": null learns nothing and has to guess.
	rep := buildStatusReport([]ControlHostInfo{
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")},
			CurrentRemote: netip.MustParseAddrPort("192.0.2.5:4242")},
	}, "v", "1s", false, true)

	b, err := json.Marshal(rep)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "relaysToMe")
	assert.NotContains(t, string(b), "pinnedRelay")

	var back statusReport
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, rep.Counts, back.Counts)
	assert.Equal(t, "direct", back.Peers[0].Path)
}

// countingCert answers how many times a certificate was deep copied. Embedding
// the interface keeps the fake to the one method under test: the report has no
// business calling any of the others, and a nil embedded interface says so by
// panicking if it does.
type countingCert struct {
	cert.Certificate
	copies atomic.Int64
}

func (c *countingCert) Copy() cert.Certificate {
	c.copies.Add(1)
	return c
}

// The report answers "which way does this peer's traffic go" and never looks at
// a certificate, but building it out of full ControlHostInfo values deep copied
// one per peer, under the hostmap read lock that tunnel setup and teardown
// need. A loop of requests against a lighthouse then costs it real work.
func Test_StatusReport_DoesNotCopyCertificates(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	crt := &countingCert{}
	for i := range 4 {
		addTestPeer(hm, netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", 11+i)), crt)
	}

	s := &statusServer{
		l:       l,
		c:       config.NewC(l),
		ctrl:    &Control{f: &Interface{hostMap: hm}},
		started: time.Now(),
	}

	rep := s.report()

	require.Len(t, rep.Peers, 4)
	assert.Zero(t, crt.copies.Load(), "the report must not copy a certificate it never reads")
}

// Every request walking the whole hostmap means a client polling in a loop
// spends the node's hostmap read lock, which is the lock tunnel setup and
// teardown need. Inside the window the last report is handed out again.
func Test_StatusServer_ReportIsCachedBriefly(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})
	addTestPeer(hm, netip.MustParseAddr("10.0.0.11"), nil)

	s := &statusServer{
		l:       l,
		c:       config.NewC(l),
		ctrl:    &Control{f: &Interface{hostMap: hm}},
		started: time.Now(),
	}

	require.Equal(t, 1, s.report().Counts.Peers)

	addTestPeer(hm, netip.MustParseAddr("10.0.0.12"), nil)
	assert.Equal(t, 1, s.report().Counts.Peers, "a request inside the window must not walk the hostmap again")

	time.Sleep(statusReportTTL + 100*time.Millisecond)
	assert.Equal(t, 2, s.report().Counts.Peers, "the page must not go stale for longer than that")
}

// addTestPeer puts one peer in the hostmap, holding crt if one is given.
func addTestPeer(hm *HostMap, addr netip.Addr, crt cert.Certificate) {
	hi := &HostInfo{
		vpnAddrs:     []netip.Addr{addr},
		localIndexId: 100,
		remotes:      NewRemoteList([]netip.Addr{addr}, nil),
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}
	if crt != nil {
		hi.ConnectionState = &ConnectionState{peerCert: &cert.CachedCertificate{Certificate: crt}}
	}
	hm.unlockedAddHostInfo(hi, &Interface{})
}

// http.Server has no deadlines of its own. A client that asks for the page and
// then stops reading holds a goroutine for as long as it likes, and a
// kept-alive connection is never reclaimed, so the cheapest possible client
// can pin a node's memory.
func Test_StatusServer_ListenerHasDeadlines(t *testing.T) {
	s, addr := startTestStatusServer(t)
	waitForStatusPage(t, addr)

	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()

	require.NotNil(t, srv)
	assert.NotZero(t, srv.ReadHeaderTimeout, "a slow header must not hold a connection open")
	assert.NotZero(t, srv.ReadTimeout, "a slow body must not hold a connection open")
	assert.NotZero(t, srv.WriteTimeout, "a client that stops reading must not park a goroutine forever")
	assert.NotZero(t, srv.IdleTimeout, "an idle kept-alive connection must be reclaimed")
}

// A HUP that changes status.listen has to move the listener. Recording the
// address and doing nothing else leaves the page answering on the old address,
// with nothing in the log to say so.
func Test_StatusServer_ReloadMovesTheListener(t *testing.T) {
	s, first := startTestStatusServer(t)
	waitForStatusPage(t, first)

	second := freeTCPAddr(t)
	s.c.Settings["status"] = map[string]any{"listen": second}
	require.NoError(t, s.reload(s.c))

	waitForStatusPage(t, second)
	waitForRefused(t, first)
}

// Emptying status.listen turns the endpoint off, rather than leaving it serving
// a page the operator has asked to be taken away.
func Test_StatusServer_ReloadCanTurnTheEndpointOff(t *testing.T) {
	s, addr := startTestStatusServer(t)
	waitForStatusPage(t, addr)

	s.c.Settings["status"] = map[string]any{"listen": ""}
	require.NoError(t, s.reload(s.c))

	waitForRefused(t, addr)
}

// `nebula -test` has to reject a status.listen that is not an address. The
// listener used to be built after the config test had already returned, so a
// typo went unnoticed until the next restart, which is exactly the moment a
// config test exists to move.
func Test_StatusListen_IsCheckedByConfigTest(t *testing.T) {
	l := test.NewLogger()

	load := func(t *testing.T, listen string) *config.C {
		t.Helper()
		dir := t.TempDir()

		before := time.Now().Add(-time.Hour)
		after := time.Now().Add(time.Hour)
		ca, _, caKey, caPEM := cert_test.NewTestCaCert(cert.Version2, cert.Curve_CURVE25519, before, after, nil, nil, nil)
		networks := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}
		_, _, keyPEM, certPEM := cert_test.NewTestCert(cert.Version2, cert.Curve_CURVE25519, ca, caKey, "status-config-test", before, after, networks, nil, nil)

		require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600))

		body := fmt.Sprintf(`
pki:
  ca: %s
  cert: %s
  key: %s
tun:
  disabled: true
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
status:
  listen: %q
`, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), listen)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte(body), 0o600))

		c := config.NewC(l)
		require.NoError(t, c.Load(dir))
		return c
	}

	ctrl, err := Main(load(t, "127.0.0.1"), true, "status-config-test", l, nil)
	require.Error(t, err, "a status.listen without a port must fail the config test")
	assert.Contains(t, err.Error(), "status.listen")
	assert.Nil(t, ctrl)

	// The check has to pass a usable address, otherwise the test above would
	// pass for any reason at all.
	ctrl, err = Main(load(t, "127.0.0.1:4280"), true, "status-config-test", l, nil)
	require.NoError(t, err)
	assert.Nil(t, ctrl, "a config test never returns a Control")
}

// startTestStatusServer brings a status server up on a free port, reporting on
// an empty hostmap, and tears it down when the test ends.
func startTestStatusServer(t *testing.T) (*statusServer, string) {
	t.Helper()
	l := test.NewLogger()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	hm := newHostMap(l)
	hm.preferredRanges.Store(&[]netip.Prefix{})

	addr := freeTCPAddr(t)
	c := config.NewC(l)
	c.Settings["status"] = map[string]any{"listen": addr}

	s := &statusServer{
		l:       l,
		ctx:     ctx,
		c:       c,
		ctrl:    &Control{f: &Interface{hostMap: hm}},
		started: time.Now(),
	}
	require.NoError(t, s.reload(c))
	s.Start()
	t.Cleanup(s.Stop)

	return s, addr
}

// freeTCPAddr hands back an address nothing is listening on. The port is
// released before it is returned, which can lose a race with an unrelated
// listener; losing it costs a flaky failure, not a wrong answer.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

var statusTestClient = &http.Client{
	Timeout:   2 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

// waitForStatusPage polls until the page answers. Start binds in a goroutine of
// its own, so the first request can arrive before the listener does.
func waitForStatusPage(t *testing.T, addr string) {
	t.Helper()
	var lastErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		resp, err := statusTestClient.Get("http://" + addr + "/status")
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return
	}
	t.Fatalf("status page at %s never answered: %v", addr, lastErr)
}

// waitForRefused polls until nothing accepts a connection on addr.
func waitForRefused(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return
		}
		_ = conn.Close()
	}
	t.Fatalf("something is still listening on %s", addr)
}
