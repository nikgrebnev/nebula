//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
)

// TestRelayIsAlsoAClient shows that a node forwarding for others can still be
// forwarded itself.
//
// Setting relay.am_relay used to take a node's own relays away, in two separate
// places, so a relay could only ever reach peers it had a direct path to. That
// forced a choice that should not exist: on a real network two nodes that see
// everybody had to be demoted from relays to plain clients purely so they could
// reach a datacentre they have no direct path to.
//
// Chains stay impossible without that coupling, because handleCreateRelayRequest
// forwards only to peers it holds a direct tunnel with.
func TestRelayIsAlsoAClient(t *testing.T) {
	t.Parallel()
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	// "me" forwards for others and, at the same time, has no direct path to
	// "them" and must go through "helper".
	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24",
		m{"relay": m{"am_relay": true, "use_relays": true}})
	helperControl, helperVpnIpNet, helperUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "helper ", "10.128.0.128/24",
		m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24",
		m{"relay": m{"use_relays": true}})

	// me knows how to reach helper, and knows them is reachable through it.
	// Note me is never told a direct address for them.
	myControl.InjectLightHouseAddr(helperVpnIpNet[0].Addr(), helperUdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{helperVpnIpNet[0].Addr()})
	helperControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, helperControl, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	helperControl.Start()
	theirControl.Start()

	t.Log("A node that is itself a relay reaches a peer through another relay")
	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("Hi from a relay")))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from a relay"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	r.RenderHostmaps("Final hostmaps", myControl, helperControl, theirControl)
}
