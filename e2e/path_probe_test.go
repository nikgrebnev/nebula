//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPathProbePinsARelay drives timers.path_probe_interval end to end.
//
// The peer is reachable only through relays and there are two of them, so there
// is a real choice to make: the send path would otherwise just take the first
// relay in the list. A pin appearing on the tunnel is the observable proof that
// the whole pipeline ran - candidates built, probes sent over each path, replies
// matched back to the leg they came from, a decision taken and recorded where an
// operator can see it.
func TestPathProbePinsARelay(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myControl, myVpnIpNet, _, myConf := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{
		// Both relays are configured, the way they are on a real node: the probe
		// takes its candidates from the configured relays, not only from the one
		// the tunnel happened to come up through.
		"relay": m{"use_relays": true, "relays": []string{"10.128.0.128", "10.128.0.129"}},
		"timers": m{
			"path_probe_interval":       "1s",
			"path_probe_margin":         "1ms",
			"connection_alive_interval": 1,
		},
	})
	helper1Control, helper1VpnIpNet, helper1UdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "helper1", "10.128.0.128/24",
		m{"relay": m{"am_relay": true}})
	helper2Control, helper2VpnIpNet, helper2UdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "helper2", "10.128.0.129/24",
		m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24",
		m{"relay": m{"use_relays": true}})

	require.Equal(t, time.Second, myConf.GetDuration("timers.path_probe_interval", 0),
		"the interval has to reach the node before its effect can be judged")

	// me can reach both helpers, and knows them is reachable through either.
	// me is never told a direct address for them, so relays are the only paths
	// and the probe has two of them to compare.
	myControl.InjectLightHouseAddr(helper1VpnIpNet[0].Addr(), helper1UdpAddr)
	myControl.InjectLightHouseAddr(helper2VpnIpNet[0].Addr(), helper2UdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{helper1VpnIpNet[0].Addr(), helper2VpnIpNet[0].Addr()})
	helper1Control.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	helper2Control.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, helper1Control, helper2Control, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	helper1Control.Start()
	helper2Control.Start()
	theirControl.Start()

	// Both relays need a tunnel of their own before either can carry anything.
	// Probing compares the relays it can reach; it does not bring up tunnels to
	// relays it has never spoken to, that is the handshake's job.
	for _, h := range []struct {
		control *nebula.Control
		addr    netip.Addr
	}{{helper1Control, helper1VpnIpNet[0].Addr()}, {helper2Control, helper2VpnIpNet[0].Addr()}} {
		myControl.InjectTunPacket(BuildTunUDPPacket(h.addr, 80, myVpnIpNet[0].Addr(), 80, []byte("wake")))
		r.RouteForAllUntilTxTun(h.control)
	}

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("hello")))
	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("hello"), p, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), 80, 80)

	pinned := netip.Addr{}
	for i := 0; i < 60 && !pinned.IsValid(); i++ {
		// Inject first, then route: RouteForAllUntilTxTun blocks until a packet
		// arrives. Both directions, because only a tunnel with incoming traffic
		// is reconsidered at all.
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("out")))
		r.RouteForAllUntilTxTun(theirControl)
		theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("back")))
		r.RouteForAllUntilTxTun(myControl)
		time.Sleep(200 * time.Millisecond)

		if hi := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false); hi != nil {
			pinned = hi.PinnedRelay
		}
	}

	require.True(t, pinned.IsValid(), "probing has to pick one of the two relays and say which")
	assert.Contains(t,
		[]netip.Addr{helper1VpnIpNet[0].Addr(), helper2VpnIpNet[0].Addr()},
		pinned,
		"the pinned path has to be one of the relays actually offered")

	myControl.Stop()
	helper1Control.Stop()
	helper2Control.Stop()
	theirControl.Stop()
}

// TestPathProbeOffByDefault guards the promise the option makes: unset means the
// old behaviour, exactly. Same topology as above, no path_probe_interval, and
// nothing may be pinned however long the tunnel runs. A feature that quietly
// turns itself on is worse than one that does nothing.
func TestPathProbeOffByDefault(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})

	myControl, myVpnIpNet, _, _ := newSimpleServer(cert.Version1, ca, caKey, "me     ", "10.128.0.1/24", m{
		"relay":  m{"use_relays": true, "relays": []string{"10.128.0.128", "10.128.0.129"}},
		"timers": m{"connection_alive_interval": 1},
	})
	helper1Control, helper1VpnIpNet, helper1UdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "helper1", "10.128.0.128/24",
		m{"relay": m{"am_relay": true}})
	helper2Control, helper2VpnIpNet, helper2UdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "helper2", "10.128.0.129/24",
		m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them   ", "10.128.0.2/24",
		m{"relay": m{"use_relays": true}})

	myControl.InjectLightHouseAddr(helper1VpnIpNet[0].Addr(), helper1UdpAddr)
	myControl.InjectLightHouseAddr(helper2VpnIpNet[0].Addr(), helper2UdpAddr)
	myControl.InjectRelays(theirVpnIpNet[0].Addr(), []netip.Addr{helper1VpnIpNet[0].Addr(), helper2VpnIpNet[0].Addr()})
	helper1Control.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	helper2Control.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)

	r := router.NewR(t, myControl, helper1Control, helper2Control, theirControl)
	defer r.RenderFlow()

	myControl.Start()
	helper1Control.Start()
	helper2Control.Start()
	theirControl.Start()

	myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("hello")))
	r.RouteForAllUntilTxTun(theirControl)

	for i := 0; i < 25; i++ {
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("out")))
		r.RouteForAllUntilTxTun(theirControl)
		theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("back")))
		r.RouteForAllUntilTxTun(myControl)
		time.Sleep(200 * time.Millisecond)

		if hi := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false); hi != nil {
			require.False(t, hi.PinnedRelay.IsValid(),
				"with the interval unset nothing may pin a path")
		}
	}

	myControl.Stop()
	helper1Control.Stop()
	helper2Control.Stop()
	theirControl.Stop()
}
