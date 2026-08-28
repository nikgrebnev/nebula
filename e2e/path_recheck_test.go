//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/cert_test"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathRecheckReHandshakes(t *testing.T) {
	ca, _, caKey, _ := cert_test.NewTestCaCert(cert.Version1, cert.Curve_CURVE25519, time.Now(), time.Now().Add(10*time.Minute), nil, nil, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConf := newSimpleServer(cert.Version1, ca, caKey, "me", "10.128.0.1/24", m{
		"timers": m{
			"rehandshake_interval":      "1s",
			"connection_alive_interval": 1,
		},
	})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(cert.Version1, ca, caKey, "them", "10.128.0.2/24", nil)

	require.Equal(t, time.Second, myConf.GetDuration("timers.rehandshake_interval", 0),
		"the interval has to reach the node before its effect can be judged")

	myControl.InjectLightHouseAddr(theirVpnIpNet[0].Addr(), theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet[0].Addr(), myUdpAddr)

	myControl.Start()
	theirControl.Start()
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	assertTunnel(t, myVpnIpNet[0].Addr(), theirVpnIpNet[0].Addr(), myControl, theirControl, r)

	first := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false)
	require.NotNil(t, first, "the tunnel has to exist before it can be rechecked")

	changed := false
	for i := 0; i < 60 && !changed; i++ {
		// Inject first, then route: RouteForAllUntilTxTun blocks until a packet
		// arrives, so routing before sending deadlocks the harness.
		//
		// Both directions matter: the connection manager only considers a
		// rehandshake for a tunnel with INCOMING traffic, so a one-way stream
		// keeps the tunnel busy and still never reaches the decision.
		myControl.InjectTunPacket(BuildTunUDPPacket(theirVpnIpNet[0].Addr(), 80, myVpnIpNet[0].Addr(), 80, []byte("out")))
		r.RouteForAllUntilTxTun(theirControl)
		theirControl.InjectTunPacket(BuildTunUDPPacket(myVpnIpNet[0].Addr(), 80, theirVpnIpNet[0].Addr(), 80, []byte("back")))
		r.RouteForAllUntilTxTun(myControl)
		time.Sleep(200 * time.Millisecond)

		if now := myControl.GetHostInfoByVpnAddr(theirVpnIpNet[0].Addr(), false); now != nil {
			changed = now.LocalIndex != first.LocalIndex
		}
	}

	assert.True(t, changed, "an aged tunnel carrying traffic must be re-handshaked by the periodic recheck")

	myControl.Stop()
	theirControl.Stop()
}
