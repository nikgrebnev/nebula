package nebula

import (
	"encoding/json"
	"net/netip"
	"testing"

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
	assert.Equal(t, 2, rep.Counts.RelaysThroughMe)
	assert.True(t, rep.AmRelay)
	assert.False(t, rep.AmLighthouse)
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

func Test_RelayState_ForwardingIsNotTheSameAsUsingARelay(t *testing.T) {
	// relayForByAddr holds both kinds: relays where this host FORWARDS somebody
	// else's traffic, and relays where it is the far end. Counting the mix as
	// "traffic I carry" reported a node with am_relay: false as carrying 64
	// pairs, which is how this was found.
	carried := netip.MustParseAddr("10.0.0.31")
	viaMe := netip.MustParseAddr("10.0.0.32")
	toMe := netip.MustParseAddr("10.0.0.11")

	rs := &RelayState{relayForByAddr: map[netip.Addr]*Relay{
		carried: {Type: ForwardingType, PeerAddr: carried, State: Established},
		viaMe:   {Type: ForwardingType, PeerAddr: viaMe, State: Established},
		toMe:    {Type: TerminalType, PeerAddr: toMe, State: Established},
	}}

	fwd := rs.CopyForwardingPeers()
	assert.Len(t, fwd, 2, "only forwarded peers count as traffic this host carries")
	assert.NotContains(t, fwd, toMe, "being the far end of a relay is not carrying it")
	assert.Len(t, rs.CopyRelayForIps(), 3, "the mixed list still holds all three")
}
