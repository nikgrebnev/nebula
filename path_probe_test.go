package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

// oneRelay is the candidate list for the common shape: one relay against the
// direct remote.
var oneRelay = []netip.Addr{netip.MustParseAddr("172.1.1.2")}

// probePeer builds a peer with a direct remote and the named relays, which is
// the only shape worth probing: something to compare against something else.
func probePeer(t *testing.T, addr string, relays ...string) *HostInfo {
	t.Helper()
	hi := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr(addr)}}
	r := netip.MustParseAddrPort("10.1.1.5:4242")
	hi.remote.Store(&r)
	for _, relay := range relays {
		hi.relayState.InsertRelayTo(netip.MustParseAddr(relay))
	}
	return hi
}

func Test_PathProbe_LegsCoverEveryPath(t *testing.T) {
	two := []netip.Addr{netip.MustParseAddr("172.1.1.2"), netip.MustParseAddr("172.1.1.3")}
	one := two[:1]
	hi := probePeer(t, "172.1.1.9", "172.1.1.2", "172.1.1.3")
	now := time.Now()

	legs := hi.startPathProbe(7, now, two)
	assert.Len(t, legs, 3, "one leg for the direct remote and one per relay")
	assert.False(t, legs[0].relay.IsValid(), "leg 0 is always the direct remote")
	assert.Equal(t, two[0], legs[1].relay)
	assert.Equal(t, two[1], legs[2].relay)

	// A peer with nothing to compare against is not probed at all.
	assert.Nil(t, probePeer(t, "172.1.1.9").startPathProbe(8, now, nil),
		"a direct peer with no relay to compare has one path")

	relayOnly := &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("172.1.1.9")}}
	assert.Nil(t, relayOnly.startPathProbe(9, now, one),
		"one relay and no direct remote is still one path")

	// Two relays and no direct remote is a choice worth measuring: the send
	// path otherwise just takes the first relay in the list.
	legs = relayOnly.startPathProbe(10, now, two)
	assert.Len(t, legs, 2, "relay against relay is a comparison too")
	assert.Equal(t, two[0], legs[0].relay, "with no direct remote there is no leg 0 to skip")
}

func Test_PathProbe_MatchesReplyToLeg(t *testing.T) {
	hi := probePeer(t, "172.1.1.9", "172.1.1.2")
	now := time.Now()
	hi.startPathProbe(7, now, oneRelay)

	hi.notePathProbeReply(pathProbePayload(7, 1), now.Add(5*time.Millisecond))
	hi.notePathProbeReply(pathProbePayload(7, 0), now.Add(80*time.Millisecond))

	// A reply from a round that is over says nothing about this one.
	hi.notePathProbeReply(pathProbePayload(6, 1), now.Add(time.Millisecond))
	// Neither does a test packet that carries no payload of ours.
	hi.notePathProbeReply([]byte(""), now.Add(time.Millisecond))
	// Nor does a leg index that does not exist.
	hi.notePathProbeReply(pathProbePayload(7, 99), now.Add(time.Millisecond))

	p := hi.takePathProbe(now.Add(100 * time.Millisecond))
	if assert.NotNil(t, p, "every leg answered, so the round is finished") {
		direct, ok := p.leg(netip.Addr{})
		assert.True(t, ok, "the direct leg is named by the zero address")
		assert.Equal(t, 80*time.Millisecond, direct.rtt)

		best, ok := p.best()
		assert.True(t, ok)
		assert.Equal(t, netip.MustParseAddr("172.1.1.2"), best.relay)
		assert.Equal(t, 5*time.Millisecond, best.rtt)
	}

	assert.Nil(t, hi.takePathProbe(now.Add(time.Second)), "a round is only taken once")
}

func Test_PathProbe_FirstReplyIsTheMeasurement(t *testing.T) {
	hi := probePeer(t, "172.1.1.9", "172.1.1.2")
	now := time.Now()
	hi.startPathProbe(7, now, oneRelay)

	hi.notePathProbeReply(pathProbePayload(7, 1), now.Add(5*time.Millisecond))
	hi.notePathProbeReply(pathProbePayload(7, 1), now.Add(500*time.Millisecond))

	p := hi.takePathProbe(now.Add(pathProbeWait))
	if assert.NotNil(t, p) {
		assert.Equal(t, 5*time.Millisecond, p.legs[1].rtt, "a duplicate must not overwrite the first reply")
	}
}

func Test_PathProbe_RoundStaysOpenUntilAnsweredOrTimedOut(t *testing.T) {
	hi := probePeer(t, "172.1.1.9", "172.1.1.2")
	now := time.Now()
	hi.startPathProbe(7, now, oneRelay)

	hi.notePathProbeReply(pathProbePayload(7, 0), now.Add(time.Millisecond))
	assert.Nil(t, hi.takePathProbe(now.Add(time.Second)),
		"one leg is still out and the wait has not run out")

	p := hi.takePathProbe(now.Add(pathProbeWait))
	if assert.NotNil(t, p, "the wait ran out, judge with what arrived") {
		assert.False(t, p.legs[1].got)
		assert.Contains(t, p.describe(), "relay 172.1.1.2=no reply")
	}
}

func Test_PathProbe_DueGating(t *testing.T) {
	hi := probePeer(t, "172.1.1.9", "172.1.1.2")
	now := time.Now()

	assert.True(t, hi.probeDue(now, time.Minute), "the first round is always due")
	assert.False(t, hi.probeDue(now.Add(time.Second), time.Minute), "not due again yet")

	hi.startPathProbe(1, now, oneRelay)
	assert.False(t, hi.probeDue(now.Add(time.Hour), time.Minute),
		"a round in flight must not be joined by another")

	hi.takePathProbe(now.Add(pathProbeWait))
	assert.True(t, hi.probeDue(now.Add(time.Hour), time.Minute), "due again once the round is over")
}

func Test_PathProbe_PreferenceSurvivesRehandshake(t *testing.T) {
	relay := netip.MustParseAddr("172.1.1.2")
	prev := probePeer(t, "172.1.1.9", "172.1.1.2")
	next := probePeer(t, "172.1.1.9", "172.1.1.2")

	// Nothing measured yet means nothing to carry.
	carryPathPreference(prev, next)
	assert.False(t, next.PinnedRelay().IsValid())

	// A measured preference belongs to the peer, so it survives the tunnel it
	// was measured on. Without this a rehandshake puts traffic straight back on
	// the path the probe rejected, every time, until the next round.
	prev.pinRelay(relay)
	carryPathPreference(prev, next)
	assert.Equal(t, relay, next.PinnedRelay())

	// Guards, so a caller cannot make it undo itself.
	carryPathPreference(nil, next)
	assert.Equal(t, relay, next.PinnedRelay(), "no previous tunnel must not clear the pin")
	carryPathPreference(next, next)
	assert.Equal(t, relay, next.PinnedRelay(), "carrying onto itself must be a no-op")
}

func Test_PathProbe_PinIsVisibleInControl(t *testing.T) {
	relay := netip.MustParseAddr("172.1.1.2")
	hi := probePeer(t, "172.1.1.9", "172.1.1.2")
	hi.remotes = NewRemoteList(nil, nil)

	// An unpinned peer must not claim a path it is not on.
	assert.False(t, copyHostInfo(hi, nil).PinnedRelay.IsValid())

	hi.pinRelay(relay)
	assert.Equal(t, relay, copyHostInfo(hi, nil).PinnedRelay,
		"which path a peer is on has to be answerable without grepping the log")
}

// Test_PathProbe_DataPathHonoursThePin covers where the traffic actually goes.
//
// This is the code that fooled me: the decision was logged, the tests passed,
// and every data packet still went direct, because sendInsideMessage resolved
// the relay with its own copy of the logic. Nothing here was covered, which is
// exactly why it survived. A preference the data path ignores is not a
// preference.
func Test_PathProbe_DataPathHonoursThePin(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	f := &Interface{hostMap: hm, l: l}

	relayAddr := netip.MustParseAddr("10.0.0.2")
	peerAddr := netip.MustParseAddr("10.0.0.54")

	relayHI := &HostInfo{
		vpnAddrs:     []netip.Addr{relayAddr},
		localIndexId: 1,
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}
	relayHI.relayState.InsertRelay(peerAddr, 100, &Relay{
		Type: ForwardingType, State: Established, LocalIndex: 100, PeerAddr: peerAddr,
	})
	hm.unlockedAddHostInfo(relayHI, f)

	peer := &HostInfo{vpnAddrs: []netip.Addr{peerAddr}}
	direct := netip.MustParseAddrPort("10.8.0.30:51107")
	peer.remote.Store(&direct)
	peer.relayState.InsertRelayTo(relayAddr)

	// Unpinned, with a direct remote: the original rule stands, no relay.
	hi, r := f.relayForSending(peer)
	assert.Nil(t, hi, "without a pin a peer with a direct remote goes direct")
	assert.Nil(t, r)

	// Pinned: traffic goes through the named relay even though the direct remote
	// is perfectly valid. This is the whole point of the feature.
	peer.pinRelay(relayAddr)
	hi, r = f.relayForSending(peer)
	if assert.NotNil(t, hi, "a pin has to reach the data path") {
		assert.Equal(t, relayHI, hi)
		assert.Equal(t, uint32(100), r.LocalIndex)
	}

	// A pin whose relay we no longer hold must not strand the peer: fall back to
	// the direct remote rather than dropping the packet.
	peer.relayState.DeleteRelay(relayAddr)
	hi, _ = f.relayForSending(peer)
	assert.Nil(t, hi, "a stale pin falls back to direct, it does not black-hole")

	// No direct remote and no pin: any usable relay will do, which is what a
	// relayed tunnel did before this change and still does.
	peer.relayState.InsertRelayTo(relayAddr)
	peer.pinRelay(netip.Addr{})
	peer.remote.Store(nil)
	hi, _ = f.relayForSending(peer)
	assert.NotNil(t, hi, "with no direct remote a relay is the only path")

	// Naming a relay we do not hold resolves to nothing rather than to some
	// other relay: a probe leg must measure the path it asked for.
	hi, _ = f.resolveRelay(peer, netip.MustParseAddr("10.0.0.9"))
	assert.Nil(t, hi, "an unheld relay must not silently resolve to another one")
}

// Test_PathProbe_PinDoesNotStrandARelayOnlyPeer covers the case the pin was most
// dangerous in: a peer reachable only through relays, pinned to one of them,
// where that relay goes away. Nothing else clears such a pin - clearing happens
// when a probe round is judged, and a round needs two paths to open, so a peer
// down to one candidate never gets another round. Meanwhile the service path
// drops the pin on its own and keeps answering, so both ends see a healthy
// tunnel that carries no data.
func Test_PathProbe_PinDoesNotStrandARelayOnlyPeer(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	f := &Interface{hostMap: hm, l: l}

	goneAddr := netip.MustParseAddr("10.0.0.2")
	liveAddr := netip.MustParseAddr("10.0.0.6")
	peerAddr := netip.MustParseAddr("10.0.0.54")

	liveHI := &HostInfo{
		vpnAddrs:     []netip.Addr{liveAddr},
		localIndexId: 2,
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
	}
	liveHI.relayState.InsertRelay(peerAddr, 200, &Relay{
		Type: ForwardingType, State: Established, LocalIndex: 200, PeerAddr: peerAddr,
	})
	hm.unlockedAddHostInfo(liveHI, f)

	// No direct remote at all: relays are the only way to this peer. It holds
	// two, and is pinned to the one we have no tunnel to.
	peer := &HostInfo{vpnAddrs: []netip.Addr{peerAddr}}
	peer.relayState.InsertRelayTo(goneAddr)
	peer.relayState.InsertRelayTo(liveAddr)
	peer.pinRelay(goneAddr)

	hi, r := f.relayForSending(peer)
	if assert.NotNil(t, hi, "a pin on a relay we cannot resolve must not swallow the peer's traffic") {
		assert.Equal(t, liveHI, hi, "the other relay it holds is a path and has to be used")
		assert.Equal(t, uint32(200), r.LocalIndex)
	}
	assert.False(t, peer.PinnedRelay().IsValid(),
		"a pin that led nowhere is dropped, or every packet pays for resolving it again")

	// And once dropped it stays dropped: the peer keeps sending over the relay
	// that works instead of retrying the one that is gone.
	hi, _ = f.relayForSending(peer)
	assert.Equal(t, liveHI, hi)
}

// Test_PathProbe_AsksForARelayItLost covers the decisions around rebuilding a
// relay so a lost path can be measured again. Without this the probe compares
// only what survived: a relay that dropped out never returns to the list and the
// best path is gone for good. Seen in the field, not imagined.
func Test_PathProbe_AsksForARelayItLost(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	rm := &relayManager{l: l, hostmap: hm}
	rm.useRelays.Store(true)

	relayAddr := netip.MustParseAddr("10.0.0.2")
	peerAddr := netip.MustParseAddr("10.0.0.54")

	f := &Interface{hostMap: hm, l: l, relayManager: rm,
		myVpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.21")}}
	cm := &connectionManager{l: l, intf: f, hostMap: hm}

	peer := &HostInfo{vpnAddrs: []netip.Addr{peerAddr}}

	// No tunnel to the relay itself: there is nothing to ask over, and asking
	// must not blow up either.
	cm.askForRelay(peer, relayAddr)
	assert.Empty(t, hm.Relays, "with no tunnel to the relay nothing can be built")

	relayHI := &HostInfo{
		vpnAddrs:     []netip.Addr{relayAddr},
		localIndexId: 1,
		relayState: RelayState{
			relayForByAddr: map[netip.Addr]*Relay{},
			relayForByIdx:  map[uint32]*Relay{},
		},
		ConnectionState: &ConnectionState{
			peerCert: &cert.CachedCertificate{Certificate: &dummyCert{version: cert.Version2}},
		},
	}
	remote := netip.MustParseAddrPort("198.51.100.138:4242")
	relayHI.remote.Store(&remote)
	hm.unlockedAddHostInfo(relayHI, f)

	// Now the relay can be rebuilt, and must be: this is the whole point.
	cm.askForRelay(peer, relayAddr)
	_, ok := relayHI.relayState.QueryRelayForByIp(peerAddr)
	assert.True(t, ok, "a lost relay has to be asked for, or the path never returns")

	// Asking again re-sends the same request rather than building a second relay:
	// a CreateRelayRequest can be lost, and with probing alone nothing else would
	// ever ask again, so the path would never come back.
	before := len(hm.Relays)
	cm.askForRelay(peer, relayAddr)
	assert.Len(t, hm.Relays, before, "a re-send must reuse the index, not build a second relay")
	again, ok := relayHI.relayState.QueryRelayForByIp(peerAddr)
	assert.True(t, ok)
	assert.Equal(t, Requested, again.State, "an unanswered relay stays Requested and keeps being asked for")

	// A relay that fell over is asked for again too, from Disestablished.
	relayHI.relayState.UpdateRelayForByIpState(peerAddr, Disestablished)
	cm.askForRelay(peer, relayAddr)
	back, ok := relayHI.relayState.QueryRelayForByIp(peerAddr)
	assert.True(t, ok)
	assert.Equal(t, Requested, back.State, "a disestablished relay is requested again, not abandoned")

	// An established relay needs nothing: it is already measurable.
	relayHI.relayState.UpdateRelayForByIpState(peerAddr, Established)
	cm.askForRelay(peer, relayAddr)
	still, _ := relayHI.relayState.QueryRelayForByIp(peerAddr)
	assert.Equal(t, Established, still.State, "an established relay must be left alone")

	// use_relays: false means do not ask at all.
	rm.useRelays.Store(false)
	other := netip.MustParseAddr("10.0.0.55")
	cm.askForRelay(&HostInfo{vpnAddrs: []netip.Addr{other}}, relayAddr)
	_, ok = relayHI.relayState.QueryRelayForByIp(other)
	assert.False(t, ok, "relays turned off means no relay is built")
}

// Test_PathProbe_LogNamesThePathInUse guards the log against the same lie the
// data path already told once: reporting "direct" while a pin sends every packet
// through a relay. describeCarriedPath exists precisely to name the path traffic
// takes, so a pin has to win there as well.
func Test_PathProbe_LogNamesThePathInUse(t *testing.T) {
	relay := netip.MustParseAddr("10.0.0.2")
	hi := probePeer(t, "10.0.0.54", "10.0.0.2")

	assert.Contains(t, describeCarriedPath(hi, ViaSender{}), "direct",
		"without a pin the direct remote is the path in use")

	hi.pinRelay(relay)
	assert.Equal(t, "relay via 10.0.0.2", describeCarriedPath(hi, ViaSender{}),
		"a pin is the path in use, whatever hostinfo.remote still says")

	// A pin whose relay is gone is not a path, and must not be named as one.
	hi.relayState.DeleteRelay(relay)
	assert.Contains(t, describeCarriedPath(hi, ViaSender{}), "direct",
		"a stale pin must not be reported as the path in use")
}

func Test_PathProbe_PreferenceFollowsThePrimary(t *testing.T) {
	l := test.NewLogger()
	hm := newHostMap(l)
	cm := &connectionManager{l: l, hostMap: hm}

	relay := netip.MustParseAddr("10.0.0.2")
	peerAddr := netip.MustParseAddr("10.0.0.54")

	old := probePeer(t, "10.0.0.54", "10.0.0.2")
	old.localIndexId = 1
	promoted := probePeer(t, "10.0.0.54", "10.0.0.2")
	promoted.localIndexId = 2

	f := &Interface{hostMap: hm, l: l}
	hm.unlockedAddHostInfo(promoted, f)
	hm.unlockedAddHostInfo(old, f)
	assert.Equal(t, old, hm.Hosts[peerAddr], "the last one added is primary")

	// The primary moved to a relay after the other tunnel was built, so the
	// tunnel about to be promoted does not know about it yet.
	old.pinRelay(relay)
	cm.swapPrimary(promoted, old)

	assert.Equal(t, relay, promoted.PinnedRelay(),
		"promoting a tunnel must not silently revert a measured path preference")
}

func Test_RelayState_HasRelay(t *testing.T) {
	hi := probePeer(t, "172.1.1.9", "172.1.1.2")
	assert.True(t, hi.relayState.hasRelay(netip.MustParseAddr("172.1.1.2")))
	assert.False(t, hi.relayState.hasRelay(netip.MustParseAddr("172.1.1.3")))
}

func Test_ConnectionManager_JudgePathProbe(t *testing.T) {
	l := test.NewLogger()
	cm := &connectionManager{l: l}
	cm.pathProbeMargin.Store(int64(10 * time.Millisecond))

	relay := netip.MustParseAddr("172.1.1.2")
	round := func(directRTT, relayRTT time.Duration, directAnswered, relayAnswered bool) *pathProbeState {
		return &pathProbeState{
			round:   1,
			started: time.Now(),
			legs: []probeLeg{
				{rtt: directRTT, got: directAnswered},
				{relay: relay, rtt: relayRTT, got: relayAnswered},
			},
		}
	}
	// Each case gets its own peer: a decision looks back over several rounds now,
	// so sharing one peer would carry history between unrelated scenarios.
	peer := func() *HostInfo { return probePeer(t, "172.1.1.9", "172.1.1.2") }

	// A relay that beats the direct path by more than the margin takes over.
	hi := peer()
	cm.judgePathProbe(hi, round(80*time.Millisecond, 5*time.Millisecond, true, true))
	assert.Equal(t, relay, hi.PinnedRelay(), "the faster path must win")

	// A relay faster by less than the margin does not, or a pair of near-equal
	// paths would swap back and forth on noise.
	hi = peer()
	cm.judgePathProbe(hi, round(20*time.Millisecond, 15*time.Millisecond, true, true))
	assert.False(t, hi.PinnedRelay().IsValid(), "a margin-sized win is not a win")

	// The direct path recovering releases the pin.
	hi = peer()
	hi.pinRelay(relay)
	cm.judgePathProbe(hi, round(5*time.Millisecond, 80*time.Millisecond, true, true))
	assert.False(t, hi.PinnedRelay().IsValid(), "traffic must come back off the relay")

	// A direct path that stopped answering is left behind even without a margin.
	hi = peer()
	cm.judgePathProbe(hi, round(0, 80*time.Millisecond, false, true))
	assert.Equal(t, relay, hi.PinnedRelay(), "an unanswering direct path is not a path")

	// Silence from every leg changes nothing: it is not evidence about the path
	// in use, and moving on it would be guessing.
	hi = peer()
	hi.pinRelay(relay)
	cm.judgePathProbe(hi, round(0, 0, false, false))
	assert.Equal(t, relay, hi.PinnedRelay(), "no replies means no decision")

	// ONE bad round must not move traffic. That is what an unstable link looks
	// like, and acting on every swing is how four peers out of fourteen spent a
	// night moving back and forth while the peers on a healthy link never moved.
	hi = peer()
	for range 3 {
		cm.judgePathProbe(hi, round(8*time.Millisecond, 40*time.Millisecond, true, true))
	}
	assert.False(t, hi.PinnedRelay().IsValid(), "direct is usually better here")
	cm.judgePathProbe(hi, round(90*time.Millisecond, 5*time.Millisecond, true, true))
	assert.False(t, hi.PinnedRelay().IsValid(), "a single swing is not a reason to move traffic")

	// A path that is SILENT this round must not win on what it used to cost.
	// Seen in the field: a peer was moved onto a direct path that had not
	// answered at all, because its median from earlier rounds still looked good.
	hi = peer()
	hi.pinRelay(relay)
	for range 3 {
		cm.judgePathProbe(hi, round(5*time.Millisecond, 40*time.Millisecond, true, true))
	}
	assert.False(t, hi.PinnedRelay().IsValid(), "direct is genuinely better here")
	hi.pinRelay(relay)
	cm.judgePathProbe(hi, round(0, 180*time.Millisecond, false, true))
	assert.Equal(t, relay, hi.PinnedRelay(),
		"a path that answered nothing must not be chosen on its remembered numbers")

	// A difference that PERSISTS does move it.
	for range 3 {
		cm.judgePathProbe(hi, round(90*time.Millisecond, 5*time.Millisecond, true, true))
	}
	assert.Equal(t, relay, hi.PinnedRelay(), "a difference that holds up over rounds is a real one")
}
