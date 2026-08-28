package nebula

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"time"
)

// Path probing measures every path this peer's traffic could take — the direct
// remote and each relay we hold for it — and pins the fastest one.
//
// It exists because picking a path at handshake time is not a fair contest. A
// direct handshake goes out immediately, while a relayed one must set the relay
// up first (CreateRelayRequest, CreateRelayResponse) and so starts a full round
// trip behind. The first reply wins, so the direct path wins even when it is
// far slower. Measured on one pair: the direct path swung between 14ms and
// 386ms while a relay one hop away answered in 5.5ms and was never considered.
//
// A reply comes back the way the peer chooses, not the way we sent it, so a
// leg measures (our path out) + (their path back). That return leg is the same
// for every leg of a round, so the differences between legs are meaningful even
// though each number carries the constant.
const (
	// pathProbeWait is how long a round stays open. A leg that has not answered
	// by then is counted as no answer rather than as slow.
	pathProbeWait = 3 * time.Second

	// pathProbePayloadLen is [8 bytes round][8 bytes leg index].
	pathProbePayloadLen = 16

	// pathProbeRounds is how many rounds a decision looks back over. One round
	// is a single sample, and a single sample decides badly on an unstable link:
	// measured overnight on a degraded uplink, four peers out of fourteen ended
	// up moving back and forth all night, each move justified by tens of
	// milliseconds at that instant. The peers reached over a healthy link never
	// moved at all. Comparing medians over a few rounds keeps the honest moves
	// and drops the ones a single swing would cause.
	pathProbeRounds = 3
)

// notePathResult files one round's measurement under the path it belongs to and
// keeps the last few. The zero address is the direct path.
func (i *HostInfo) notePathResult(path netip.Addr, rtt time.Duration) {
	if i.pathHistory == nil {
		i.pathHistory = map[netip.Addr][]time.Duration{}
	}
	h := append(i.pathHistory[path], rtt)
	if len(h) > pathProbeRounds {
		h = h[len(h)-pathProbeRounds:]
	}
	i.pathHistory[path] = h
}

// pathTypical returns what a path usually costs: the median of the rounds
// remembered for it. A median rather than a mean because one bad round should
// not drag the answer, which is the whole point of looking back at all.
func (i *HostInfo) pathTypical(path netip.Addr) (time.Duration, bool) {
	h := i.pathHistory[path]
	if len(h) == 0 {
		return 0, false
	}
	s := make([]time.Duration, len(h))
	copy(s, h)
	slices.Sort(s)
	return s[len(s)/2], true
}

// forgetPaths drops history for paths that are no longer offered, so a relay
// that went away cannot be chosen later on stale numbers.
func (i *HostInfo) forgetPaths(keep map[netip.Addr]struct{}) {
	for p := range i.pathHistory {
		if _, ok := keep[p]; !ok {
			delete(i.pathHistory, p)
		}
	}
}

// probeLeg is one candidate path under measurement.
type probeLeg struct {
	// relay is the relay this leg is sent through. An invalid address means the
	// leg goes straight to the direct remote.
	relay netip.Addr
	rtt   time.Duration
	got   bool
}

// pathProbeState is the round in flight for one peer.
type pathProbeState struct {
	round   uint64
	started time.Time
	legs    []probeLeg
}

// hasRelay reports whether this peer is still reachable through the given
// relay. Unlike CopyRelayIps it allocates nothing, so the send path can ask.
func (rs *RelayState) hasRelay(addr netip.Addr) bool {
	rs.RLock()
	defer rs.RUnlock()
	for _, r := range rs.relays {
		if r == addr {
			return true
		}
	}
	return false
}

// PinnedRelay returns the relay traffic for this peer is currently pinned to,
// or the zero value when traffic follows the usual rules.
func (i *HostInfo) PinnedRelay() netip.Addr {
	if p := i.pinnedRelay.Load(); p != nil {
		return *p
	}
	return netip.Addr{}
}

// pinRelay makes traffic for this peer go through addr even though a direct
// remote exists. Clearing is pinRelay(netip.Addr{}).
func (i *HostInfo) pinRelay(addr netip.Addr) {
	if !addr.IsValid() {
		i.pinnedRelay.Store(nil)
		return
	}
	i.pinnedRelay.Store(&addr)
}

// probeDue reports whether a new round is due, and stamps it when it is. The
// stamp is taken here rather than after the round finishes so a peer that never
// answers cannot be probed every tick.
func (i *HostInfo) probeDue(now time.Time, interval time.Duration) bool {
	i.probeMu.Lock()
	defer i.probeMu.Unlock()
	if i.probe != nil {
		return false
	}
	if !i.lastProbeAt.IsZero() && now.Sub(i.lastProbeAt) < interval {
		return false
	}
	i.lastProbeAt = now
	return true
}

// startPathProbe opens a round over the direct remote and the given relays, and
// returns the legs to send. It returns nil when fewer than two paths exist:
// measuring a single path decides nothing.
//
// The relays are supplied by the caller rather than read from relayState
// because relayState only remembers relays this tunnel actually came up
// through. A tunnel that handshook directly holds an empty list even when
// relays are configured, reachable, and faster — which is the very case worth
// finding.
func (i *HostInfo) startPathProbe(round uint64, now time.Time, relays []netip.Addr) []probeLeg {
	legs := make([]probeLeg, 0, len(relays)+1)
	if i.GetRemote().IsValid() {
		// The direct remote is always leg 0 when there is one.
		legs = append(legs, probeLeg{})
	}
	for _, r := range relays {
		legs = append(legs, probeLeg{relay: r})
	}
	if len(legs) < 2 {
		return nil
	}

	i.probeMu.Lock()
	i.probe = &pathProbeState{round: round, started: now, legs: legs}
	i.probeMu.Unlock()

	out := make([]probeLeg, len(legs))
	copy(out, legs)
	return out
}

// pathProbePayload builds the payload for one leg. The peer echoes it back
// unchanged, which is what lets a reply be matched to the path it took.
func pathProbePayload(round uint64, leg int) []byte {
	p := make([]byte, pathProbePayloadLen)
	binary.BigEndian.PutUint64(p[:8], round)
	binary.BigEndian.PutUint64(p[8:], uint64(leg))
	return p
}

// notePathProbeReply records the arrival of an echoed probe payload. Anything
// that is not a payload of ours is ignored: test packets are also sent by
// punchy and by the connection manager, and they carry no payload at all.
func (i *HostInfo) notePathProbeReply(payload []byte, now time.Time) {
	if len(payload) != pathProbePayloadLen {
		return
	}
	round := binary.BigEndian.Uint64(payload[:8])
	leg := binary.BigEndian.Uint64(payload[8:])

	i.probeMu.Lock()
	defer i.probeMu.Unlock()
	if i.probe == nil || i.probe.round != round || leg >= uint64(len(i.probe.legs)) {
		return
	}
	if i.probe.legs[leg].got {
		// A duplicate reply says nothing new, and the first one is the honest
		// measurement.
		return
	}
	i.probe.legs[leg].got = true
	i.probe.legs[leg].rtt = now.Sub(i.probe.started)
}

// takePathProbe returns a finished round and clears it, or nil when the round
// is still open. A round is finished once every leg answered or the wait ran
// out — an unanswered leg is not worth waiting on past that.
func (i *HostInfo) takePathProbe(now time.Time) *pathProbeState {
	i.probeMu.Lock()
	defer i.probeMu.Unlock()
	if i.probe == nil {
		return nil
	}

	done := true
	for _, l := range i.probe.legs {
		if !l.got {
			done = false
			break
		}
	}
	if !done && now.Sub(i.probe.started) < pathProbeWait {
		return nil
	}

	p := i.probe
	i.probe = nil
	return p
}

// best returns the fastest leg that answered.
func (p *pathProbeState) best() (probeLeg, bool) {
	var best probeLeg
	found := false
	for _, l := range p.legs {
		if !l.got {
			continue
		}
		if !found || l.rtt < best.rtt {
			best = l
			found = true
		}
	}
	return best, found
}

// carryPathPreference moves a measured path preference onto the HostInfo that
// replaces this one.
//
// A rehandshake builds a fresh HostInfo and the pin lives on the old one, so
// without this every rehandshake drops traffic back onto the path the probe
// already rejected until the next round measures it again. Which path is faster
// is a fact about the peer, not about the tunnel instance.
//
// A pin that no longer fits the new tunnel is harmless: the send path drops a
// pin whose relay is gone, and the next round judges it afresh.
func carryPathPreference(prev, next *HostInfo) {
	if prev == nil || next == nil || prev == next {
		return
	}
	if pin := prev.PinnedRelay(); pin.IsValid() {
		next.pinRelay(pin)
	}
}

// carries reports whether the named path was part of this round at all,
// answered or not. It is what separates "the path in use went quiet" from
// "there was no path in use", which read the same in the measurement but are
// different events.
func (p *pathProbeState) carries(relay netip.Addr) bool {
	for _, l := range p.legs {
		if l.relay == relay {
			return true
		}
	}
	return false
}

// leg returns what the named path measured this round: the relay's leg, or the
// direct leg when the address is the zero value. It reports false when that path
// is not in this round or did not answer.
func (p *pathProbeState) leg(relay netip.Addr) (probeLeg, bool) {
	for _, l := range p.legs {
		if l.relay == relay {
			if !l.got {
				return probeLeg{}, false
			}
			return l, true
		}
	}
	return probeLeg{}, false
}

// describe renders the round for the log: what each path cost, in leg order.
func (p *pathProbeState) describe() string {
	s := ""
	for _, l := range p.legs {
		if s != "" {
			s += " "
		}
		name := "direct"
		if l.relay.IsValid() {
			name = "relay " + l.relay.String()
		}
		if !l.got {
			s += name + "=no reply"
			continue
		}
		s += name + "=" + l.rtt.Round(time.Millisecond/10).String()
	}
	return s
}
