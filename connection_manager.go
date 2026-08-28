package nebula

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/header"
)

type trafficDecision int

const (
	doNothing      trafficDecision = 0
	deleteTunnel   trafficDecision = 1 // delete the hostinfo on our side, do not notify the remote
	closeTunnel    trafficDecision = 2 // delete the hostinfo and notify the remote
	swapPrimary    trafficDecision = 3
	migrateRelays  trafficDecision = 4
	tryRehandshake trafficDecision = 5
	sendTestPacket trafficDecision = 6
)

type connectionManager struct {
	// relayUsed holds which relay localIndexs are in use
	relayUsed     map[uint32]struct{}
	relayUsedLock *sync.RWMutex

	hostMap      *HostMap
	trafficTimer *LockingTimerWheel[uint32]
	intf         *Interface
	punchy       *Punchy

	// Configuration settings
	checkInterval           time.Duration
	pendingDeletionInterval time.Duration
	inactivityTimeout       atomic.Int64
	dropInactive            atomic.Bool
	// pathRecheckInterval, when non-zero, makes an established primary tunnel
	// re-run the handshake on that schedule so a better remote can win again.
	// Zero (the default) keeps the existing behaviour: the remote chosen at
	// handshake time is kept until the tunnel dies.
	pathRecheckInterval atomic.Int64

	// pathProbeInterval, when non-zero, measures every path to a peer — the
	// direct remote and each relay — and pins the one that answers fastest.
	// Zero (the default) keeps the existing behaviour: whatever the handshake
	// race produced is used until the tunnel dies.
	pathProbeInterval atomic.Int64
	// pathProbeMargin is how much faster a relay must be before traffic is
	// moved onto it, so a pair of near-equal paths is not swapped back and
	// forth on measurement noise.
	pathProbeMargin atomic.Int64
	// pathProbeSpread is how far behind the fastest path another path may sit
	// and still count as equally good, in percent. Zero keeps the old behaviour
	// of always pinning the single fastest path. Never above
	// maxPathProbeSpread, whatever the config asked for.
	pathProbeSpread atomic.Int64
	// probeRound numbers rounds so a late reply from a previous one is ignored.
	probeRound atomic.Uint64

	l *slog.Logger
}

func newConnectionManagerFromConfig(l *slog.Logger, c *config.C, hm *HostMap, p *Punchy) *connectionManager {
	cm := &connectionManager{
		hostMap:       hm,
		l:             l,
		punchy:        p,
		relayUsed:     make(map[uint32]struct{}),
		relayUsedLock: &sync.RWMutex{},
	}

	cm.reload(c, true)
	c.RegisterReloadCallback(func(c *config.C) {
		cm.reload(c, false)
	})

	return cm
}

// rehandshakeIntervalFromConfig reads timers.rehandshake_interval and says so
// when the value is not a duration.
//
// GetDuration falls back to its default on any parse error, and every other key
// in this timers block is written as a plain number of seconds. So "30" is the
// natural thing to write here, and it does not mean thirty of anything: it
// fails to parse and leaves the feature switched off, with the config looking
// configured. Refusing outright is not open to us here, since a reload callback
// has nowhere to return an error, so the least we owe the operator is to say
// which value was thrown away.
func rehandshakeIntervalFromConfig(c *config.C, l *slog.Logger) time.Duration {
	raw := c.GetString("timers.rehandshake_interval", "")
	if raw == "" {
		return 0
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		l.Warn("timers.rehandshake_interval is not a duration and was ignored",
			"provided", raw,
			"example", "30m",
		)
		return 0
	}

	return d
}

func (cm *connectionManager) reload(c *config.C, initial bool) {
	if initial {
		cm.checkInterval = time.Duration(c.GetInt("timers.connection_alive_interval", 5)) * time.Second
		cm.pendingDeletionInterval = time.Duration(c.GetInt("timers.pending_deletion_interval", 10)) * time.Second

		// We want at least a minimum resolution of 500ms per tick so that we can hit these intervals
		// pretty close to their configured duration.
		// The inactivity duration is checked each time a hostinfo ticks through so we don't need the wheel to contain it.
		minDuration := min(time.Millisecond*500, cm.checkInterval, cm.pendingDeletionInterval)
		maxDuration := max(cm.checkInterval, cm.pendingDeletionInterval)
		cm.trafficTimer = NewLockingTimerWheel[uint32](minDuration, maxDuration)
	}

	if initial || c.HasChanged("timers.rehandshake_interval") {
		old := time.Duration(cm.pathRecheckInterval.Load())
		cm.pathRecheckInterval.Store((int64)(rehandshakeIntervalFromConfig(c, cm.l)))
		if initial {
			cm.l.Info("Path recheck configured",
				"interval", time.Duration(cm.pathRecheckInterval.Load()),
			)
		}
		if !initial {
			cm.l.Info("Path recheck interval has changed",
				"oldDuration", old,
				"newDuration", time.Duration(cm.pathRecheckInterval.Load()),
			)
		}
	}

	if initial || c.HasChanged("timers.path_probe_interval") || c.HasChanged("timers.path_probe_margin") {
		old := time.Duration(cm.pathProbeInterval.Load())
		cm.pathProbeInterval.Store((int64)(c.GetDuration("timers.path_probe_interval", 0)))
		cm.pathProbeMargin.Store((int64)(c.GetDuration("timers.path_probe_margin", 10*time.Millisecond)))
		if initial {
			cm.l.Info("Path probe configured",
				"interval", time.Duration(cm.pathProbeInterval.Load()),
				"margin", time.Duration(cm.pathProbeMargin.Load()),
			)
		} else {
			cm.l.Info("Path probe interval has changed",
				"oldDuration", old,
				"newDuration", time.Duration(cm.pathProbeInterval.Load()),
				"margin", time.Duration(cm.pathProbeMargin.Load()),
			)
		}
	}

	if initial || c.HasChanged("timers.path_probe_spread") {
		old := cm.pathProbeSpread.Load()
		cm.pathProbeSpread.Store(pathProbeSpreadFromConfig(cm.l, c))
		if initial {
			cm.l.Info("Path probe spread configured",
				"percent", cm.pathProbeSpread.Load(),
			)
		} else {
			cm.l.Info("Path probe spread has changed",
				"oldPercent", old,
				"newPercent", cm.pathProbeSpread.Load(),
			)
		}
	}

	if initial || c.HasChanged("tunnels.inactivity_timeout") {
		old := cm.getInactivityTimeout()
		cm.inactivityTimeout.Store((int64)(c.GetDuration("tunnels.inactivity_timeout", 10*time.Minute)))
		if !initial {
			cm.l.Info("Inactivity timeout has changed",
				"oldDuration", old,
				"newDuration", cm.getInactivityTimeout(),
			)
		}
	}

	if initial || c.HasChanged("tunnels.drop_inactive") {
		old := cm.dropInactive.Load()
		cm.dropInactive.Store(c.GetBool("tunnels.drop_inactive", false))
		if !initial {
			cm.l.Info("Drop inactive setting has changed",
				"oldBool", old,
				"newBool", cm.dropInactive.Load(),
			)
		}
	}
}

// pathProbeSpreadFromConfig reads the spread and holds it inside the range
// where calling two paths equally good still means something. A number outside
// it is brought to the limit and reported rather than refused, the way
// listen.batch and routines are handled: a node that comes up on a sane number
// is worth more than one that will not come up at all.
func pathProbeSpreadFromConfig(l *slog.Logger, c *config.C) int64 {
	spread := int64(c.GetInt("timers.path_probe_spread", 0))
	if spread < 0 || spread > maxPathProbeSpread {
		clamped := min(max(spread, 0), maxPathProbeSpread)
		l.Warn("timers.path_probe_spread is out of range",
			"provided", spread,
			"overridden to", clamped,
		)
		spread = clamped
	}
	return spread
}

func (cm *connectionManager) getInactivityTimeout() time.Duration {
	return (time.Duration)(cm.inactivityTimeout.Load())
}

func (cm *connectionManager) In(h *HostInfo) {
	h.markIn()
}

// OutNoRebind records outbound traffic without consuming the rebind epoch, for relayed sends: the direct path
// to the relay consumes the edge, the via send must not.
func (cm *connectionManager) OutNoRebind(h *HostInfo) {
	h.markOutOnly()
}

// Out records outbound traffic and reports whether we rebound since this tunnel last sent
func (cm *connectionManager) Out(h *HostInfo) bool {
	return h.markOut(cm.intf.rebindEpoch.Load())
}

func (cm *connectionManager) RelayUsed(localIndex uint32) {
	cm.relayUsedLock.RLock()
	// If this already exists, return
	if _, ok := cm.relayUsed[localIndex]; ok {
		cm.relayUsedLock.RUnlock()
		return
	}
	cm.relayUsedLock.RUnlock()
	cm.relayUsedLock.Lock()
	cm.relayUsed[localIndex] = struct{}{}
	cm.relayUsedLock.Unlock()
}

// getAndResetTrafficCheck returns if there was any inbound or outbound traffic within the last tick and
// resets the state for this local index
func (cm *connectionManager) getAndResetTrafficCheck(h *HostInfo, now time.Time) (bool, bool) {
	in, out := h.takeTraffic()
	if in || out {
		h.lastUsed = now
	}
	return in, out
}

func (cm *connectionManager) Start(ctx context.Context) {
	clockSource := time.NewTicker(cm.trafficTimer.t.tickDuration)
	defer clockSource.Stop()

	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-clockSource.C:
			cm.trafficTimer.Advance(now)
			for {
				localIndex, has := cm.trafficTimer.Purge()
				if !has {
					break
				}

				cm.doTrafficCheck(localIndex, p, nb, out, now)
			}
		}
	}
}

func (cm *connectionManager) doTrafficCheck(localIndex uint32, p, nb, out []byte, now time.Time) {
	decision, hostinfo, primary := cm.makeTrafficDecision(localIndex, now)

	switch decision {
	case deleteTunnel:
		if cm.hostMap.DeleteHostInfo(hostinfo) {
			// Only clearing the lighthouse cache if this is the last hostinfo for this vpn ip in the hostmap
			cm.intf.lightHouse.DeleteVpnAddrs(hostinfo.vpnAddrs)
		}

	case closeTunnel:
		cm.intf.sendCloseTunnel(hostinfo)
		cm.intf.closeTunnel(hostinfo)

	case swapPrimary:
		cm.swapPrimary(hostinfo, primary)

	case migrateRelays:
		cm.migrateRelayUsed(hostinfo, primary)

	case tryRehandshake:
		cm.tryRehandshake(hostinfo)

	case sendTestPacket:
		cm.intf.SendMessageToHostInfo(header.Test, header.TestRequest, hostinfo, p, nb, out)
	}

	// Probing is unilateral: it only decides which way we send. Both ends may
	// run it, and on an asymmetric network they should — the fast direction is
	// not always the same one.
	switch decision {
	case doNothing, sendTestPacket, tryRehandshake:
		if hostinfo != nil {
			cm.maybePathProbe(hostinfo, nb, out, now)
		}
	}

	cm.resetRelayTrafficCheck(hostinfo)
}

func (cm *connectionManager) resetRelayTrafficCheck(hostinfo *HostInfo) {
	if hostinfo != nil {
		cm.relayUsedLock.Lock()
		defer cm.relayUsedLock.Unlock()
		// No need to migrate any relays, delete usage info now.
		for _, idx := range hostinfo.relayState.CopyRelayForIdxs() {
			delete(cm.relayUsed, idx)
		}
	}
}

func (cm *connectionManager) migrateRelayUsed(oldhostinfo, newhostinfo *HostInfo) {
	relayFor := oldhostinfo.relayState.CopyAllRelayFor()

	for _, r := range relayFor {
		existing, ok := newhostinfo.relayState.QueryRelayForByIp(r.PeerAddr)

		var index uint32
		var relayFrom netip.Addr
		var relayTo netip.Addr
		switch {
		case ok:
			switch existing.State {
			case Established, PeerRequested, Disestablished:
				// This relay already exists in newhostinfo, then do nothing.
				continue
			case Requested:
				// The relay exists in a Requested state; re-send the request
				index = existing.LocalIndex
				switch r.Type {
				case TerminalType:
					relayFrom = cm.intf.myVpnAddrs[0]
					relayTo = existing.PeerAddr
				case ForwardingType:
					relayFrom = existing.PeerAddr
					relayTo = newhostinfo.vpnAddrs[0]
				default:
					// should never happen
					panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
				}
			}
		case !ok:
			cm.relayUsedLock.RLock()
			if _, relayUsed := cm.relayUsed[r.LocalIndex]; !relayUsed {
				// The relay hasn't been used; don't migrate it.
				cm.relayUsedLock.RUnlock()
				continue
			}
			cm.relayUsedLock.RUnlock()
			// The relay doesn't exist at all; create some relay state and send the request.
			var err error
			index, err = AddRelay(cm.l, newhostinfo, cm.hostMap, r.PeerAddr, nil, r.Type, Requested)
			if err != nil {
				cm.l.Error("failed to migrate relay to new hostinfo", "error", err)
				continue
			}
			switch r.Type {
			case TerminalType:
				relayFrom = cm.intf.myVpnAddrs[0]
				relayTo = r.PeerAddr
			case ForwardingType:
				relayFrom = r.PeerAddr
				relayTo = newhostinfo.vpnAddrs[0]
			default:
				// should never happen
				panic(fmt.Sprintf("Migrating unknown relay type: %v", r.Type))
			}
		}

		// Send a CreateRelayRequest to the peer.
		req := NebulaControl{
			Type:                NebulaControl_CreateRelayRequest,
			InitiatorRelayIndex: index,
		}

		switch newhostinfo.GetCert().Certificate.Version() {
		case cert.Version1:
			if !relayFrom.Is4() {
				cm.l.Error("can not migrate v1 relay with a v6 network because the relay is not running a current nebula version")
				continue
			}

			if !relayTo.Is4() {
				cm.l.Error("can not migrate v1 relay with a v6 remote network because the relay is not running a current nebula version")
				continue
			}

			b := relayFrom.As4()
			req.OldRelayFromAddr = binary.BigEndian.Uint32(b[:])
			b = relayTo.As4()
			req.OldRelayToAddr = binary.BigEndian.Uint32(b[:])
		case cert.Version2:
			req.RelayFromAddr = netAddrToProtoAddr(relayFrom)
			req.RelayToAddr = netAddrToProtoAddr(relayTo)
		default:
			newhostinfo.logger(cm.l).Error("Unknown certificate version found while attempting to migrate relay")
			continue
		}

		msg, err := req.Marshal()
		if err != nil {
			cm.l.Error("failed to marshal Control message to migrate relay", "error", err)
		} else {
			cm.intf.SendMessageToHostInfo(header.Control, 0, newhostinfo, msg, make([]byte, 12), make([]byte, mtu))
			cm.l.Info("send CreateRelayRequest",
				"relayFrom", relayFrom,
				"relayTo", relayTo,
				"initiatorRelayIndex", req.InitiatorRelayIndex,
				"responderRelayIndex", req.ResponderRelayIndex,
				"vpnAddrs", newhostinfo.vpnAddrs,
			)
		}
	}
}

func (cm *connectionManager) makeTrafficDecision(localIndex uint32, now time.Time) (trafficDecision, *HostInfo, *HostInfo) {
	// Read lock the main hostmap to order decisions based on tunnels being the primary tunnel
	cm.hostMap.RLock()
	defer cm.hostMap.RUnlock()

	hostinfo := cm.hostMap.Indexes[localIndex]
	if hostinfo == nil {
		cm.l.Debug("Not found in hostmap", "localIndex", localIndex)
		return doNothing, nil, nil
	}

	if cm.isInvalidCertificate(now, hostinfo) {
		return closeTunnel, hostinfo, nil
	}

	if hostinfo.ConnectionState != nil && hostinfo.ConnectionState.messageCounter.Load() >= RejectAfterMessages {
		// Send path can't encrypt a CloseTunnel notify, so just delete locally; the peer recovers via recv_error.
		hostinfo.logger(cm.l).Error("Dropping tunnel, message counter is exhausted")
		return deleteTunnel, hostinfo, nil
	}

	primary := cm.hostMap.Hosts[hostinfo.vpnAddrs[0]]
	mainHostInfo := true
	if primary != nil && primary != hostinfo {
		mainHostInfo = false
	}

	// Check for traffic on this hostinfo
	inTraffic, outTraffic := cm.getAndResetTrafficCheck(hostinfo, now)

	// A hostinfo is determined alive if there is incoming traffic
	if inTraffic {
		decision := doNothing
		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Tunnel status",
				"tunnelCheck", m{"state": "alive", "method": "passive"},
			)
		}
		hostinfo.setPendingDeletion(false)

		if mainHostInfo {
			decision = tryRehandshake
		} else {
			if cm.shouldSwapPrimary(hostinfo) {
				decision = swapPrimary
			} else {
				// migrate the relays to the primary, if in use.
				decision = migrateRelays
			}
		}

		cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)

		if !outTraffic {
			// Send a punch packet to keep the NAT state alive
			cm.punchy.SendPunch(hostinfo)
		}

		return decision, hostinfo, primary
	}

	if hostinfo.isPendingDeletion() {
		// We have already sent a test packet and nothing was returned, this hostinfo is dead
		hostinfo.logger(cm.l).Info("Tunnel status",
			"tunnelCheck", m{"state": "dead", "method": "active"},
		)

		return deleteTunnel, hostinfo, nil
	}

	decision := doNothing
	if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
		if !outTraffic {
			inactiveFor, isInactive := cm.isInactive(hostinfo, now)
			if isInactive {
				// Tunnel is inactive, tear it down
				hostinfo.logger(cm.l).Info("Dropping tunnel due to inactivity",
					"inactiveDuration", inactiveFor,
					"primary", mainHostInfo,
				)

				return closeTunnel, hostinfo, primary
			}

			// If we aren't sending or receiving traffic then its an unused tunnel and we don't to test the tunnel.
			// Just maintain NAT state if configured to do so.
			cm.punchy.SendPunch(hostinfo)
			cm.trafficTimer.Add(hostinfo.localIndexId, cm.checkInterval)
			return doNothing, nil, nil
		}

		// We aren't receiving traffic but we are sending it. The outbound
		// traffic itself refreshes the primary remote's NAT state; this
		// fans out to non-primary remotes, but only if target_all_remotes
		// is configured.
		cm.punchy.SendPunchToAll(hostinfo)

		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Tunnel status",
				"tunnelCheck", m{"state": "testing", "method": "active"},
			)
		}

		// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
		decision = sendTestPacket

	} else {
		if cm.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(cm.l).Debug("Hostinfo sadness")
		}
	}

	hostinfo.setPendingDeletion(true)
	cm.trafficTimer.Add(hostinfo.localIndexId, cm.pendingDeletionInterval)
	return decision, hostinfo, nil
}

func (cm *connectionManager) isInactive(hostinfo *HostInfo, now time.Time) (time.Duration, bool) {
	if cm.dropInactive.Load() == false {
		// We aren't configured to drop inactive tunnels
		return 0, false
	}

	inactiveDuration := now.Sub(hostinfo.lastUsed)
	if inactiveDuration < cm.getInactivityTimeout() {
		// It's not considered inactive
		return inactiveDuration, false
	}

	// The tunnel is inactive
	return inactiveDuration, true
}

func (cm *connectionManager) shouldSwapPrimary(current *HostInfo) bool {
	// The primary tunnel is the most recent handshake to complete locally and should work entirely fine.
	// If we are here then we have multiple tunnels for a host pair and neither side believes the same tunnel is primary.
	// Let's sort this out.

	// Only one side should swap because if both swap then we may never resolve to a single tunnel.
	// vpn addr is static across all tunnels for this host pair so lets
	// use that to determine if we should consider swapping.
	if current.vpnAddrs[0].Compare(cm.intf.myVpnAddrs[0]) < 0 {
		// Their primary vpn addr is less than mine. Do not swap.
		return false
	}

	if current.ConnectionState.messageCounter.Load() >= RehandshakeAfterMessages {
		// This tunnel is being rolled for counter exhaustion, never swap back onto its spent key.
		return false
	}

	crt := cm.intf.pki.getCertState().getCertificate(current.ConnectionState.myCert.Version())
	if crt == nil {
		//my cert was reloaded away. We should definitely swap from this tunnel
		return true
	}
	// If this tunnel is using the latest certificate then we should swap it to primary for a bit and see if things
	// settle down.
	return bytes.Equal(current.ConnectionState.myCert.Signature(), crt.Signature())
}

func (cm *connectionManager) swapPrimary(current, primary *HostInfo) {
	cm.hostMap.Lock()
	// Make sure the primary is still the same after the write lock. This avoids a race with a rehandshake.
	if cm.hostMap.Hosts[current.vpnAddrs[0]] == primary {
		// The measured path preference belongs to the peer, so it follows the
		// primary the same way relays do. The tunnel being promoted got the pin
		// when it was built, but the old primary may have moved since; without
		// this the promotion silently reverts that decision until the next
		// round measures it again.
		carryPathPreference(primary, current)
		cm.hostMap.unlockedMakePrimary(current)
	}
	cm.hostMap.Unlock()
}

// isInvalidCertificate decides if we should destroy a tunnel.
// returns true if pki.disconnect_invalid is true and the certificate is no longer valid.
// Blocklisted certificates will skip the pki.disconnect_invalid check and return true.
func (cm *connectionManager) isInvalidCertificate(now time.Time, hostinfo *HostInfo) bool {
	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false //don't tear down tunnels for handshakes in progress
	}

	caPool := cm.intf.pki.GetCAPool()
	err := caPool.VerifyCachedCertificate(now, remoteCert)
	if err == nil {
		return false //cert is still valid! yay!
	} else if err == cert.ErrBlockListed { //avoiding errors.Is for speed
		// Block listed certificates should always be disconnected
		hostinfo.logger(cm.l).Info("Remote certificate is blocked, tearing down the tunnel",
			"error", err,
			"fingerprint", remoteCert.Fingerprint,
		)
		return true
	} else if cm.intf.disconnectInvalid.Load() {
		hostinfo.logger(cm.l).Info("Remote certificate is no longer valid, tearing down the tunnel",
			"error", err,
			"fingerprint", remoteCert.Fingerprint,
		)
		return true
	} else {
		//if we reach here, the cert is no longer valid, but we're configured to keep tunnels from now-invalid certs open
		return false
	}
}

// maybePathProbe judges a finished probe round, or opens a new one when the
// interval has come round again.
func (cm *connectionManager) maybePathProbe(hostinfo *HostInfo, nb, out []byte, now time.Time) {
	interval := time.Duration(cm.pathProbeInterval.Load())
	if interval <= 0 || hostinfo.ConnectionState == nil {
		return
	}

	// A round in flight is judged before another is opened, so the two never
	// overlap and a reply can always be attributed.
	if p := hostinfo.takePathProbe(now); p != nil {
		cm.judgePathProbe(hostinfo, p)
		return
	}

	if !hostinfo.probeDue(now, interval) {
		return
	}

	round := cm.probeRound.Add(1)
	relays := cm.probeCandidates(hostinfo)
	legs := hostinfo.startPathProbe(round, now, relays)
	if len(legs) == 0 {
		// Say why nothing was measured. Silence here is indistinguishable from
		// a broken feature, which cost real time to work out once already.
		cm.l.Debug("Path probe skipped",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "fewer than two paths to compare",
			"haveDirectRemote", hostinfo.GetRemote().IsValid(),
			"relays", relays,
		)
		return
	}
	cm.l.Debug("Path probe sent",
		"vpnAddrs", hostinfo.vpnAddrs,
		"round", round,
		"legs", len(legs),
	)
	for i, l := range legs {
		payload := pathProbePayload(round, i)
		remote, via := netip.AddrPort{}, l.relay
		if !l.relay.IsValid() {
			// Naming the remote explicitly keeps this leg direct even when a pin
			// from an earlier round is in force.
			remote, via = hostinfo.GetRemote(), netip.Addr{}
		}
		cm.intf.sendNoMetricsVia(header.Test, header.TestRequest, hostinfo.ConnectionState,
			hostinfo, remote, via, payload, nb, out, 0)
	}
}

// probeCandidates lists the relays that could carry this peer's traffic right
// now: the ones this tunnel already uses, plus every relay we are configured to
// use that holds an established relay for this peer.
//
// The configured ones matter because relayState only remembers how the tunnel
// came up. A tunnel that handshook directly carries an empty relay list even
// when relays answered during that same handshake, so without this the
// comparison would never have a second path to make.
//
// A relay that qualifies is recorded on the peer as well. That is true — the
// peer is reachable through it — and it is what lets a pin take effect and a
// failover find the relay later.
func (cm *connectionManager) probeCandidates(hostinfo *HostInfo) []netip.Addr {
	var out []netip.Addr
	seen := make(map[netip.Addr]struct{})

	add := func(r netip.Addr) {
		if !r.IsValid() || r == hostinfo.vpnAddrs[0] {
			return
		}
		if _, ok := seen[r]; ok {
			return
		}
		seen[r] = struct{}{}
		if _, _, err := cm.intf.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, r); err != nil {
			// No established relay for this peer through that host, so there is
			// nothing to measure this round. Ask for one, so the path can be
			// measured next time: without this a relay that drops out never
			// comes back into the comparison and the best path is lost for good.
			cm.askForRelay(hostinfo, r)
			return
		}
		hostinfo.relayState.InsertRelayTo(r)
		out = append(out, r)
	}

	for _, r := range hostinfo.relayState.CopyRelayIps() {
		add(r)
	}
	if cm.intf.lightHouse != nil {
		for _, r := range cm.intf.lightHouse.GetRelaysForMe() {
			add(r)
		}
	}
	return out
}

// askForRelay rebuilds a relay this peer used to be reachable through, so it can
// be measured again. requestRelay decides what that means: a first request when
// there is no relay state, or the same request sent again when an earlier one
// went unanswered. Re-sending matters here - a lost request would otherwise
// leave the relay Requested for good, and with probing alone nothing else would
// ever ask again.
func (cm *connectionManager) askForRelay(hostinfo *HostInfo, relay netip.Addr) {
	if cm.intf.relayManager == nil || !cm.intf.relayManager.GetUseRelays() {
		return
	}
	relayHostInfo := cm.intf.hostMap.QueryVpnAddr(relay)
	if relayHostInfo == nil || !relayHostInfo.GetRemote().IsValid() {
		// No tunnel to the relay itself; nothing to ask over.
		return
	}
	cm.l.Debug("Path probe is rebuilding a relay so the path can be measured again",
		"vpnAddrs", hostinfo.vpnAddrs,
		"relay", relay,
	)
	cm.intf.relayManager.requestRelay(cm.intf, hostinfo.logger(cm.l), slog.LevelDebug,
		relayHostInfo, hostinfo.vpnAddrs[0])
}

// pairSeed is a stable number for this pair of nodes, used to spread equally
// good paths. It must depend on BOTH ends: seeding from the peer alone would
// make every node pick the same relay for that peer, which is the concentration
// this is meant to undo.
func (cm *connectionManager) pairSeed(hostinfo *HostInfo) uint64 {
	h := fnv.New64a()
	if cm.intf != nil {
		for _, a := range cm.intf.myVpnAddrs {
			b := a.As16()
			h.Write(b[:])
		}
	}
	for _, a := range hostinfo.vpnAddrs {
		b := a.As16()
		h.Write(b[:])
	}
	return h.Sum64()
}

// judgePathProbe acts on a finished round and says in the log what it saw, so a
// tunnel sitting on a slow path is visible there and not only in round trip
// time.
func (cm *connectionManager) judgePathProbe(hostinfo *HostInfo, p *pathProbeState) {
	margin := time.Duration(cm.pathProbeMargin.Load())
	pinned := hostinfo.PinnedRelay()

	// File this round under each path and decide on what the paths USUALLY cost,
	// not on this one sample. A single sample decides badly on an unstable link:
	// overnight, four peers reached over a degraded uplink moved back and forth
	// all night while peers over a healthy link never moved at all.
	keep := map[netip.Addr]struct{}{}
	for _, l := range p.legs {
		keep[l.relay] = struct{}{}
		if l.got {
			hostinfo.notePathResult(l.relay, l.rtt)
		}
	}
	hostinfo.forgetPaths(keep)

	var live []probeLeg
	for _, l := range p.legs {
		// A path has to be alive NOW to be chosen. Looking back over rounds is
		// what stops a single swing from moving traffic, but the remembered
		// numbers must never resurrect a path that just went silent: seen in the
		// field, a peer was moved onto a direct path that had not answered at
		// all, because its median from earlier rounds still looked good.
		if !l.got {
			continue
		}
		typ, ok := hostinfo.pathTypical(l.relay)
		if !ok {
			continue
		}
		live = append(live, probeLeg{relay: l.relay, rtt: typ, got: true})
	}

	// Among paths that measure the same, spread the load instead of piling every
	// pair onto the single fastest relay. See chooseLeg for why.
	best, haveBest := chooseLeg(live, cm.pathProbeSpread.Load(), cm.pairSeed(hostinfo))

	if !haveBest {
		// Silence is not evidence that the path in use is bad, so nothing moves.
		cm.l.Info("Path probe got no replies",
			"vpnAddrs", hostinfo.vpnAddrs,
			"paths", p.describe(),
		)
		return
	}

	// Compare against the path actually in use, not against the direct one. A
	// margin that only guards direct-against-relay leaves relay-against-relay
	// unguarded, and two relays within noise of each other then swap every
	// round. Measured: one peer went .1 -> .2 -> .1 in forty minutes because the
	// two relays sat 10ms apart, exactly the margin.
	// The path in use is judged on this round for silence — a path that just
	// went quiet must hand over now, not in three rounds — but on its typical
	// cost when it is answering.
	current, haveCurrent := p.leg(pinned)
	if haveCurrent {
		if typ, ok := hostinfo.pathTypical(pinned); ok {
			current.rtt = typ
		}
	}
	if haveCurrent && best.rtt+margin >= current.rtt {
		cm.l.Debug("Path probe kept the same path",
			"vpnAddrs", hostinfo.vpnAddrs,
			"paths", p.describe(),
			"pinnedRelay", pinned,
			"margin", margin,
		)
		return
	}

	want := best.relay
	if want == pinned {
		cm.l.Debug("Path probe kept the same path",
			"vpnAddrs", hostinfo.vpnAddrs,
			"paths", p.describe(),
			"pinnedRelay", pinned,
		)
		return
	}

	// Three different things can move a tunnel, and flattening them into one
	// line makes the log useless for telling a healthy network from a sick one.
	reason := "faster by more than the margin"
	if !haveCurrent {
		switch {
		case !pinned.IsValid():
			// First decision for this peer. Not a failover.
			reason = "no path was in use"
		case p.carries(pinned):
			// The path was measured this round and did not answer.
			reason = "path in use stopped answering"
		default:
			// The path was not even a candidate any more: the relay tunnel it
			// rode on is gone. Seen in the field the moment a relay was cut, and
			// calling it "no path was in use" was plainly wrong - there was one.
			reason = "path in use is gone"
		}
	}

	hostinfo.pinRelay(want)
	if want.IsValid() {
		cm.l.Info("Path probe pinned a faster relay",
			"vpnAddrs", hostinfo.vpnAddrs,
			"relay", want,
			"wasPinned", pinned,
			"reason", reason,
			"paths", p.describe(),
			"margin", margin,
		)
	} else {
		cm.l.Info("Path probe released the pinned relay",
			"vpnAddrs", hostinfo.vpnAddrs,
			"wasPinned", pinned,
			"reason", reason,
			"paths", p.describe(),
			"margin", margin,
		)
	}
}

func (cm *connectionManager) tryRehandshake(hostinfo *HostInfo) {
	cs := cm.intf.pki.getCertState()
	curCrt := hostinfo.ConnectionState.myCert
	curCrtVersion := curCrt.Version()
	myCrt := cs.getCertificate(curCrtVersion)
	if myCrt == nil {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"version", curCrtVersion,
			"reason", "local certificate removed",
		)
		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
	peerCrt := hostinfo.ConnectionState.peerCert
	if peerCrt != nil && curCrtVersion < peerCrt.Certificate.Version() {
		// if our certificate version is less than theirs, and we have a matching version available, rehandshake?
		if cs.getCertificate(peerCrt.Certificate.Version()) != nil {
			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", hostinfo.vpnAddrs,
				"version", curCrtVersion,
				"peerVersion", peerCrt.Certificate.Version(),
				"reason", "local certificate version lower than peer, attempting to correct",
			)
			cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(hh *HandshakeHostInfo) {
				hh.initiatingVersionOverride = peerCrt.Certificate.Version()
			})
			return
		}
	}
	if !bytes.Equal(curCrt.Signature(), myCrt.Signature()) {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "local certificate is not current",
		)

		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
	if curCrtVersion < cs.initiatingVersion {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "current cert version < pki.initiatingVersion",
		)

		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}
	if hostinfo.ConnectionState.messageCounter.Load() >= RehandshakeAfterMessages {
		cm.l.Info("Re-handshaking with remote",
			"vpnAddrs", hostinfo.vpnAddrs,
			"reason", "message counter rehandshake threshold reached",
		)

		cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], nil)
		return
	}

	// Periodic path recheck. Only one end of a pair drives it, chosen the same
	// way shouldSwapPrimary breaks its tie: the node with the lower vpn addr.
	// Otherwise both ends re-handshake into each other.
	// The handshake fans out to every known remote and
	// the first reply wins, so simply re-running it lets a better path take
	// over. Without this the remote picked at handshake time is kept forever:
	// a tunnel that fell back to a relay stays there long after the direct
	// path came back, and from the outside it still looks "up".
	if interval := time.Duration(cm.pathRecheckInterval.Load()); interval > 0 {
		since := hostinfo.pathCheckedAt
		// One clock reading decides the whole thing and is also what gets
		// logged. Reading the clock again per branch lets a tunnel fall between
		// two of them on the same pass, and reports an elapsed time that is not
		// the one the decision was made on.
		elapsed := time.Since(since)
		switch {
		case since.IsZero():
			hostinfo.logger(cm.l).Debug("Path recheck skipped", "reason", "tunnel carries no establish stamp")
		case elapsed < interval:
			// not due yet, nothing to say
		case cm.intf.myVpnAddrs[0].Compare(hostinfo.vpnAddrs[0]) >= 0:
			hostinfo.logger(cm.l).Debug("Path recheck skipped", "reason", "peer drives this pair",
				"elapsed", elapsed, "mine", cm.intf.myVpnAddrs[0], "peer", hostinfo.vpnAddrs[0])
		default:
			// Describe the path traffic takes now, so the outcome can be
			// compared against it. A valid remote means the data plane is going
			// direct even if the last handshake arrived through a relay.
			var from string
			if pin := hostinfo.PinnedRelay(); pin.IsValid() && hostinfo.relayState.hasRelay(pin) {
				// Path probing put traffic on this relay, so that is the path in
				// use whatever hostinfo.remote says.
				from = "relay via " + pin.String()
			} else if r := hostinfo.remote.Load(); r != nil && r.IsValid() {
				from = "direct " + r.String()
			} else if relays := hostinfo.relayState.CopyRelayIps(); len(relays) > 0 {
				// A relayed tunnel carries no remote of its own; name the relay
				// we are reaching this peer through. Same wording as the outcome
				// uses, otherwise an unchanged path reads as a switch.
				from = "relay via " + relays[0].String()
			}

			cm.l.Info("Re-handshaking with remote",
				"vpnAddrs", hostinfo.vpnAddrs,
				"reason", "periodic path recheck",
				"interval", interval,
				"currentPath", from,
			)
			cm.intf.handshakeManager.StartHandshake(hostinfo.vpnAddrs[0], func(hh *HandshakeHostInfo) {
				hh.pathRecheck.Store(&from)
			})
			return
		}
	}
}
