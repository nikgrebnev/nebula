package nebula

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
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
			if r := hostinfo.remote.Load(); r != nil && r.IsValid() {
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
