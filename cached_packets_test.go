package nebula

import (
	"net/netip"
	"testing"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
)

// Packets for a tunnel that is still coming up wait in a queue whose ceiling
// used to be hard coded at 100, and a busy node lost more than half of that
// waiting data. The ceiling now comes from config, and anything above it has to
// land in the dropped counter instead of disappearing quietly.
func TestCachePacketRespectsConfiguredLimit(t *testing.T) {
	l := test.NewLogger()
	m := &cachedPacketMetrics{
		sent:    metrics.NewCounter(),
		dropped: metrics.NewCounter(),
	}
	hh := &HandshakeHostInfo{
		hostinfo:       &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")}},
		maxPacketStore: 3,
	}

	for i := 0; i < 5; i++ {
		hh.cachePacket(l, header.Message, 0, []byte{byte(i)}, nil, m)
	}

	assert.Len(t, hh.packetStore, 3, "the queue must stop at the configured ceiling")
	assert.Equal(t, int64(2), m.dropped.Count(), "packets past the ceiling must be counted as dropped")
}

// A zero ceiling means the setting is absent, so the previous default applies.
// Otherwise an existing config would silently end up with a queue of zero.
func TestCachePacketFallsBackToDefault(t *testing.T) {
	l := test.NewLogger()
	m := &cachedPacketMetrics{
		sent:    metrics.NewCounter(),
		dropped: metrics.NewCounter(),
	}
	hh := &HandshakeHostInfo{
		hostinfo: &HostInfo{vpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")}},
	}

	for i := 0; i < DefaultHandshakeCachedPackets+2; i++ {
		hh.cachePacket(l, header.Message, 0, []byte{byte(i)}, nil, m)
	}

	assert.Len(t, hh.packetStore, DefaultHandshakeCachedPackets)
	assert.Equal(t, int64(2), m.dropped.Count())
}
