package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func leg(relay string, ms int) probeLeg {
	var a netip.Addr
	if relay != "" {
		a = netip.MustParseAddr(relay)
	}
	return probeLeg{relay: a, rtt: time.Duration(ms) * time.Millisecond, got: true}
}

// With spread off the behaviour is the old one, strictly the fastest path.
// Existing configurations must not notice this change at all.
func TestChooseLegWithoutSpreadPicksFastest(t *testing.T) {
	legs := []probeLeg{leg("10.0.0.1", 30), leg("10.0.0.2", 10), leg("10.0.0.6", 20)}
	got, ok := chooseLeg(legs, 0, 12345)
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), got.relay)
}

// The direct path here is not the fastest, only close enough to count as
// equal, and it still wins: it costs no third node anything.
func TestChooseLegPrefersDirectWithinSpread(t *testing.T) {
	legs := []probeLeg{leg("10.0.0.2", 10), leg("", 11), leg("10.0.0.1", 10)}
	got, ok := chooseLeg(legs, 20, 999)
	assert.True(t, ok)
	assert.False(t, got.relay.IsValid(), "the direct path must be chosen")
}

// Different pairs must land on different relays; that is the whole point.
func TestChooseLegSpreadsEqualRelays(t *testing.T) {
	legs := []probeLeg{leg("10.0.0.1", 10), leg("10.0.0.2", 11), leg("10.0.0.6", 10)}
	seen := map[netip.Addr]int{}
	for seed := uint64(0); seed < 300; seed++ {
		got, ok := chooseLeg(legs, 20, seed)
		assert.True(t, ok)
		seen[got.relay]++
	}
	assert.Len(t, seen, 3, "every equal path must be used")
	for relay, n := range seen {
		assert.Greater(t, n, 50, "path %s was chosen too rarely", relay)
	}
}

// A pair that changes path every round is worse off than one sharing a relay,
// so the same seed has to keep producing the same answer.
func TestChooseLegIsStableForSameSeed(t *testing.T) {
	legs := []probeLeg{leg("10.0.0.1", 10), leg("10.0.0.2", 11), leg("10.0.0.6", 10)}
	first, _ := chooseLeg(legs, 20, 42)
	for i := 0; i < 20; i++ {
		got, _ := chooseLeg(legs, 20, 42)
		assert.Equal(t, first.relay, got.relay)
	}
	// Leg order must not change the answer.
	shuffled := []probeLeg{legs[2], legs[0], legs[1]}
	got, _ := chooseLeg(shuffled, 20, 42)
	assert.Equal(t, first.relay, got.relay)
}

// A clearly slower path must never count as equal, whatever the seed.
func TestChooseLegExcludesSlowPaths(t *testing.T) {
	legs := []probeLeg{leg("10.0.0.1", 10), leg("10.0.0.2", 100)}
	for seed := uint64(0); seed < 50; seed++ {
		got, ok := chooseLeg(legs, 20, seed)
		assert.True(t, ok)
		assert.Equal(t, netip.MustParseAddr("10.0.0.1"), got.relay)
	}
}

// A path that did not answer is not a candidate, however good its last
// measurement was.
func TestChooseLegIgnoresSilentPaths(t *testing.T) {
	silent := leg("10.0.0.1", 1)
	silent.got = false
	legs := []probeLeg{silent, leg("10.0.0.2", 50)}
	got, ok := chooseLeg(legs, 20, 7)
	assert.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("10.0.0.2"), got.relay)
}
