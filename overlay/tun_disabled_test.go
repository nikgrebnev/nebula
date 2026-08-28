package overlay

import (
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Close used to clear the field the read loop was receiving from, which the
// race detector flags and which no amount of retrying makes safe. Run the two
// against each other so the fix is checked here rather than only by the five
// second integration test in cmd/nebula.
func TestDisabledTunCloseRacesWithRead(t *testing.T) {
	tun := newDisabledTun([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		4, false, test.NewLogger())

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 1500)
			for {
				if _, err := tun.Read(b); err == io.EOF {
					return
				}
			}
		}()
	}

	require.NoError(t, tun.Close())
	wg.Wait()
}

// Closing twice happened in the field: the device is closed by whoever gets
// there first, and the previous guard made the second call a no-op only by
// luck of scheduling.
func TestDisabledTunCloseIsIdempotent(t *testing.T) {
	tun := newDisabledTun([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		1, false, test.NewLogger())
	assert.NoError(t, tun.Close())
	assert.NoError(t, tun.Close())

	b := make([]byte, 1500)
	_, err := tun.Read(b)
	assert.Equal(t, io.EOF, err, "a read after Close must return EOF, not block")
}

// A sender running into a closed device must be dropped, not panic. Closing the
// packet channel itself would turn this into "send on closed channel".
func TestDisabledTunWriteAfterCloseDoesNotPanic(t *testing.T) {
	tun := newDisabledTun([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		1, false, test.NewLogger())
	require.NoError(t, tun.Close())

	// An ICMP echo request is the path that writes back into the read channel.
	echo := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
		10, 0, 0, 2, 10, 0, 0, 1,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	assert.NotPanics(t, func() { _, _ = tun.Write(echo) })
}

// Closing the channel used to let a reader take what was already queued before
// it saw the close. Keep that: a bug fix should not quietly change behaviour.
func TestDisabledTunReadDrainsQueueAfterClose(t *testing.T) {
	tun := newDisabledTun([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		4, false, test.NewLogger())

	// An ICMP echo request is the path that queues a reply for the reader.
	echo := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
		10, 0, 0, 2, 10, 0, 0, 1,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	_, err := tun.Write(echo)
	require.NoError(t, err)
	require.NoError(t, tun.Close())

	b := make([]byte, 1500)
	n, err := tun.Read(b)
	require.NoError(t, err, "a packet queued before Close must still be delivered")
	assert.Greater(t, n, 0)

	_, err = tun.Read(b)
	assert.Equal(t, io.EOF, err, "and EOF once the queue is drained")
}
