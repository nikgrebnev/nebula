package nebula

import (
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"

	"github.com/slackhq/nebula/test"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleReport() statusReport {
	pin := netip.MustParseAddr("10.0.0.2")
	relay := netip.MustParseAddr("10.0.0.6")
	remote := netip.MustParseAddrPort("192.0.2.5:4242")
	return buildStatusReport([]ControlHostInfo{
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.11")},
			CurrentRemote: remote, PinnedRelay: pin, MessageCounter: 7},
		{VpnAddrs: []netip.Addr{netip.MustParseAddr("10.0.0.13")},
			CurrentRelaysToMe: []netip.Addr{relay}},
	}, "1.11.1-test", "5m0s", true, false)
}

// The JSON has to parse back and carry the same numbers, otherwise a metrics
// collector silently records something other than what the page shows.
func Test_StatusJSON_IsValidAndCarriesTheReport(t *testing.T) {
	w := httptest.NewRecorder()
	require.NoError(t, writeStatusJSON(w, sampleReport()))

	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var got statusReport
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got), "response must be parsable JSON")
	assert.Equal(t, "1.11.1-test", got.Version)
	require.Len(t, got.Peers, 2)
	assert.Equal(t, "relay 10.0.0.2 (measured)", got.Peers[0].Path)
	assert.Equal(t, uint64(7), got.Peers[0].Messages)
	assert.Equal(t, 2, got.Counts.Peers)
}

// The template runs on every request, and a failure part way through reaches
// the client as a page that stops in the middle. This is the cheap place to
// find that out.
func Test_StatusHTML_RendersTheSameReport(t *testing.T) {
	w := httptest.NewRecorder()
	require.NoError(t, writeStatusHTML(w, sampleReport()))

	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	body := w.Body.String()
	assert.Contains(t, body, "nebula 1.11.1-test")
	assert.Contains(t, body, "10.0.0.11")
	assert.Contains(t, body, "relay 10.0.0.2 (measured)")
	assert.Contains(t, body, "relaying for")
	assert.False(t, strings.Contains(body, "{{"), "body must not contain unrendered template fields")
}

// An empty listen address means the status page is off, not that the config
// is wrong. Without this, a node with no status block would still start a
// listener: net/http reads a blank Addr as port 80.
func Test_StatusServer_StartWithoutListenIsANoOp(t *testing.T) {
	s := &statusServer{l: test.NewLogger(), listen: ""}
	s.Start()
	assert.Nil(t, s.srv, "server must not start without a listen address")
	s.Stop()
	s.Stop() // a second Stop must be safe
}
