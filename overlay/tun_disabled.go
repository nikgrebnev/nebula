package overlay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/routing"
)

type disabledTun struct {
	read chan []byte
	// closed is shut instead of read: a sender racing a close of read would
	// panic, so the channel packets travel on is never closed at all. Readers
	// and senders watch this one to learn the device is going away.
	closed      chan struct{}
	closeOnce   sync.Once
	vpnNetworks []netip.Prefix

	// Track these metrics since we don't have the tun device to do it for us
	tx metrics.Counter
	rx metrics.Counter
	l  *slog.Logger
}

// Read hands the next queued packet to a reader, copying it into b. Reads
// from concurrent queues are safe: the channel receive serializes them and
// each queue copies into its own private scratch buffer.
func (t *disabledTun) Read(b []byte) (int, error) {
	var r []byte
	select {
	case r = <-t.read:
	default:
		// Nothing queued: now it matters whether the device is going away.
		// Draining first keeps the old behaviour, where closing the channel let
		// a reader take what was already queued before it saw the close.
		select {
		case r = <-t.read:
		case <-t.closed:
			return 0, io.EOF
		}
	}

	t.tx.Inc(1)
	if t.l.Enabled(context.Background(), slog.LevelDebug) {
		t.l.Debug("Write payload", "raw", prettyPacket(r))
	}

	return copy(b, r), nil
}

func newDisabledTun(vpnNetworks []netip.Prefix, queueLen int, metricsEnabled bool, l *slog.Logger) *disabledTun {
	tun := &disabledTun{
		closed:      make(chan struct{}),
		vpnNetworks: vpnNetworks,
		read:        make(chan []byte, queueLen),
		l:           l,
	}

	if metricsEnabled {
		tun.tx = metrics.GetOrRegisterCounter("messages.tx.message", nil)
		tun.rx = metrics.GetOrRegisterCounter("messages.rx.message", nil)
	} else {
		tun.tx = &metrics.NilCounter{}
		tun.rx = &metrics.NilCounter{}
	}

	return tun
}

func (*disabledTun) Activate() error {
	return nil
}

func (*disabledTun) RoutesFor(addr netip.Addr) routing.Gateways {
	return routing.Gateways{}
}

func (t *disabledTun) Networks() []netip.Prefix {
	return t.vpnNetworks
}

func (*disabledTun) Name() string {
	return "disabled"
}

func (t *disabledTun) handleICMPEchoRequest(b []byte) bool {
	out := make([]byte, len(b))
	out = iputil.CreateICMPEchoResponse(b, out)
	if out == nil {
		return false
	}

	// attempt to write it, but don't block
	select {
	case t.read <- out:
	default:
		t.l.Debug("tun_disabled: dropped ICMP Echo Reply response")
	}

	return true
}

func (t *disabledTun) Write(b []byte) (int, error) {
	t.rx.Inc(1)

	// Check for ICMP Echo Request before spending time doing the full parsing
	if t.handleICMPEchoRequest(b) {
		if t.l.Enabled(context.Background(), slog.LevelDebug) {
			t.l.Debug("Disabled tun responded to ICMP Echo Request", "raw", prettyPacket(b))
		}
	} else if t.l.Enabled(context.Background(), slog.LevelDebug) {
		t.l.Debug("Disabled tun received unexpected payload", "raw", prettyPacket(b))
	}
	return len(b), nil
}

func (t *disabledTun) Queues(n int) ([]tio.Queue, error) {
	out := make([]tio.Queue, n)
	for i := range out {
		// NoClose: the shared channel and metrics are owned by the
		// disabledTun; Close on the device tears them down once for everybody.
		out[i] = tio.NewSingleQueueNoClose(t, defaultBatchBufSize)
	}
	return out, nil
}

// Close is safe to call more than once and safe to call while readers and
// senders are running. It does not touch t.read: writing that field is what the
// race detector flagged, and closing it would turn a concurrent send into a
// panic.
func (t *disabledTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	return nil
}

type prettyPacket []byte

func (p prettyPacket) String() string {
	var s strings.Builder

	for i, b := range p {
		if i > 0 && i%8 == 0 {
			s.WriteString(" ")
		}
		s.WriteString(fmt.Sprintf("%02x ", b))
	}

	return s.String()
}
