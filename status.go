package nebula

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/slackhq/nebula/config"
)

// A status endpoint answers "what is this node doing right now" over HTTP:
// which peers it holds, which path each peer's traffic is on, and which relays
// it carries for others.
//
// It exists because the only other way to ask was to ssh to every node and grep
// the log for the last decision. That does not scale past a handful of hosts,
// it cannot be watched over time, and a log line is the past tense of a
// decision rather than the current state. Prometheus stats next door answer
// "how much", not "through whom": topology is not a counter.
//
// Bind it to the nebula address and the endpoint is reachable from inside the
// overlay and nowhere else, which is the right blast radius for something that
// lists your peers.
type statusServer struct {
	l            *slog.Logger
	ctx          context.Context
	c            *config.C
	buildVersion string
	started      time.Time

	mu   sync.Mutex
	ctrl *Control
	// controlStarted is set by the first Start, which Control makes when the
	// node comes up. Until then a config change only records the address:
	// there is no node to report on yet, and Start reads what was recorded.
	controlStarted bool
	listen         string
	srv            *http.Server

	reportMu sync.Mutex
	reported statusReport
	reportAt time.Time
}

// statusReportTTL is how long a report is handed out again before another one
// is built. Building one walks the whole hostmap while holding the read lock
// that tunnel setup and teardown need - around 200us for 500 peers on a 2019
// desktop core - so without this a client polling in a loop spends a node's
// lock time on a page nobody reads twice. A page a human refreshes does not
// need to be fresher than this, and a collector scraping it does not either.
const statusReportTTL = time.Second

// newStatusServerFromConfig validates status.listen and registers the reload
// callback. It takes no Control because it is built during `nebula -test` too,
// where there is no Control and the point is to reject a bad address before a
// restart finds it; Main calls attach once the Control exists.
func newStatusServerFromConfig(ctx context.Context, l *slog.Logger, c *config.C, buildVersion string) (*statusServer, error) {
	s := &statusServer{
		l:            l,
		ctx:          ctx,
		c:            c,
		buildVersion: buildVersion,
		started:      time.Now(),
	}
	if err := s.reload(c); err != nil {
		return nil, err
	}
	c.RegisterReloadCallback(func(c *config.C) {
		if err := s.reload(c); err != nil {
			s.l.Error("Failed to reload status listener from config", "error", err)
		}
	})
	return s, nil
}

// attach hands over the Control the endpoint reports on. Start refuses to bind
// before this happens, so a config reload during a config test cannot stand a
// listener up on a node that does not exist.
func (s *statusServer) attach(ctrl *Control) {
	s.mu.Lock()
	s.ctrl = ctrl
	s.mu.Unlock()
}

// reload applies status.listen. Changing the address on a running node moves
// the listener: the old one is shut down and the new one bound, and an empty
// address turns the endpoint off. Before the node is up the address is only
// recorded, because Start is what binds it.
func (s *statusServer) reload(c *config.C) error {
	addr := c.GetString("status.listen", "")
	if addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("status.listen is not host:port: %w", err)
		}
	}

	s.mu.Lock()
	changed := s.listen != addr
	s.listen = addr
	move := changed && s.controlStarted
	s.mu.Unlock()

	if !move {
		return nil
	}

	s.Stop()
	if addr == "" {
		s.l.Info("Status listener stopped, status.listen is now empty")
		return nil
	}
	s.Start()
	return nil
}

// Start binds the endpoint and returns; the listener runs in its own goroutine.
// It is a no-op when status.listen is empty, when a listener is already up, or
// before a Control has been attached.
func (s *statusServer) Start() {
	s.mu.Lock()
	s.controlStarted = true
	addr := s.listen
	if addr == "" || s.srv != nil || s.ctrl == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	srv := newStatusHTTPServer(addr, s.handler())
	s.srv = srv
	s.mu.Unlock()

	// The watcher exists to shut the listener down when the node does. It ends
	// with the listener so a moved endpoint does not leave one behind per
	// reload.
	done := make(chan struct{})
	go func() {
		select {
		case <-s.ctx.Done():
			s.Stop()
		case <-done:
		}
	}()

	go func() {
		defer close(done)
		s.l.Info("Status listener started", "listen", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.l.Error("Status listener stopped", "error", err)
		}
		// Only drop the pointer if it is still ours. A reload that moved the
		// endpoint has already put its own listener there, and clearing that
		// one would leave it running with nothing able to stop it.
		s.mu.Lock()
		if s.srv == srv {
			s.srv = nil
		}
		s.mu.Unlock()
	}()
}

func (s *statusServer) Stop() {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func (s *statusServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status.json", s.serveJSON)
	mux.HandleFunc("/status", s.serveHTML)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/status", http.StatusFound)
	})
	return mux
}

// newStatusHTTPServer builds the listener with a deadline on every phase of a
// request. http.Server has none by default: without WriteTimeout a client that
// sends a request and then stops reading holds a goroutine and its buffers for
// as long as it cares to, and without IdleTimeout a kept-alive connection is
// never reclaimed. Neither needs an attacker, a stuck ssh tunnel to the page is
// enough.
func newStatusHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// statusPeer is one peer as the endpoint reports it. It is deliberately not
// ControlHostInfo: that carries the whole certificate, which is bulk nobody
// reads when the question is "which way does this peer's traffic go".
type statusPeer struct {
	VpnAddrs []netip.Addr `json:"vpnAddrs"`
	Path     string       `json:"path"`
	// Remote and PinnedRelay are strings, not netip types: `omitempty` does
	// nothing for a struct, so an unset address would ship as "" and leave the
	// reader guessing whether it is absent or empty.
	Remote      string       `json:"remote,omitempty"`
	PinnedRelay string       `json:"pinnedRelay,omitempty"`
	RelaysToMe  []netip.Addr `json:"relaysToMe,omitempty"`
	// ForwardingFor is traffic this node CARRIES for others. Reporting the
	// mixed relay list here instead would credit every node that merely uses a
	// relay with carrying one.
	ForwardingFor []netip.Addr `json:"forwardingFor,omitempty"`
	Messages      uint64       `json:"messages"`
}

type statusReport struct {
	Version      string       `json:"version"`
	Uptime       string       `json:"uptime"`
	AmRelay      bool         `json:"amRelay"`
	AmLighthouse bool         `json:"amLighthouse"`
	Peers        []statusPeer `json:"peers"`
	Counts       statusCounts `json:"counts"`
}

type statusCounts struct {
	Peers   int `json:"peers"`
	Direct  int `json:"direct"`
	Relayed int `json:"relayed"`
	Pinned  int `json:"pinned"`
	// RelaysThroughMe is the number of peer pairs this node carries traffic
	// for, each counted once. Forwarding a pair leaves a record on both of its
	// ends, so this is not the sum of the per-peer lists below.
	RelaysThroughMe int `json:"relaysThroughMe"`
}

// describePeerPath names the path a peer's traffic takes, using the same order
// of preference the send path itself uses: a measured pin wins, then a direct
// remote, then whatever relay is on hand.
func describePeerPath(h ControlHostInfo) string {
	if h.PinnedRelay.IsValid() {
		return "relay " + h.PinnedRelay.String() + " (measured)"
	}
	if h.CurrentRemote.IsValid() {
		return "direct"
	}
	if len(h.CurrentRelaysToMe) > 0 {
		return "relay " + h.CurrentRelaysToMe[0].String()
	}
	return "unknown"
}

// report answers with the last report while it is younger than statusReportTTL,
// and builds a new one otherwise. Holding reportMu across the build also means
// concurrent requests wait for one walk instead of each starting their own.
func (s *statusServer) report() statusReport {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()

	if !s.reportAt.IsZero() && time.Since(s.reportAt) < statusReportTTL {
		return s.reported
	}

	s.mu.Lock()
	ctrl := s.ctrl
	s.mu.Unlock()

	var hosts []ControlHostInfo
	if ctrl != nil {
		hosts = ctrl.listHostmapPaths()
	}

	s.reported = buildStatusReport(
		hosts,
		s.buildVersion,
		time.Since(s.started).Truncate(time.Second).String(),
		s.c.GetBool("relay.am_relay", false),
		s.c.GetBool("lighthouse.am_lighthouse", false),
	)
	s.reportAt = time.Now()

	return s.reported
}

// buildStatusReport is split out from report so the shape of the answer can be
// tested without standing up a whole node.
func buildStatusReport(hosts []ControlHostInfo, version, uptime string, amRelay, amLighthouse bool) statusReport {
	rep := statusReport{
		Version:      version,
		Uptime:       uptime,
		AmRelay:      amRelay,
		AmLighthouse: amLighthouse,
		Peers:        make([]statusPeer, 0, len(hosts)),
	}

	forwarding := false

	for _, h := range hosts {
		p := statusPeer{
			VpnAddrs:      h.VpnAddrs,
			Path:          describePeerPath(h),
			RelaysToMe:    h.CurrentRelaysToMe,
			ForwardingFor: h.ForwardingFor,
			Messages:      h.MessageCounter,
		}
		if h.CurrentRemote.IsValid() {
			p.Remote = h.CurrentRemote.String()
		}
		if h.PinnedRelay.IsValid() {
			p.PinnedRelay = h.PinnedRelay.String()
		}
		rep.Peers = append(rep.Peers, p)
		rep.Counts.Peers++
		if p.PinnedRelay != "" {
			rep.Counts.Pinned++
		}
		if p.Path == "direct" {
			rep.Counts.Direct++
		} else if p.Path != "unknown" {
			rep.Counts.Relayed++
		}
		forwarding = forwarding || len(h.ForwardingFor) > 0
	}

	if forwarding {
		rep.Counts.RelaysThroughMe = countCarriedPairs(hosts)
	}

	return rep
}

// countCarriedPairs counts the peer pairs this node forwards between. Carrying
// a pair puts an entry on the peer the traffic comes from and on the peer it
// goes to, so adding up the per-peer lists reports twice the work being done.
//
// A peer can be known by several addresses while the far end of a pair names
// only one of them, so every address is folded onto the peer's first one before
// the two ends are matched up. A peer that is not in the list at all - a
// hostinfo that went away between the two reads - still counts once, under the
// address it was named by.
func countCarriedPairs(hosts []ControlHostInfo) int {
	primary := make(map[netip.Addr]netip.Addr, len(hosts))
	for _, h := range hosts {
		for _, a := range h.VpnAddrs {
			primary[a] = h.VpnAddrs[0]
		}
	}

	carried := make(map[[2]netip.Addr]struct{})
	for _, h := range hosts {
		if len(h.VpnAddrs) == 0 {
			continue
		}
		self := h.VpnAddrs[0]
		for _, other := range h.ForwardingFor {
			if first, ok := primary[other]; ok {
				other = first
			}
			pair := [2]netip.Addr{self, other}
			if other.Compare(self) < 0 {
				pair = [2]netip.Addr{other, self}
			}
			carried[pair] = struct{}{}
		}
	}

	return len(carried)
}

func (s *statusServer) serveJSON(w http.ResponseWriter, r *http.Request) {
	if err := writeStatusJSON(w, s.report()); err != nil {
		s.l.Error("Failed to write status json", "error", err)
	}
}

// writeStatusJSON is split out from the handler for the same reason
// buildStatusReport is split out from report: so the shape of what goes on the
// wire can be tested without standing up a node.
func writeStatusJSON(w http.ResponseWriter, rep statusReport) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

var statusTmpl = template.Must(template.New("status").Parse(`<!doctype html>
<meta charset="utf-8"><title>nebula status</title>
<style>
body{font:14px/1.4 system-ui,sans-serif;margin:2rem;color:#222}
table{border-collapse:collapse}th,td{padding:.25rem .6rem;border-bottom:1px solid #ddd;text-align:left}
th{background:#f4f4f4}td.n{text-align:right;font-variant-numeric:tabular-nums}
.d{color:#0a0}.r{color:#b60}
</style>
<h1>nebula {{.Version}}</h1>
<p>uptime {{.Uptime}}{{if .AmLighthouse}} &middot; lighthouse{{end}}{{if .AmRelay}} &middot; relay{{end}}<br>
peers {{.Counts.Peers}} &middot; direct {{.Counts.Direct}} &middot; relayed {{.Counts.Relayed}} &middot;
pinned {{.Counts.Pinned}} &middot; relaying for {{.Counts.RelaysThroughMe}} pairs</p>
<table><tr><th>peer<th>path<th>remote<th>relays to me<th>relaying through me<th>messages</tr>
{{range .Peers}}<tr>
<td>{{range .VpnAddrs}}{{.}} {{end}}
<td class="{{if eq .Path "direct"}}d{{else}}r{{end}}">{{.Path}}
<td>{{.Remote}}
<td>{{range .RelaysToMe}}{{.}} {{end}}
<td>{{range .ForwardingFor}}{{.}} {{end}}
<td class="n">{{.Messages}}
</tr>{{end}}</table>
`))

func (s *statusServer) serveHTML(w http.ResponseWriter, r *http.Request) {
	if err := writeStatusHTML(w, s.report()); err != nil {
		s.l.Error("Failed to write status html", "error", err)
	}
}

// writeStatusHTML renders the same report as the JSON endpoint. Kept separate
// from the handler so the template is exercised by tests: a template that fails
// to execute would otherwise only show up as a half written page in production.
func writeStatusHTML(w http.ResponseWriter, rep statusReport) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return statusTmpl.Execute(w, rep)
}
