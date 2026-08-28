package nebula

import (
	"context"
	"encoding/json"
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
// "how much", not "through whom" — topology is not a counter.
//
// Bind it to the nebula address and the endpoint is reachable from inside the
// overlay and nowhere else, which is the right blast radius for something that
// lists your peers.
type statusServer struct {
	l            *slog.Logger
	ctx          context.Context
	c            *config.C
	ctrl         *Control
	buildVersion string
	started      time.Time

	mu     sync.Mutex
	listen string
	srv    *http.Server
}

func newStatusServerFromConfig(ctx context.Context, l *slog.Logger, c *config.C, ctrl *Control, buildVersion string) (*statusServer, error) {
	s := &statusServer{
		l:            l,
		ctx:          ctx,
		c:            c,
		ctrl:         ctrl,
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

// reload records the wanted address. A changed address takes effect on the next
// Start; a running listener is left alone rather than dropped mid-flight, since
// nothing depends on the endpoint being restarted promptly.
func (s *statusServer) reload(c *config.C) error {
	addr := c.GetString("status.listen", "")
	if addr != "" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("status.listen is not host:port: %w", err)
		}
	}
	s.mu.Lock()
	s.listen = addr
	s.mu.Unlock()
	return nil
}

func (s *statusServer) Start() {
	s.mu.Lock()
	addr := s.listen
	if addr == "" || s.srv != nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status.json", s.serveJSON)
	mux.HandleFunc("/status", s.serveHTML)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/status", http.StatusFound)
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.srv = srv
	s.mu.Unlock()

	go func() {
		s.l.Info("Status listener started", "listen", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.l.Error("Status listener stopped", "error", err)
		}
	}()
	go func() {
		<-s.ctx.Done()
		s.Stop()
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
	Peers           int `json:"peers"`
	Direct          int `json:"direct"`
	Relayed         int `json:"relayed"`
	Pinned          int `json:"pinned"`
	RelaysThroughMe int `json:"relaysThroughMe"`
}

// describePath names the path a peer's traffic takes, using the same order of
// preference the send path itself uses: a measured pin wins, then a direct
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

func (s *statusServer) report() statusReport {
	return buildStatusReport(
		s.ctrl.ListHostmapHosts(false),
		s.buildVersion,
		time.Since(s.started).Truncate(time.Second).String(),
		s.c.GetBool("relay.am_relay", false),
		s.c.GetBool("lighthouse.am_lighthouse", false),
	)
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
		rep.Counts.RelaysThroughMe += len(h.ForwardingFor)
	}
	return rep
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
<p>uptime {{.Uptime}}{{if .AmLighthouse}} · lighthouse{{end}}{{if .AmRelay}} · relay{{end}}<br>
peers {{.Counts.Peers}} · direct {{.Counts.Direct}} · relayed {{.Counts.Relayed}} ·
pinned {{.Counts.Pinned}} · relaying for {{.Counts.RelaysThroughMe}}</p>
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
