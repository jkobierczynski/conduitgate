// Command conduitgate is a read-only Modbus/TCP enforcement proxy.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"conduitgate/modbus"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always --dirty)"
var version = "dev"

var (
	logger  *slog.Logger
	metrics = modbus.NewMetrics()
)

func main() {
	policyPath := flag.String("policy", "", "policy file (JSON); see policy/example.json")
	listen := flag.String("listen", "", "listen address, when running without a policy")
	target := flag.String("target", "", "device to protect, when running without a policy")
	diag := flag.Bool("allow-diagnostics", false,
		"without a policy: permit FC 8 with the default subfunction allowlist")
	explain := flag.String("explain", "",
		"print the rationale for a denial reason code, or \"list\" for all of them")

	logFormat := flag.String("log-format", "text", "text or json")
	logAllows := flag.Bool("log-allows", false,
		"log permitted operations too; off by default because a polling HMI "+
			"generates them continuously and the audit value is in the denials")
	metricsAddr := flag.String("metrics", "",
		"serve Prometheus metrics and /healthz on this address; empty disables it")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *explain != "" {
		if !printExplanation(*explain) {
			os.Exit(1)
		}
		return
	}

	logger = newLogger(*logFormat)
	metrics.Add("conduitgate_build_info", 1, "version", version)

	if *metricsAddr != "" {
		serveMetrics(*metricsAddr)
	}

	switch {
	case *policyPath != "":
		runPolicy(*policyPath, *logAllows)
	case *target != "":
		runBench(*listen, *target, *diag, *logAllows)
	default:
		logger.Error("one of -policy or -target is required")
		os.Exit(2)
	}
}

func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	switch strings.ToLower(format) {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	default:
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
}

// serveMetrics runs the management endpoints on their own listener, separate
// from every data path. Nothing here reaches the device, and it should be bound
// to a management interface rather than the one clients connect on.
func serveMetrics(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := metrics.WriteText(w); err != nil {
			logger.Warn("writing metrics failed", "error", err)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("metrics listener failed", "addr", addr, "error", err)
		os.Exit(1)
	}
	if host, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		if ip := net.ParseIP(host); host == "" || ip == nil || ip.IsUnspecified() {
			logger.Warn("metrics endpoint is not bound to a specific address; "+
				"bind it to a management interface", "addr", addr)
		}
	}
	logger.Info("metrics listening", "addr", addr, "paths", "/metrics /healthz")
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server stopped", "error", err)
		}
	}()
}

// runPolicy serves every target in the policy, one listener each.
//
// A listener that cannot bind is fatal rather than skipped: a partially served
// policy is worse than none, because the targets that did come up make the
// gateway look like it is working.
func runPolicy(path string, logAllows bool) {
	pol, err := modbus.LoadPolicy(path)
	if err != nil {
		// A policy that does not load is not a reason to run with none.
		logger.Error("policy rejected", "error", err)
		os.Exit(1)
	}

	maxOut, ttl, idle, maxConns := pol.SessionLimits()
	logger.Info("policy loaded",
		"path", path, "version", version, "targets", len(pol.Targets),
		"fail", failWord(pol.FailOpen()),
		"max_outstanding", maxOut,
		"pending_ttl", ttl.String(),
		"idle_timeout", idle.String(),
		"half_open_timeout", halfOpenWord(pol.HalfOpenTimeout()),
		"max_conns_per_source", maxConns)

	if pol.FailOpen() {
		logger.Warn("fail_mode is open: denied requests are forwarded and this proxy enforces nothing")
	}

	proxies := make(map[string]*modbus.Proxy, len(pol.Targets))
	listeners := make([]net.Listener, 0, len(pol.Targets))

	for _, t := range pol.Targets {
		ln, lerr := net.Listen("tcp", t.Listen)
		if lerr != nil {
			for _, open := range listeners {
				open.Close()
			}
			logger.Error("listener failed", "target", t.Name, "listen", t.Listen, "error", lerr)
			os.Exit(1)
		}
		listeners = append(listeners, ln)

		units := make([]string, 0, len(t.Units))
		for _, u := range t.Units {
			units = append(units, fmt.Sprint(u.ID))
		}
		logger.Info("target ready",
			"target", t.Name, "listen", t.Listen, "device", t.Address,
			"units", strings.Join(units, ","), "sources", sourceWord(t))

		proxy := pol.NewProxy(t)
		proxy.Metrics = metrics
		proxy.OnEvent = eventLogger(logAllows)
		proxies[t.Name] = proxy
	}

	go watchReloads(path, pol, proxies)

	var wg sync.WaitGroup
	for i, t := range pol.Targets {
		proxy, ln, name := proxies[t.Name], listeners[i], t.Name
		wg.Add(1)
		go func() {
			defer wg.Done()
			if serr := proxy.Serve(ln); serr != nil {
				logger.Error("target stopped", "target", name, "error", serr)
			}
		}()
	}
	wg.Wait()
}

// watchReloads applies a new policy on SIGHUP.
//
// Only the rule sets are swapped — units, address windows and per-target source
// lists — because those are held atomically and can change under live
// connections safely. Anything structural is refused and the running policy is
// kept: rebinding listeners or retuning session bounds underneath an inline
// element in a control path is worse than asking for a restart at a moment the
// operator chooses.
func watchReloads(path string, current *modbus.Policy, proxies map[string]*modbus.Proxy) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	for range ch {
		next, err := modbus.LoadPolicy(path)
		if err != nil {
			logger.Error("reload refused: policy rejected", "path", path, "error", err)
			continue
		}
		if before, after := topology(current), topology(next); before != after {
			logger.Error("reload refused: targets changed, which needs a restart",
				"was", before, "now", after)
			continue
		}
		if before, after := sessionShape(current), sessionShape(next); before != after {
			logger.Error("reload refused: session bounds changed, which needs a restart",
				"was", before, "now", after)
			continue
		}
		if current.FailOpen() != next.FailOpen() {
			logger.Error("reload refused: fail_mode changed, which needs a restart")
			continue
		}

		for _, t := range next.Targets {
			if proxy, ok := proxies[t.Name]; ok {
				proxy.SetRules(t)
			}
		}
		current = next
		logger.Info("policy reloaded; rules apply to live connections from their next request",
			"path", path, "targets", len(next.Targets))
	}
}

// topology is the part of a policy that cannot change without a restart.
func topology(p *modbus.Policy) string {
	parts := make([]string, 0, len(p.Targets))
	for _, t := range p.Targets {
		parts = append(parts, fmt.Sprintf("%s@%s->%s", t.Name, t.Listen, t.Address))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func sessionShape(p *modbus.Policy) string {
	maxOut, ttl, idle, conns := p.SessionLimits()
	return fmt.Sprintf("%d/%s/%s/%d/%s", maxOut, ttl, idle, conns, p.HalfOpenTimeout())
}

// runBench is the no-policy mode: one global read-only rule, every unit id
// reachable, every address in range. Useful at a bench, not in a plant.
func runBench(listen, target string, diag, logAllows bool) {
	lim := modbus.DefaultLimits()
	lim.AllowDiagnostics = diag

	p := &modbus.Proxy{
		Name:        "bench",
		Target:      target,
		Limits:      lim,
		IdleTimeout: 120 * time.Second,
		Metrics:     metrics,
		OnEvent:     eventLogger(logAllows),
	}
	if listen == "" {
		listen = "127.0.0.1:5502"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Error("listener failed", "listen", listen, "error", err)
		os.Exit(1)
	}
	logger.Warn("no policy: global read-only posture, all unit ids and addresses reachable")
	logger.Info("listening", "listen", listen, "device", target, "version", version)
	if serr := p.Serve(ln); serr != nil {
		logger.Error("stopped", "error", serr)
		os.Exit(1)
	}
}

// eventLogger renders decisions as structured records.
//
// Denials are warnings and always logged; permitted operations are info and off
// unless asked for. A polling HMI produces an allow every poll interval
// forever, so logging them by default would bury the denials and swamp whatever
// collects them. The reason code is the field to alert on.
func eventLogger(logAllows bool) func(modbus.Event) {
	return func(e modbus.Event) {
		if e.Allowed {
			if !logAllows {
				return
			}
			logger.Info("allow",
				"target", e.Target, "dir", e.Dir, "remote", e.Remote,
				"txid", e.TxID, "unit", e.UnitID,
				"fc", fmt.Sprintf("0x%02X", e.FC), "fc_name", e.Name)
			return
		}
		logger.Warn("deny",
			"target", e.Target, "dir", e.Dir, "remote", e.Remote,
			"txid", e.TxID, "unit", e.UnitID,
			"fc", fmt.Sprintf("0x%02X", e.FC), "fc_name", e.Name,
			"reason", e.Reason, "detail", e.Detail)
	}
}

func halfOpenWord(d time.Duration) string {
	if d < 0 {
		return "disabled"
	}
	return d.String()
}

func failWord(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}

func sourceWord(t *modbus.TargetPolicy) string {
	switch {
	case len(t.Sources) > 0:
		return strings.Join(t.Sources, ",")
	case t.InheritsSources():
		return "inherited"
	default:
		return "any"
	}
}

// printExplanation backs -explain. Denial reason codes are the tool's stable
// interface — they appear in logs, in metrics and in this lookup — so they are
// documented here rather than pasted into every log line.
func printExplanation(code string) bool {
	if code == "list" {
		fmt.Println("Denial reason codes. Use -explain <code> for the rationale.")
		fmt.Println()
		for _, c := range modbus.ReasonCodes() {
			fmt.Printf("  %s\n", c)
		}
		return true
	}
	text, ok := modbus.Explain(code)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown reason code %q; try -explain list\n", code)
		return false
	}
	fmt.Printf("%s\n\n%s\n", code, text)
	return true
}
