// Command conduitgate is a read-only Modbus/TCP enforcement proxy.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"conduitgate/modbus"
)

func main() {
	policyPath := flag.String("policy", "", "policy file (JSON); see policy/example.json")
	listen := flag.String("listen", "", "listen address, when running without a policy")
	target := flag.String("target", "", "device to protect, when running without a policy")
	diag := flag.Bool("allow-diagnostics", false,
		"without a policy: permit FC 8 with the default subfunction allowlist")
	explain := flag.String("explain", "",
		"print the rationale for a denial reason code, or \"list\" for all of them")
	flag.Parse()

	if *explain != "" {
		if !printExplanation(*explain) {
			os.Exit(1)
		}
		return
	}

	switch {
	case *policyPath != "":
		runPolicy(*policyPath)
	case *target != "":
		runBench(*listen, *target, *diag)
	default:
		log.Fatal("one of -policy or -target is required")
	}
}

// runPolicy serves every target in the policy, one listener each.
//
// A listener that cannot bind is fatal rather than skipped: a partially served
// policy is worse than none, because the targets that did come up make the
// gateway look like it is working.
func runPolicy(path string) {
	pol, err := modbus.LoadPolicy(path)
	if err != nil {
		// A policy that does not load is not a reason to run with none.
		log.Fatalf("%v", err)
	}

	maxOut, ttl, idle, maxConns := pol.SessionLimits()
	log.Printf("policy %s: %d target(s), fail %s, %d outstanding, %ds ttl, %ds idle, %d conns/source",
		path, len(pol.Targets), failWord(pol.FailOpen()), maxOut,
		int(ttl.Seconds()), int(idle.Seconds()), maxConns)
	if pol.FailOpen() {
		log.Printf("WARNING: fail_mode is \"open\" — denied requests are forwarded, " +
			"and this proxy enforces nothing")
	}

	listeners := make([]net.Listener, 0, len(pol.Targets))
	for _, t := range pol.Targets {
		ln, err := net.Listen("tcp", t.Listen)
		if err != nil {
			for _, open := range listeners {
				open.Close()
			}
			log.Fatalf("target %q: %v", t.Name, err)
		}
		listeners = append(listeners, ln)

		units := make([]string, 0, len(t.Units))
		for _, u := range t.Units {
			units = append(units, fmt.Sprintf("%d", u.ID))
		}
		log.Printf("  %-16s %s -> %s  unit(s) %v  sources %s",
			t.Name, t.Listen, t.Address, units, sourceWord(t))
	}

	var wg sync.WaitGroup
	for i, t := range pol.Targets {
		proxy := pol.NewProxy(t)
		proxy.OnEvent = logEvent
		ln := listeners[i]
		name := t.Name
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.Serve(ln); err != nil {
				log.Printf("target %q stopped: %v", name, err)
			}
		}()
	}
	wg.Wait()
}

// runBench is the no-policy mode: one global read-only rule, every unit id
// reachable, every address in range. Useful at a bench, not in a plant.
func runBench(listen, target string, diag bool) {
	lim := modbus.DefaultLimits()
	lim.AllowDiagnostics = diag

	p := &modbus.Proxy{
		Name:        "bench",
		Target:      target,
		Limits:      lim,
		IdleTimeout: 120 * time.Second,
		OnEvent:     logEvent,
	}
	if listen == "" {
		listen = "127.0.0.1:5502"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("no policy: global read-only posture, all unit ids and addresses reachable")
	log.Printf("conduitgate listening on %s -> %s (read-only)", listen, target)
	log.Fatal(p.Serve(ln))
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
		return fmt.Sprintf("%v", t.Sources)
	case t.InheritsSources():
		return "inherited from policy"
	default:
		return "any"
	}
}

func logEvent(e modbus.Event) {
	dir := "->"
	if e.Dir == modbus.DirResponse {
		dir = "<-"
	}
	if e.Allowed {
		log.Printf("ALLOW %s [%s] tx=%-5d uid=%-3d fc=0x%02X %s",
			dir, e.Target, e.TxID, e.UnitID, e.FC, e.Name)
		return
	}
	log.Printf("DENY  %s [%s] tx=%-5d uid=%-3d fc=0x%02X %s [%s] %s",
		dir, e.Target, e.TxID, e.UnitID, e.FC, e.Name, e.Reason, e.Detail)
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
