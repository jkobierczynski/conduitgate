package modbus

import (
	"strings"
	"testing"
)

func TestMetricsCountersAndGauges(t *testing.T) {
	m := NewMetrics()
	m.Inc("conduitgate_requests_total", "target", "line3", "decision", "allow")
	m.Inc("conduitgate_requests_total", "target", "line3", "decision", "allow")
	m.Inc("conduitgate_requests_total", "target", "line3", "decision", "deny")

	if got := m.Value("conduitgate_requests_total", "target", "line3", "decision", "allow"); got != 2 {
		t.Errorf("allow = %d, want 2", got)
	}
	if got := m.Value("conduitgate_requests_total", "target", "line3", "decision", "deny"); got != 1 {
		t.Errorf("deny = %d, want 1", got)
	}
	if got := m.Value("conduitgate_requests_total", "target", "other", "decision", "allow"); got != 0 {
		t.Errorf("an unseen label set should read zero, got %d", got)
	}

	m.Add("conduitgate_connections_open", 1, "target", "line3")
	m.Add("conduitgate_connections_open", 1, "target", "line3")
	m.Add("conduitgate_connections_open", -1, "target", "line3")

	var b strings.Builder
	if err := m.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`# TYPE conduitgate_requests_total counter`,
		`conduitgate_requests_total{target="line3",decision="allow"} 2`,
		`conduitgate_requests_total{target="line3",decision="deny"} 1`,
		`# TYPE conduitgate_connections_open gauge`,
		`conduitgate_connections_open{target="line3"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q:\n%s", want, out)
		}
	}
}

// Successive scrapes must diff cleanly, so series order cannot depend on map
// iteration.
func TestMetricsExpositionIsDeterministic(t *testing.T) {
	m := NewMetrics()
	for _, target := range []string{"zulu", "alpha", "mike"} {
		for _, reason := range []string{ReasonWrite, ReasonUMAS, ReasonAddressNotAllowed} {
			m.Inc("conduitgate_denials_total", "target", target, "reason", reason)
		}
	}
	var first strings.Builder
	m.WriteText(&first)
	for i := 0; i < 20; i++ {
		var next strings.Builder
		m.WriteText(&next)
		if next.String() != first.String() {
			t.Fatal("exposition order varies between scrapes")
		}
	}
}

func TestMetricsEscapesLabels(t *testing.T) {
	m := NewMetrics()
	m.Inc("conduitgate_denials_total", "target", `odd"name\here`, "reason", "x")
	var b strings.Builder
	m.WriteText(&b)
	if !strings.Contains(b.String(), `target="odd\"name\\here"`) {
		t.Errorf("label not escaped:\n%s", b.String())
	}
}

// Metrics are optional, so every call site must tolerate a nil receiver rather
// than guarding at each one.
func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.Inc("x", "a", "b")
	m.Add("y", 1, "a", "b")
	if got := m.Value("x", "a", "b"); got != 0 {
		t.Errorf("nil metrics returned %d", got)
	}
}

// The proxy must count through the same path that emits events, so that a
// denial can never be reported without being counted.
func TestProxyCountsDecisions(t *testing.T) {
	dev := newFakeDevice(t, nil)
	m := NewMetrics()
	addr, _ := startProxy(t, dev.addr(), func(p *Proxy) { p.Metrics = m })

	c := dial(t, addr)
	send(t, c, 1, 1, readHolding(0, 1))
	if _, err := recv(c); err != nil {
		t.Fatal(err)
	}
	send(t, c, 2, 1, []byte{0x06, 0x00, 0x0A, 0xDE, 0xAD})
	if _, err := recv(c); err != nil {
		t.Fatal(err)
	}

	if got := m.Value("conduitgate_requests_total", "target", "test", "decision", "allow"); got != 1 {
		t.Errorf("allowed requests = %d, want 1", got)
	}
	if got := m.Value("conduitgate_requests_total", "target", "test", "decision", "deny"); got != 1 {
		t.Errorf("denied requests = %d, want 1", got)
	}
	if got := m.Value("conduitgate_denials_total",
		"target", "test", "direction", DirRequest, "reason", ReasonWrite); got != 1 {
		t.Errorf("write denials = %d, want 1", got)
	}
	if got := m.Value("conduitgate_responses_total", "target", "test", "decision", "allow"); got != 1 {
		t.Errorf("allowed responses = %d, want 1", got)
	}
	if got := m.Value("conduitgate_connections_total",
		"target", "test", "outcome", "accepted"); got != 1 {
		t.Errorf("accepted connections = %d, want 1", got)
	}
}

// Rules swap under a live connection: a tightened policy must take effect on
// the next request, not wait for a long-lived session to reconnect.
func TestProxyRulesSwapAppliesToLiveConnections(t *testing.T) {
	dev := newFakeDevice(t, nil)
	wide := `{"version":1,"targets":[{"name":"t","listen":"127.0.0.1:1","address":"127.0.0.1:2",
	  "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":100}]}]}]}`
	narrow := `{"version":1,"targets":[{"name":"t","listen":"127.0.0.1:1","address":"127.0.0.1:2",
	  "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":10}]}]}]}`

	wideT, _ := mustPolicy(t, wide).Target("t")
	narrowT, _ := mustPolicy(t, narrow).Target("t")

	var proxy *Proxy
	addr, _ := startProxy(t, dev.addr(), func(p *Proxy) {
		p.SetRules(wideT)
		proxy = p
	})

	c := dial(t, addr)
	send(t, c, 1, 1, readHolding(50, 1))
	got, err := recv(c)
	if err != nil || got.PDU[0] != 0x03 {
		t.Fatalf("read inside the wide window refused: %+v %v", got, err)
	}

	proxy.SetRules(narrowT)

	send(t, c, 2, 1, readHolding(50, 1))
	got, err = recv(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.PDU[0] != 0x83 || got.PDU[1] != ExIllegalDataAddress {
		t.Errorf("after tightening, the same read gave % x; it should be refused", got.PDU)
	}

	// And the narrowed window still serves what it permits.
	send(t, c, 3, 1, readHolding(0, 1))
	if got, err = recv(c); err != nil || got.PDU[0] != 0x03 {
		t.Errorf("permitted read refused after reload: %+v %v", got, err)
	}
}
