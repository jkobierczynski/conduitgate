package modbus

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Metrics is a minimal Prometheus-text exposition, hand-rolled to keep the
// dependency count at zero.
//
// Label cardinality is bounded by the policy — targets and the fixed set of
// denial reason codes — so there is no risk of the unbounded-label explosion
// that usually argues for a real client library. Nothing here is per-connection
// or per-register.
type Metrics struct {
	mu       sync.Mutex
	counters map[string]map[string]uint64
	gauges   map[string]map[string]int64
}

func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]map[string]uint64),
		gauges:   make(map[string]map[string]int64),
	}
}

var metricHelp = map[string]string{
	"conduitgate_requests_total":    "Requests decided, by target and decision.",
	"conduitgate_responses_total":   "Device responses decided, by target and decision.",
	"conduitgate_denials_total":     "Denials by reason code; the reason is the stable interface.",
	"conduitgate_connections_total": "Connections by admission outcome.",
	"conduitgate_connections_open":  "Connections currently open, by target.",
	"conduitgate_build_info":        "Build identity; always 1, labelled with the version.",
}

var metricType = map[string]string{
	"conduitgate_connections_open": "gauge",
	"conduitgate_build_info":       "gauge",
}

// Inc adds one to a counter. Labels are key, value pairs.
func (m *Metrics) Inc(name string, labels ...string) {
	if m == nil {
		return
	}
	key := labelKey(labels)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counters[name] == nil {
		m.counters[name] = make(map[string]uint64)
	}
	m.counters[name][key]++
}

// Add adjusts a gauge.
func (m *Metrics) Add(name string, delta int64, labels ...string) {
	if m == nil {
		return
	}
	key := labelKey(labels)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gauges[name] == nil {
		m.gauges[name] = make(map[string]int64)
	}
	m.gauges[name][key] += delta
}

// Value reads one series back. For tests and for a health endpoint.
func (m *Metrics) Value(name string, labels ...string) uint64 {
	if m == nil {
		return 0
	}
	key := labelKey(labels)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name][key]
}

// WriteText renders the Prometheus text exposition format. Series are sorted so
// that successive scrapes diff cleanly and tests are deterministic.
func (m *Metrics) WriteText(w io.Writer) error {
	m.mu.Lock()
	type series struct{ name, labels string }
	var names []string
	snapshot := map[string]map[string]string{}

	for name, byLabel := range m.counters {
		names = append(names, name)
		snapshot[name] = map[string]string{}
		for lbl, v := range byLabel {
			snapshot[name][lbl] = fmt.Sprint(v)
		}
	}
	for name, byLabel := range m.gauges {
		if snapshot[name] == nil {
			names = append(names, name)
			snapshot[name] = map[string]string{}
		}
		for lbl, v := range byLabel {
			snapshot[name][lbl] = fmt.Sprint(v)
		}
	}
	m.mu.Unlock()

	sort.Strings(names)
	for _, name := range names {
		if help, ok := metricHelp[name]; ok {
			if _, err := fmt.Fprintf(w, "# HELP %s %s\n", name, help); err != nil {
				return err
			}
		}
		kind := metricType[name]
		if kind == "" {
			kind = "counter"
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", name, kind); err != nil {
			return err
		}

		labels := make([]string, 0, len(snapshot[name]))
		for lbl := range snapshot[name] {
			labels = append(labels, lbl)
		}
		sort.Strings(labels)
		for _, lbl := range labels {
			if _, err := fmt.Fprintf(w, "%s%s %s\n", name, lbl, snapshot[name][lbl]); err != nil {
				return err
			}
		}
	}
	return nil
}

func labelKey(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(labels); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(labels[i])
		b.WriteString(`="`)
		b.WriteString(escapeLabel(labels[i+1]))
		b.WriteString(`"`)
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabel applies the three escapes the exposition format requires.
//
// Written out rather than using strings.NewReplacer, which allocates a replacer
// on every call for a job that is three byte comparisons. Most label values
// need no escaping at all, so the common path returns the input unchanged.
func escapeLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
