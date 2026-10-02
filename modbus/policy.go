package modbus

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Policy is the operator-authored rule set: which clients may connect, which
// devices are fronted, which unit ids exist behind each, and which registers
// each of those exposes.
//
// It narrows; it never widens. Everything in classify.go applies first and
// cannot be overridden from a file — a policy that names a write function code
// is rejected at load time rather than honoured. An operator can make this tool
// stricter than read-only, and cannot make it looser.
//
// MULTIPLE TARGETS. Each target gets its own listener, and the listen address
// is what selects it: a client connecting to :5021 reaches line 3's PLC and
// nothing else. That keeps one client connection mapped to exactly one device
// connection, which is what makes response correlation tractable. The
// alternative — one listener with the unit id routing to different backends —
// is a serial-gateway model needing connection pooling and cross-backend
// correlation, and it is deliberately not this.
//
// FILE FORMAT. Parsed with encoding/json, whose DisallowUnknownFields gives the
// property that matters for a security policy: a mistyped key is an error, not
// a silently missing rule. The structs also carry yaml tags, so switching to
// YAML is two lines once gopkg.in/yaml.v3 is available:
//
//	import "gopkg.in/yaml.v3"
//	... in ParsePolicy, replace the json.Decoder block with:
//	    dec := yaml.NewDecoder(bytes.NewReader(data)); dec.KnownFields(true)
//	    if err := dec.Decode(&p); err != nil { ... }
//
// ADDRESSING. Start is a protocol address: the 0-based number that appears on
// the wire, not the 1-based 4xxxx convention. Holding register 40001 in an HMI
// is address 0 here. The policy is written in the same numbers the filter
// compares against, because a translation step between policy and enforcement
// is a place for the two to disagree.
type Policy struct {
	Version  int             `json:"version" yaml:"version"`
	FailMode string          `json:"fail_mode" yaml:"fail_mode"`
	Sources  []string        `json:"sources" yaml:"sources"`
	Session  SessionPolicy   `json:"session" yaml:"session"`
	Targets  []*TargetPolicy `json:"targets" yaml:"targets"`

	sourceNets []*net.IPNet
}

// SessionPolicy bounds what one client may consume. It applies to every target;
// durations are whole seconds and zero means the built-in default.
type SessionPolicy struct {
	MaxOutstanding     int `json:"max_outstanding" yaml:"max_outstanding"`
	PendingTTLSeconds  int `json:"pending_ttl_seconds" yaml:"pending_ttl_seconds"`
	IdleTimeoutSeconds int `json:"idle_timeout_seconds" yaml:"idle_timeout_seconds"`
	MaxConnsPerSource  int `json:"max_conns_per_source" yaml:"max_conns_per_source"`
}

// TargetPolicy is one device, reached through one listener.
type TargetPolicy struct {
	Name    string `json:"name" yaml:"name"`
	Listen  string `json:"listen" yaml:"listen"`
	Address string `json:"address" yaml:"address"`

	// Sources narrows the policy-wide source list for this target alone, which
	// is how a vendor reaches the flow meter without reaching the main PLC. An
	// omitted or empty list inherits the policy's, so a target cannot open
	// itself to everyone merely by mentioning the key.
	Sources []string `json:"sources" yaml:"sources"`

	Units []UnitPolicy `json:"units" yaml:"units"`

	sourceNets []*net.IPNet
	inherited  bool
	units      map[uint8]*UnitPolicy
}

// UnitPolicy is one addressable device behind a target. Behind a serial gateway
// or a backplane bridge the unit id selects different physical hardware at the
// same IP and port, so each one carries its own rules; a unit id absent from
// this list is denied outright.
type UnitPolicy struct {
	ID          uint8  `json:"id" yaml:"id"`
	Description string `json:"description" yaml:"description"`

	// Deny flags keep the zero value equal to the built-in read-only posture,
	// so an omitted field is never accidentally permissive beyond it.
	AllowDiagnostics  bool     `json:"allow_diagnostics" yaml:"allow_diagnostics"`
	DiagSubfunctions  []uint16 `json:"diag_subfunctions" yaml:"diag_subfunctions"`
	DenyDeviceID      bool     `json:"deny_device_id" yaml:"deny_device_id"`
	DenyEventCounter  bool     `json:"deny_event_counter" yaml:"deny_event_counter"`
	MaxDeviceIDObject int      `json:"max_device_id_object" yaml:"max_device_id_object"`

	Rules []AddressRule `json:"rules" yaml:"rules"`
}

// AddressRule permits a set of read function codes over a window of addresses.
// A request must fall entirely inside one rule; a read straddling two adjacent
// rules is refused, because permitting it would mean the policy's windows do
// not mean what they say.
type AddressRule struct {
	FC    []byte `json:"fc" yaml:"fc"`
	Start uint16 `json:"start" yaml:"start"`
	Count uint32 `json:"count" yaml:"count"`

	// Note is where the justification for a rule lives — the thing an auditor
	// asks about and JSON cannot express as a comment. It is carried into
	// validation errors.
	Note string `json:"note" yaml:"note"`
}

// addressableFCs are the function codes an address rule may name: the reads
// that carry a start address and a quantity. Everything else is either gated by
// a flag (diagnostics, device identification, event counter) or refused
// unconditionally by classify.go.
var addressableFCs = map[byte]bool{0x01: true, 0x02: true, 0x03: true, 0x04: true}

// ParsePolicy decodes and validates a policy document.
func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return ParsePolicy(data)
}

func (p *Policy) compile() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: version %d is not supported (expected 1)", p.Version)
	}
	switch p.FailMode {
	case "", "closed", "open":
	default:
		return fmt.Errorf("policy: fail_mode %q must be \"closed\" or \"open\"", p.FailMode)
	}
	if len(p.Targets) == 0 {
		return fmt.Errorf("policy: no targets, so nothing would be reachable")
	}
	if p.Session.MaxOutstanding < 0 || p.Session.PendingTTLSeconds < 0 ||
		p.Session.IdleTimeoutSeconds < 0 || p.Session.MaxConnsPerSource < 0 {
		return fmt.Errorf("policy: session values must not be negative")
	}

	var err error
	if p.sourceNets, err = parseCIDRs("policy", p.Sources); err != nil {
		return err
	}

	names := make(map[string]bool, len(p.Targets))
	listens := make(map[string]string, len(p.Targets))
	for _, t := range p.Targets {
		if t.Name == "" {
			return fmt.Errorf("policy: every target needs a name; it is what the audit log reports")
		}
		if names[t.Name] {
			return fmt.Errorf("policy: target name %q appears more than once", t.Name)
		}
		names[t.Name] = true

		if t.Listen == "" {
			return fmt.Errorf("policy: target %q has no listen address", t.Name)
		}
		if prev, dup := listens[t.Listen]; dup {
			// Two targets on one listener would make the device a client
			// reaches depend on nothing observable.
			return fmt.Errorf("policy: targets %q and %q both listen on %s",
				prev, t.Name, t.Listen)
		}
		listens[t.Listen] = t.Name

		if err := t.compile(p); err != nil {
			return err
		}
	}
	return nil
}

func (t *TargetPolicy) compile(p *Policy) error {
	if t.Address == "" {
		return fmt.Errorf("policy: target %q has no device address", t.Name)
	}
	if t.Address == t.Listen {
		return fmt.Errorf("policy: target %q listens on %s and dials the same address",
			t.Name, t.Listen)
	}
	if len(t.Units) == 0 {
		return fmt.Errorf("policy: target %q lists no units, so nothing would be reachable", t.Name)
	}

	if len(t.Sources) == 0 {
		t.sourceNets, t.inherited = p.sourceNets, true
	} else {
		nets, err := parseCIDRs(fmt.Sprintf("target %q", t.Name), t.Sources)
		if err != nil {
			return err
		}
		t.sourceNets = nets
	}

	t.units = make(map[uint8]*UnitPolicy, len(t.Units))
	for i := range t.Units {
		u := &t.Units[i]
		if _, dup := t.units[u.ID]; dup {
			return fmt.Errorf("policy: target %q lists unit %d more than once", t.Name, u.ID)
		}
		if err := u.validate(t.Name); err != nil {
			return err
		}
		t.units[u.ID] = u
	}
	return nil
}

func parseCIDRs(where string, list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, cidr := range list {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("policy: %s source %q is not a CIDR: %w", where, cidr, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func (u *UnitPolicy) validate(target string) error {
	if u.MaxDeviceIDObject < 0 || u.MaxDeviceIDObject > 0xFF {
		return fmt.Errorf("policy: target %q unit %d max_device_id_object %d is out of range",
			target, u.ID, u.MaxDeviceIDObject)
	}
	if len(u.Rules) == 0 && u.DenyDeviceID && u.DenyEventCounter && !u.AllowDiagnostics {
		return fmt.Errorf("policy: target %q unit %d permits nothing at all; remove it instead",
			target, u.ID)
	}
	for i, r := range u.Rules {
		where := fmt.Sprintf("target %q unit %d rule %d", target, u.ID, i)
		if r.Note != "" {
			where = fmt.Sprintf("%s (%s)", where, r.Note)
		}
		if len(r.FC) == 0 {
			return fmt.Errorf("policy: %s names no function codes", where)
		}
		for _, fc := range r.FC {
			if !addressableFCs[fc] {
				// The important guard: a policy file must not be able to widen
				// the tool beyond what classify.go permits. Naming a write here
				// is a configuration error, not an instruction.
				return fmt.Errorf(
					"policy: %s names function code 0x%02X (%s), which is not an "+
						"addressable read; this tool never forwards it and a policy "+
						"cannot enable it", where, fc, Name(fc))
			}
		}
		if r.Count == 0 {
			return fmt.Errorf("policy: %s has count 0", where)
		}
		if uint32(r.Start)+r.Count > 0x10000 {
			return fmt.Errorf("policy: %s spans %d..%d, past the 16-bit address space",
				where, r.Start, uint32(r.Start)+r.Count)
		}
	}
	for _, sub := range u.DiagSubfunctions {
		if !DefaultLimits().DiagSubFunctions[sub] {
			return fmt.Errorf("policy: target %q unit %d names diagnostic subfunction 0x%04X, "+
				"which is not one of the read-only counter reads", target, u.ID, sub)
		}
	}
	if len(u.DiagSubfunctions) > 0 && !u.AllowDiagnostics {
		return fmt.Errorf("policy: target %q unit %d lists diag_subfunctions but "+
			"allow_diagnostics is false", target, u.ID)
	}
	return nil
}

// FailOpen reports the configured failure mode.
func (p *Policy) FailOpen() bool { return p.FailMode == "open" }

// SessionLimits resolves the configured session bounds, substituting defaults.
func (p *Policy) SessionLimits() (maxOutstanding int, pendingTTL, idle time.Duration, maxConns int) {
	maxOutstanding = p.Session.MaxOutstanding
	if maxOutstanding == 0 {
		maxOutstanding = DefaultMaxOutstanding
	}
	pendingTTL = time.Duration(p.Session.PendingTTLSeconds) * time.Second
	if pendingTTL == 0 {
		pendingTTL = DefaultPendingTTL
	}
	idle = time.Duration(p.Session.IdleTimeoutSeconds) * time.Second
	return maxOutstanding, pendingTTL, idle, p.Session.MaxConnsPerSource
}

// Target returns a target by name.
func (p *Policy) Target(name string) (*TargetPolicy, bool) {
	for _, t := range p.Targets {
		if t.Name == name {
			return t, true
		}
	}
	return nil, false
}

// NewProxy builds the enforcement proxy for one target.
func (p *Policy) NewProxy(t *TargetPolicy) *Proxy {
	maxOutstanding, pendingTTL, idle, maxConns := p.SessionLimits()
	return &Proxy{
		Name:              t.Name,
		Target:            t.Address,
		Rules:             t,
		MaxOutstanding:    maxOutstanding,
		PendingTTL:        pendingTTL,
		IdleTimeout:       idle,
		MaxConnsPerSource: maxConns,
		FailOpen:          p.FailOpen(),
	}
}

// InheritsSources reports whether this target uses the policy-wide source list
// rather than one of its own, which main() states at startup.
func (t *TargetPolicy) InheritsSources() bool { return t.inherited }

// AllowSource reports whether a client address may reach this target. An empty
// list — after inheritance — means any address.
func (t *TargetPolicy) AllowSource(ip net.IP) bool {
	if len(t.sourceNets) == 0 {
		return true
	}
	for _, n := range t.sourceNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Unit returns the policy for a unit id behind this target.
func (t *TargetPolicy) Unit(id uint8) (*UnitPolicy, bool) {
	u, ok := t.units[id]
	return u, ok
}

// Limits derives the decoding posture for this unit.
func (u *UnitPolicy) Limits() Limits {
	lim := Limits{
		AllowDiagnostics: u.AllowDiagnostics,
		DenyDeviceID:     u.DenyDeviceID,
		DenyEventCounter: u.DenyEventCounter,
	}
	if u.MaxDeviceIDObject > 0 {
		lim.MaxDeviceIDObject = byte(u.MaxDeviceIDObject)
	}
	if u.AllowDiagnostics {
		lim.DiagSubFunctions = make(map[uint16]bool, len(u.DiagSubfunctions))
		for _, s := range u.DiagSubfunctions {
			lim.DiagSubFunctions[s] = true
		}
	}
	return lim
}

// Check applies the address rules to a decoded request. Requests without an
// address — diagnostics, device identification, the event counter — are already
// decided by Limits and pass through here.
//
// Two distinct refusals, because they call for different fixes. If no rule names
// the function code at all, widening an address window will not help and saying
// "address not allowed" would send the operator to the wrong line of the policy.
func (u *UnitPolicy) Check(req Request) *Denial {
	r, ok := req.(ReadRequest)
	if !ok {
		return nil
	}
	end := r.End()

	named := false
	for _, rule := range u.Rules {
		if !ruleCoversFC(rule, r.FC) {
			continue
		}
		named = true
		if uint32(r.Start) >= uint32(rule.Start) && end <= uint32(rule.Start)+rule.Count {
			return nil
		}
	}

	if !named {
		return deny(r.FC, ReasonFunctionNotAllowed,
			fmt.Sprintf("no rule for unit %d names %s", u.ID, Name(r.FC)),
			ExIllegalFunction)
	}
	return deny(r.FC, ReasonAddressNotAllowed,
		fmt.Sprintf("unit %d has no rule covering %s over %s", u.ID, Name(r.FC), addrSpan(r.Start, end)),
		ExIllegalDataAddress)
}

// addrSpan reads naturally for the single-register case, which is most of them.
func addrSpan(start uint16, end uint32) string {
	if end == uint32(start)+1 {
		return fmt.Sprintf("address %d", start)
	}
	return fmt.Sprintf("addresses %d..%d", start, end-1)
}

func ruleCoversFC(rule AddressRule, fc byte) bool {
	for _, c := range rule.FC {
		if c == fc {
			return true
		}
	}
	return false
}
