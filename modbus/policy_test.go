package modbus

import (
	"net"
	"strings"
	"testing"
)

const minimalPolicy = `{
  "version": 1,
  "targets": [
    {
      "name": "line3",
      "listen": "127.0.0.1:5502",
      "address": "127.0.0.1:5020",
      "units": [
        {"id": 1, "rules": [{"fc": [3], "start": 0, "count": 20, "note": "process values"}]}
      ]
    }
  ]
}`

func mustPolicy(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	return p
}

func mustUnit(t *testing.T, doc, target string, id uint8) *UnitPolicy {
	t.Helper()
	tp, ok := mustPolicy(t, doc).Target(target)
	if !ok {
		t.Fatalf("target %q missing", target)
	}
	u, ok := tp.Unit(id)
	if !ok {
		t.Fatalf("unit %d missing from %q", id, target)
	}
	return u
}

func rejects(t *testing.T, doc, wantSubstring string) {
	t.Helper()
	_, err := ParsePolicy([]byte(doc))
	if err == nil {
		t.Fatalf("policy accepted, want rejection mentioning %q", wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("error %q does not mention %q", err, wantSubstring)
	}
}

func TestPolicyLoads(t *testing.T) {
	p := mustPolicy(t, minimalPolicy)
	if len(p.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(p.Targets))
	}
	tp, ok := p.Target("line3")
	if !ok {
		t.Fatal("target line3 missing")
	}
	if tp.Address != "127.0.0.1:5020" || tp.Listen != "127.0.0.1:5502" {
		t.Errorf("addresses = %q -> %q", tp.Listen, tp.Address)
	}
	if _, ok := tp.Unit(1); !ok {
		t.Error("unit 1 missing")
	}
	if _, ok := tp.Unit(2); ok {
		t.Error("unit 2 should not exist")
	}
	if _, ok := p.Target("nope"); ok {
		t.Error("unknown target resolved")
	}
}

// Each target gets its own listener and its own scope. Two targets fronting the
// same device must not share rules.
func TestTargetsAreIndependentlyScoped(t *testing.T) {
	doc := `{"version":1,"targets":[
	  {"name":"narrow","listen":"127.0.0.1:5520","address":"127.0.0.1:5020",
	   "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":20}]}]},
	  {"name":"wide","listen":"127.0.0.1:5521","address":"127.0.0.1:5020",
	   "units":[{"id":2,"rules":[{"fc":[3],"start":40,"count":20}]}]}]}`
	p := mustPolicy(t, doc)

	narrow, _ := p.Target("narrow")
	wide, _ := p.Target("wide")

	if _, ok := narrow.Unit(2); ok {
		t.Error("the narrow target sees the wide target's unit")
	}
	if _, ok := wide.Unit(1); ok {
		t.Error("the wide target sees the narrow target's unit")
	}

	n1, _ := narrow.Unit(1)
	w2, _ := wide.Unit(2)
	if d := n1.Check(ReadRequest{FC: 0x03, Start: 40, Quantity: 1}); d == nil {
		t.Error("the narrow target permitted the wide target's window")
	}
	if d := w2.Check(ReadRequest{FC: 0x03, Start: 0, Quantity: 1}); d == nil {
		t.Error("the wide target permitted the narrow target's window")
	}
}

func TestTargetValidation(t *testing.T) {
	rejects(t, `{"version":1,"targets":[]}`, "no targets")

	noName := `{"version":1,"targets":[{"listen":"a:1","address":"b:2",
	  "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, noName, "needs a name")

	dupName := `{"version":1,"targets":[
	  {"name":"x","listen":"a:1","address":"b:2","units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]},
	  {"name":"x","listen":"a:2","address":"b:2","units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, dupName, "appears more than once")

	// Two targets on one listener would make the device a client reaches
	// depend on nothing observable.
	dupListen := `{"version":1,"targets":[
	  {"name":"x","listen":"a:1","address":"b:2","units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]},
	  {"name":"y","listen":"a:1","address":"b:3","units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, dupListen, "both listen on")

	noListen := `{"version":1,"targets":[{"name":"x","address":"b:2",
	  "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, noListen, "no listen address")

	noAddr := `{"version":1,"targets":[{"name":"x","listen":"a:1",
	  "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, noAddr, "no device address")

	// Listening on the device's own address would be a loop.
	loop := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"a:1",
	  "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, loop, "dials the same address")

	noUnits := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[]}]}`
	rejects(t, noUnits, "lists no units")
}

// The property that matters most: a policy file narrows, never widens. An
// operator must not be able to turn this into a read/write proxy by editing
// configuration.
func TestPolicyCannotEnableWrites(t *testing.T) {
	for _, fc := range []int{0x05, 0x06, 0x10, 0x17, 0x5A} {
		doc := strings.Replace(minimalPolicy, `"fc": [3]`, `"fc": [`+itoa(fc)+`]`, 1)
		rejects(t, doc, "cannot enable it")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A mistyped key must be an error, not a silently missing rule.
func TestPolicyRejectsUnknownKeys(t *testing.T) {
	rejects(t, strings.Replace(minimalPolicy, `"start": 0`, `"strat": 0`, 1), "strat")
	rejects(t, strings.Replace(minimalPolicy, `"units"`, `"unit"`, 1), "unit")
	rejects(t, strings.Replace(minimalPolicy, `"targets"`, `"target"`, 1), "target")
}

func TestUnitValidation(t *testing.T) {
	rejects(t, strings.Replace(minimalPolicy, `"version": 1`, `"version": 2`, 1), "version 2")
	rejects(t, strings.Replace(minimalPolicy, `"count": 20`, `"count": 0`, 1), "count 0")
	rejects(t, strings.Replace(minimalPolicy, `"start": 0, "count": 20`,
		`"start": 65530, "count": 100`, 1), "past the 16-bit address space")
	rejects(t, strings.Replace(minimalPolicy, `"fc": [3]`, `"fc": []`, 1), "no function codes")

	// The note and the target name are carried into the error so the operator
	// knows which line of which target to look at.
	rejects(t, strings.Replace(minimalPolicy, `"count": 20`, `"count": 0`, 1), "process values")
	rejects(t, strings.Replace(minimalPolicy, `"count": 20`, `"count": 0`, 1), `target "line3"`)

	dupUnit := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[
	  {"id":1,"rules":[{"fc":[3],"start":0,"count":1}]},
	  {"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, dupUnit, "more than once")

	empty := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[
	  {"id":1,"deny_device_id":true,"deny_event_counter":true}]}]}`
	rejects(t, empty, "permits nothing")

	badDiag := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[
	  {"id":1,"allow_diagnostics":true,"diag_subfunctions":[4],
	   "rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, badDiag, "not one of the read-only counter reads")

	orphan := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[
	  {"id":1,"diag_subfunctions":[11],"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	rejects(t, orphan, "allow_diagnostics is false")

	rejects(t, strings.Replace(minimalPolicy, `"version": 1`,
		`"fail_mode": "maybe", "version": 1`, 1), "fail_mode")
}

func TestPolicySourceACL(t *testing.T) {
	doc := strings.Replace(minimalPolicy, `"version": 1`,
		`"version": 1, "sources": ["10.40.0.0/24", "192.168.10.25/32"]`, 1)
	tp, _ := mustPolicy(t, doc).Target("line3")

	if !tp.InheritsSources() {
		t.Error("a target with no list of its own should inherit")
	}
	for _, ip := range []string{"10.40.0.1", "10.40.0.255", "192.168.10.25"} {
		if !tp.AllowSource(net.ParseIP(ip)) {
			t.Errorf("%s should be allowed", ip)
		}
	}
	for _, ip := range []string{"10.41.0.1", "192.168.10.26", "127.0.0.1"} {
		if tp.AllowSource(net.ParseIP(ip)) {
			t.Errorf("%s should be refused", ip)
		}
	}

	// No sources anywhere means any address, which main() warns about.
	bare, _ := mustPolicy(t, minimalPolicy).Target("line3")
	if !bare.AllowSource(net.ParseIP("8.8.8.8")) {
		t.Error("an empty source list should permit any address")
	}

	rejects(t, strings.Replace(minimalPolicy, `"version": 1`,
		`"version": 1, "sources": ["not-a-cidr"]`, 1), "is not a CIDR")
}

// A target may narrow the policy-wide list for itself: the vendor reaches the
// flow meter without reaching the main PLC.
func TestPerTargetSourceOverride(t *testing.T) {
	doc := `{"version":1,"sources":["10.0.0.0/8"],"targets":[
	  {"name":"open","listen":"a:1","address":"b:2",
	   "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]},
	  {"name":"narrow","listen":"a:2","address":"b:3","sources":["10.1.2.3/32"],
	   "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	p := mustPolicy(t, doc)
	open, _ := p.Target("open")
	narrow, _ := p.Target("narrow")

	if !open.AllowSource(net.ParseIP("10.9.9.9")) {
		t.Error("the inheriting target should accept the policy-wide range")
	}
	if narrow.AllowSource(net.ParseIP("10.9.9.9")) {
		t.Error("the overriding target should not accept the wider range")
	}
	if !narrow.AllowSource(net.ParseIP("10.1.2.3")) {
		t.Error("the overriding target should accept its own address")
	}
	if narrow.InheritsSources() {
		t.Error("a target with its own list should not report inheritance")
	}

	rejects(t, strings.Replace(doc, `"sources":["10.1.2.3/32"]`, `"sources":["bad"]`, 1),
		`target "narrow"`)
}

func TestAddressRuleEnforcement(t *testing.T) {
	u := mustUnit(t, minimalPolicy, "line3", 1)

	inside := []ReadRequest{
		{FC: 0x03, Start: 0, Quantity: 1},
		{FC: 0x03, Start: 19, Quantity: 1},
		{FC: 0x03, Start: 0, Quantity: 20},
		{FC: 0x03, Start: 10, Quantity: 10},
	}
	for _, r := range inside {
		if d := u.Check(r); d != nil {
			t.Errorf("%d..%d should be permitted: %v", r.Start, r.End()-1, d)
		}
	}

	// The rule names FC 3, so these are address failures.
	for _, r := range []ReadRequest{
		{FC: 0x03, Start: 20, Quantity: 1},
		{FC: 0x03, Start: 19, Quantity: 2},
		{FC: 0x03, Start: 100, Quantity: 1},
	} {
		d := u.Check(r)
		if d == nil {
			t.Errorf("fc 0x%02X %d..%d should be refused", r.FC, r.Start, r.End()-1)
			continue
		}
		if d.Reason != ReasonAddressNotAllowed {
			t.Errorf("reason = %q, want %q", d.Reason, ReasonAddressNotAllowed)
		}
		if d.Exception != ExIllegalDataAddress {
			t.Errorf("exception = 0x%02X, want 0x02", d.Exception)
		}
	}

	// No rule names FC 4 or FC 1 at all, which is a different fault: widening
	// an address window would not help, so it must not be reported as one.
	for _, r := range []ReadRequest{
		{FC: 0x04, Start: 0, Quantity: 1},
		{FC: 0x01, Start: 0, Quantity: 1},
	} {
		d := u.Check(r)
		if d == nil {
			t.Errorf("fc 0x%02X should be refused", r.FC)
			continue
		}
		if d.Reason != ReasonFunctionNotAllowed {
			t.Errorf("fc 0x%02X reason = %q, want %q", r.FC, d.Reason, ReasonFunctionNotAllowed)
		}
		if d.Exception != ExIllegalFunction {
			t.Errorf("fc 0x%02X exception = 0x%02X, want 0x01", r.FC, d.Exception)
		}
	}
}

// A single-register refusal should not read "addresses 20..20".
func TestSingleAddressWording(t *testing.T) {
	u := mustUnit(t, minimalPolicy, "line3", 1)
	d := u.Check(ReadRequest{FC: 0x03, Start: 20, Quantity: 1})
	if !strings.Contains(d.Detail, "address 20") || strings.Contains(d.Detail, "20..20") {
		t.Errorf("detail = %q", d.Detail)
	}
	d = u.Check(ReadRequest{FC: 0x03, Start: 30, Quantity: 3})
	if !strings.Contains(d.Detail, "addresses 30..32") {
		t.Errorf("detail = %q", d.Detail)
	}
}

// Every reason code a denial can carry must have a documented explanation.
func TestEveryReasonIsExplained(t *testing.T) {
	for _, code := range ReasonCodes() {
		text, ok := Explain(code)
		if !ok || len(text) < 40 {
			t.Errorf("%s has no usable explanation", code)
		}
	}
	for _, code := range []string{
		ReasonWrite, ReasonHybrid, ReasonUMAS, ReasonFunctionNotAllowed,
		ReasonAddressNotAllowed, ReasonUnitNotAllowed, ReasonSourceNotAllowed,
		ReasonRespByteCount, ReasonRespUnsolicited, ReasonEventCounterDisabled,
	} {
		if _, ok := Explain(code); !ok {
			t.Errorf("%s is undocumented", code)
		}
	}
}

// Details are written once per event into a log a SIEM will parse. The long
// form belongs behind -explain.
func TestDenialDetailsStayShort(t *testing.T) {
	lim := DefaultLimits()
	for _, pdu := range [][]byte{
		{0x5A, 0x00, 0x41, 0x00},
		{0x17, 0, 3, 0, 6, 0, 14, 0, 3, 6, 0, 0, 0, 0, 0, 0},
		{0x06, 0, 10, 0xDE, 0xAD},
		{0x08, 0x00, 0x0B, 0x00, 0x00},
		{0x2B, 0x0D, 0x00, 0x00},
		{0x14, 0x0E, 0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02},
	} {
		_, d := DecodeRequest(pdu, lim)
		if d == nil {
			t.Fatalf("pdu % x was permitted", pdu)
		}
		if len(d.Detail) > 160 {
			t.Errorf("fc 0x%02X detail is %d chars, too long for a log line: %q",
				pdu[0], len(d.Detail), d.Detail)
		}
	}
}

// A read that straddles two adjacent rules is refused. Permitting it would mean
// the windows do not mean what they say, and an operator who wanted the union
// can write it as one rule.
func TestAdjacentRulesDoNotMerge(t *testing.T) {
	doc := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[
	  {"id":1,"rules":[
	    {"fc":[3],"start":0,"count":10},
	    {"fc":[3],"start":10,"count":10}]}]}]}`
	u := mustUnit(t, doc, "x", 1)

	if d := u.Check(ReadRequest{FC: 0x03, Start: 0, Quantity: 10}); d != nil {
		t.Errorf("first window should be permitted: %v", d)
	}
	if d := u.Check(ReadRequest{FC: 0x03, Start: 10, Quantity: 10}); d != nil {
		t.Errorf("second window should be permitted: %v", d)
	}
	if d := u.Check(ReadRequest{FC: 0x03, Start: 5, Quantity: 10}); d == nil {
		t.Error("a read straddling both windows should be refused")
	}
}

// Requests with no address are decided by Limits, not by address rules.
func TestNonAddressRequestsPassTheRuleCheck(t *testing.T) {
	u := mustUnit(t, minimalPolicy, "line3", 1)
	if d := u.Check(EventCounterRequest{}); d != nil {
		t.Errorf("event counter should not be address-checked: %v", d)
	}
	if d := u.Check(DeviceIDRequest{ReadDevIDCode: 1}); d != nil {
		t.Errorf("device id should not be address-checked: %v", d)
	}
}

func TestUnitLimitsDerivation(t *testing.T) {
	doc := `{"version":1,"targets":[{"name":"x","listen":"a:1","address":"b:2","units":[
	  {"id":1,"allow_diagnostics":true,"diag_subfunctions":[11,12],
	   "deny_device_id":true,"deny_event_counter":true,"max_device_id_object":3,
	   "rules":[{"fc":[3],"start":0,"count":1}]}]}]}`
	lim := mustUnit(t, doc, "x", 1).Limits()

	if !lim.AllowDiagnostics || !lim.DenyDeviceID || !lim.DenyEventCounter {
		t.Errorf("flags not carried: %+v", lim)
	}
	if lim.MaxDeviceIDObject != 3 {
		t.Errorf("max device id object = %d, want 3", lim.MaxDeviceIDObject)
	}
	if !lim.DiagSubFunctions[11] || !lim.DiagSubFunctions[12] || lim.DiagSubFunctions[13] {
		t.Errorf("subfunction allowlist = %v", lim.DiagSubFunctions)
	}

	// And those limits actually bite at the decode layer.
	if _, d := DecodeRequest([]byte{0x0B}, lim); d == nil || d.Reason != ReasonEventCounterDisabled {
		t.Errorf("event counter should be refused for this unit, got %v", d)
	}
	if _, d := DecodeRequest([]byte{0x2B, 0x0E, 0x01, 0x00}, lim); d == nil {
		t.Error("device id should be refused for this unit")
	}
	if _, d := DecodeRequest([]byte{0x08, 0x00, 0x0B, 0x00, 0x00}, lim); d != nil {
		t.Errorf("subfunction 11 should be permitted for this unit: %v", d)
	}
}

func TestSessionDefaults(t *testing.T) {
	p := mustPolicy(t, minimalPolicy)
	maxOut, ttl, idle, conns := p.SessionLimits()
	if maxOut != DefaultMaxOutstanding {
		t.Errorf("max outstanding = %d, want the default", maxOut)
	}
	if ttl != DefaultPendingTTL {
		t.Errorf("pending ttl = %v, want the default", ttl)
	}
	if idle != 0 || conns != 0 {
		t.Errorf("unset values should stay zero, got idle=%v conns=%d", idle, conns)
	}
}

// NewProxy must carry the policy's settings onto the proxy, since nothing else
// reads them at run time.
func TestNewProxyCarriesSettings(t *testing.T) {
	doc := strings.Replace(minimalPolicy, `"version": 1`,
		`"version": 1, "fail_mode": "open", "session": {"max_outstanding": 4, `+
			`"pending_ttl_seconds": 7, "idle_timeout_seconds": 11, "max_conns_per_source": 2}`, 1)
	p := mustPolicy(t, doc)
	tp, _ := p.Target("line3")
	proxy := p.NewProxy(tp)

	if proxy.Name != "line3" || proxy.Target != "127.0.0.1:5020" || proxy.Rules() != tp {
		t.Errorf("proxy not bound to its target: %+v", proxy)
	}
	if proxy.MaxOutstanding != 4 || proxy.PendingTTL.Seconds() != 7 ||
		proxy.IdleTimeout.Seconds() != 11 || proxy.MaxConnsPerSource != 2 {
		t.Errorf("session settings not carried: %+v", proxy)
	}
	if !proxy.FailOpen {
		t.Error("fail_mode open not carried")
	}
}

func TestExamplePolicyIsValid(t *testing.T) {
	p, err := LoadPolicy("../policy/example.json")
	if err != nil {
		t.Fatalf("the shipped example does not load: %v", err)
	}
	if len(p.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(p.Targets))
	}

	line3, ok := p.Target("line3-plc")
	if !ok {
		t.Fatal("line3-plc missing from the example")
	}
	u7, ok := line3.Unit(7)
	if !ok {
		t.Fatal("unit 7 missing from the example")
	}
	if d := u7.Check(ReadRequest{FC: 0x03, Start: 200, Quantity: 1}); d == nil {
		t.Error("the example's calibration block should be unreachable")
	}
	if d := u7.Check(ReadRequest{FC: 0x03, Start: 100, Quantity: 20}); d != nil {
		t.Errorf("the example's totaliser block should be readable: %v", d)
	}

	hmi, ok := p.Target("packaging-hmi")
	if !ok {
		t.Fatal("packaging-hmi missing from the example")
	}
	if hmi.InheritsSources() {
		t.Error("packaging-hmi declares its own source list")
	}
	if hmi.AllowSource(net.ParseIP("10.40.0.1")) {
		t.Error("packaging-hmi should not accept the policy-wide range")
	}
	if !hmi.AllowSource(net.ParseIP("10.40.0.55")) {
		t.Error("packaging-hmi should accept its own vendor address")
	}
}

func TestIntegrationPolicyIsValid(t *testing.T) {
	p, err := LoadPolicy("../test/policy-test.json")
	if err != nil {
		t.Fatalf("the integration test policy does not load: %v", err)
	}
	if len(p.Targets) != 2 {
		t.Errorf("targets = %d, want 2", len(p.Targets))
	}
}
