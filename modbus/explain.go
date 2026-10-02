package modbus

import "sort"

// Long-form rationale, keyed by reason code.
//
// A denial's Detail says what happened to this PDU, in one clause, because it
// is written once per event into a log that a SIEM will parse and an operator
// will scan. The reasoning behind the rule belongs here instead: printed on
// request by `conduitgate -explain <code>`, not reprinted a thousand times.
//
// That split also makes the reason codes the documented interface they were
// already acting as. A code that appears in a log, in a metric and in this map
// is something an auditor can look up; a paragraph pasted into every line is
// not.
var explanations = map[string]string{
	ReasonWrite: `Modbus write function codes are refused unconditionally. This tool forwards
reads; there is no configuration that enables a write, and a policy file naming
a write function code is rejected when it loads.`,

	ReasonHybrid: `FC 23 (Read/Write Multiple Registers) carries both operations in one PDU, and
the specification performs THE WRITE BEFORE THE READ. The response contains only
the read data, so a permitted FC 23 returns an ordinary-looking read response
while the write happens silently — the operator gets no signal at all.

The write quantity field is constrained to 1-121, so no legal FC 23 omits its
write half. There is no read-only subset to permit, and no address range that
makes it safe. It is refused outright.

A filter written as "does this PDU read registers?" passes FC 23. That is the
single most common way a read-only Modbus filter turns out not to be one.`,

	ReasonUMAS: `Function code 0x5A (90) is Schneider Electric's UMAS engineering protocol.

The trap is where the specification files it: 0x5A sits in the RESERVED list, not
in the user-defined ranges (65-72, 100-110). A filter that default-denies the
user-defined ranges while treating "reserved" as unused passes the entire
Modicon engineering protocol.

Inside FC 0x5A the structure is [0x5A][session key][UMAS function code][data]:

    UMAS 0x21  pu_WriteMemoryBlock   arbitrary memory write, no reservation needed
    UMAS 0x40  ex_StartTask          start the PLC, absent an application password
    UMAS 0x41  ex_StopTask           STOP the PLC, absent an application password
    UMAS 0x30/31/32                  program download

This is why the posture is default-deny rather than a ruleset: nobody writes a
signature for a function code they have not enumerated. Denial happens at
classification, so the UMAS layer is never parsed — a sub-protocol parser this
tool does not contain is one that cannot contain a bug.`,

	ReasonProgramTransfer: `FC 20 (Read File Record) is nominally a read, but it reads "extended memory". On
Modicon-family devices file records back configuration and program storage, so
this is a program upload rather than a tag read. FC 21 is the matching download
path and is a write.`,

	ReasonDestructiveRead: `FC 24 (Read FIFO Queue) is specified as non-destructive, but some vendor
implementations pop the queue, making the read a state change. Refused because
the behaviour is per-device and cannot be established from the wire.`,

	ReasonInfoDisclosure: `Refused as information disclosure rather than as a state change. These function
codes are safe for the process but reveal device identity, event history or
status that helps an attacker fingerprint the target. Enable them per unit if a
client genuinely needs them.`,

	ReasonVendorDefined: `The specification reserves 65-72 (0x41-0x48) and 100-110 (0x64-0x6E) for
vendor-assigned function codes whose contents are undocumented. Siemens, WAGO,
Hitachi and others use them. Since the payload cannot be validated, the code
cannot be forwarded.`,

	ReasonReserved: `A reserved function code. Reserved does not mean unused: 0x5A is reserved and
carries Schneider's entire engineering protocol. Anything reserved fails closed.`,

	ReasonDiagDisabled: `FC 8 (Diagnostics) is disabled by default. Its readable subfunctions carry only
counter statistics, while several others change state:

    0x0001  Restart Communications Option   reinitializes the comms stack
    0x0003  Change ASCII Input Delimiter    persistent configuration change
    0x0004  Force Listen Only Mode          isolates the device, returns NO response
    0x000A  Clear Counters                  anti-forensic
    0x0000  Return Query Data               echoes arbitrary bytes: a covert channel

0x0004 in particular is a single-packet denial of service. Enable FC 8 per unit
with an explicit subfunction allowlist only if the counter reads are genuinely
needed.`,

	ReasonDiagSubFunction: `The subfunction is not in this unit's allowlist. Only the counter reads
(0x0002, 0x000B-0x0012) can be allowlisted at all; the state-changing
subfunctions are refused whatever the policy says.`,

	ReasonMEINotAllowed: `FC 43 is decided by its MEI type byte, never by the function code alone.

    MEI 14 (0x0E)  Read Device Identification   genuinely read-only
    MEI 13 (0x0D)  CANopen General Reference    a READ AND WRITE path into the
                                                object dictionary — a tunnel
                                                straight through the filter

All other MEI values are reserved and fail closed. Read device id code 04
(individual access) is also refused, since it is how a client reaches one
specific object including a private one.`,

	ReasonMEIObjectPrivate: `Device identification objects 0x00-0x06 are the standard ones. The range
0x80-0xFF is product-dependent private space and on some devices exposes
credentials. It is refused in both directions: on the request, and on a response
where the device returned an object the client never asked for.`,

	ReasonMalformed: `The PDU does not match the shape its function code requires. Trailing bytes
beyond a fixed-length request are the classic place to hide content that a
lenient device might act on, so any length disagreement is refused rather than
truncated.`,

	ReasonQuantity: `The requested quantity is outside the specification's range (1-2000 coils,
1-125 registers). A device may be stricter; none may be looser.`,

	ReasonAddressOverflow: `The request's start plus quantity runs past the 16-bit address space. A device
that wraps would serve a different range than the policy checked, so this is a
policy-integrity refusal rather than a courtesy.`,

	ReasonTooManyOutstanding: `The connection already holds the configured maximum of in-flight requests.
Bounding this stops a client making the proxy hold correlation state on its
behalf. Raise session.max_outstanding if a legitimate client pipelines harder.`,

	ReasonSourceNotAllowed: `The client's address is not in the policy's source list. Checked at accept,
before any bytes are read, so a client that is not listed never gets to send a
PDU. An empty source list permits any address.`,

	ReasonTooManyConns: `The source address already holds its allowance of connections
(session.max_conns_per_source). Refused at accept rather than queued.`,

	ReasonUnitNotAllowed: `The unit id is not listed for this target. Behind a serial gateway or a
backplane bridge the unit id selects different physical hardware at the same IP
and port, so an unlisted unit is not a device this proxy fronts. Add it to the
policy's target.units if it should be reachable.`,

	ReasonFunctionNotAllowed: `No rule for this unit names this function code. This is distinct from
policy.address_not_allowed: widening an existing rule's address window will not
help, because no window applies to this function code at all. Add the function
code to a rule's fc list, or add a rule for it.`,

	ReasonAddressNotAllowed: `A rule names this function code, but no single rule covers the whole requested
range. Note that adjacent rules do not merge — a read straddling 0..9 and 10..19
is refused even though both windows are permitted, because allowing it would
mean the windows do not mean what they say. Write the union as one rule if that
is what was intended.`,

	ReasonEventCounterDisabled: `FC 11 (Get Comm Event Counter) is disabled for this unit by policy. It is
read-only and permitted by default; deny_event_counter turns it off.`,

	ReasonRespUnsolicited: `The device sent a response with no matching outstanding request. It cannot be
relayed, because the client has no transaction to attach it to, and it is not
attributable enough to answer. It is dropped and recorded.

Correlation is keyed on (transaction id, unit id): a reply carrying the wrong
unit id is not an answer to this request.`,

	ReasonRespMismatch: `The response does not correspond to the request that produced it — a different
function code, a subfunction that does not echo, or an exception for a function
the client never sent. Relaying it would let a device answer a question nobody
asked.`,

	ReasonRespByteCount: `The response's declared byte count disagrees either with the actual PDU length or
with the quantity the request asked for.

This is the response-side twin of the MBAP length desync: where a device and a
client resolve the disagreement differently, they see different data. The
request is not optional context here — "did this device return the number of
registers that were requested" cannot be answered from the response alone.`,

	ReasonRespMalformed: `The response PDU does not match the shape its function code requires — a
truncated header, an object whose declared length runs past the PDU, or trailing
bytes after the declared content.`,

	ReasonRespObject: `The device returned a device-identification object outside the permitted range,
which the client did not ask for. Refused on the way back as well as on the way
out; see mei.object_private.`,

	ReasonRespExceptionCode: `The device returned an exception code the specification does not define. Passing
the byte through would let it smuggle a value to a lenient client, so the
response is refused and the client is told the device failed.`,
}

// Explain returns the long-form rationale for a reason code.
func Explain(reason string) (string, bool) {
	s, ok := explanations[reason]
	return s, ok
}

// ReasonCodes lists every documented reason code, sorted.
func ReasonCodes() []string {
	out := make([]string, 0, len(explanations))
	for k := range explanations {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
