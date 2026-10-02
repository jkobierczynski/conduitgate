package modbus

import "fmt"

// Modbus exception codes returned to a denied client. A denial must produce a
// well-formed protocol error rather than a silent drop: a dropped packet makes
// the client hang and retransmit, which an engineer debugs as a network fault
// and an operator experiences as an outage of unknown cause.
const (
	ExIllegalFunction    = 0x01
	ExIllegalDataAddress = 0x02
	ExIllegalDataValue   = 0x03
)

// Stable reason codes. These are emitted to the audit log and to metrics, so
// they are part of the tool's interface and must not be reworded casually.
const (
	ReasonWrite            = "fc.write"
	ReasonHybrid           = "fc.hybrid_write_before_read"
	ReasonProgramTransfer  = "fc.program_transfer"
	ReasonDestructiveRead  = "fc.destructive_read"
	ReasonInfoDisclosure   = "fc.info_disclosure"
	ReasonVendorDefined    = "fc.vendor_defined"
	ReasonReserved         = "fc.reserved"
	ReasonUMAS             = "fc.umas"
	ReasonUnknown          = "fc.unknown"
	ReasonDiagDisabled     = "fc.diagnostics_disabled"
	ReasonDiagSubFunction  = "diag.subfunction_not_allowed"
	ReasonMEINotAllowed    = "mei.not_allowed"
	ReasonMEIObjectPrivate = "mei.object_private"
	ReasonMalformed        = "pdu.malformed"
	ReasonQuantity         = "pdu.quantity_out_of_range"
	ReasonAddressOverflow  = "pdu.address_overflow"

	// Policy-layer reasons. These are refusals by the operator's rule set
	// rather than by the protocol classification above.
	ReasonSourceNotAllowed     = "policy.source_not_allowed"
	ReasonUnitNotAllowed       = "policy.unit_not_allowed"
	ReasonAddressNotAllowed    = "policy.address_not_allowed"
	ReasonFunctionNotAllowed   = "policy.function_not_allowed"
	ReasonTooManyConns         = "policy.too_many_connections"
	ReasonEventCounterDisabled = "fc.event_counter_disabled"
)

// Denial is a refusal to forward, carrying everything the audit trail needs and
// the exception code to hand back to the client.
type Denial struct {
	FC        byte
	Reason    string
	Detail    string
	Exception byte
}

func (d *Denial) Error() string {
	return fmt.Sprintf("modbus: denied fc=0x%02X reason=%s: %s", d.FC, d.Reason, d.Detail)
}

func deny(fc byte, reason, detail string, ex byte) *Denial {
	return &Denial{FC: fc, Reason: reason, Detail: detail, Exception: ex}
}

// classification is the static verdict for a function code, before any PDU
// content is examined.
type classification struct {
	name   string
	reason string // empty means the function code is a candidate for decoding
	detail string
}

// fcTable is the enumeration of every function code this tool has an opinion
// about. It is deliberately explicit rather than range-based: an auditor should
// be able to read the denial reason for any code seen on the wire, and an
// operator should never see "unknown" for a code that is in fact well known.
//
// Absence from this table is not permission. Anything not listed falls through
// to ReasonUnknown and is denied.
var fcTable = map[byte]classification{
	// --- decodable reads: no reason, so they proceed to content validation ---
	0x01: {name: "Read Coils"},
	0x02: {name: "Read Discrete Inputs"},
	0x03: {name: "Read Holding Registers"},
	0x04: {name: "Read Input Registers"},
	0x0B: {name: "Get Comm Event Counter"},
	0x08: {name: "Diagnostics"},                      // gated by Limits, then by subfunction
	0x2B: {name: "Encapsulated Interface Transport"}, // gated by MEI type

	// --- plain writes ---
	0x05: {"Write Single Coil", ReasonWrite, "single coil write"},
	0x06: {"Write Single Register", ReasonWrite, "single register write"},
	0x0F: {"Write Multiple Coils", ReasonWrite, "multiple coil write"},
	0x10: {"Write Multiple Registers", ReasonWrite, "multiple register write"},
	0x15: {"Write File Record", ReasonWrite, "file record write; program download path on Modicon-family devices"},
	0x16: {"Mask Write Register", ReasonWrite, "read-modify-write disguised by its mask fields"},

	// --- the hybrid ---
	0x17: {"Read/Write Multiple Registers", ReasonHybrid,
		"writes before it reads, and returns only the read data"},

	// --- reads that are not reads ---
	0x14: {"Read File Record", ReasonProgramTransfer,
		"reads extended memory; a program upload on Modicon-family devices"},
	0x18: {"Read FIFO Queue", ReasonDestructiveRead,
		"some vendor implementations pop the queue"},
	0x07: {"Read Exception Status", ReasonInfoDisclosure, "serial-oriented status disclosure"},
	0x0C: {"Get Comm Event Log", ReasonInfoDisclosure, "event log disclosure"},
	0x11: {"Report Server ID", ReasonInfoDisclosure, "device fingerprinting"},

	// --- vendor sub-protocol hiding in the reserved range ---
	0x5A: {"UMAS (Schneider Electric)", ReasonUMAS,
		"Schneider engineering protocol hiding in the reserved range; stops the PLC and writes memory"},
}

// Reserved function codes. Reserved does not mean unused — 0x5A above is the
// standing counterexample — so these fail closed and are named in the log.
var reservedFCs = map[byte]bool{
	0x09: true, 0x0A: true, 0x0D: true, 0x0E: true,
	0x29: true, 0x2A: true, 0x5B: true,
	0x7D: true, 0x7E: true, 0x7F: true,
}

// Classify returns a Denial for any function code that must not be decoded, or
// nil for the small set this tool is prepared to parse.
//
// Ordering is the point: classification happens before decoding, so hostile
// input only ever reaches the parsers for function codes that are already
// permitted in principle. The vendor-protocol problem is unbounded; refusing to
// parse what will never be forwarded bounds the exposed surface to six codes.
func Classify(fc byte, lim Limits) *Denial {
	if c, ok := fcTable[fc]; ok {
		if c.reason != "" {
			return deny(fc, c.reason, c.name+": "+c.detail, ExIllegalFunction)
		}
		if fc == 0x0B && lim.DenyEventCounter {
			return deny(fc, ReasonEventCounterDisabled,
				"Get Comm Event Counter is disabled for this unit", ExIllegalFunction)
		}
		if fc == 0x08 && !lim.AllowDiagnostics {
			return deny(fc, ReasonDiagDisabled,
				"Diagnostics is disabled; enable it per unit with a subfunction allowlist",
				ExIllegalFunction)
		}
		return nil
	}

	switch {
	case fc >= 0x41 && fc <= 0x48: // 65-72
		return deny(fc, ReasonVendorDefined,
			"user-defined range 65-72; contents are vendor-assigned and undocumented",
			ExIllegalFunction)
	case fc >= 0x64 && fc <= 0x6E: // 100-110
		return deny(fc, ReasonVendorDefined,
			"user-defined range 100-110; contents are vendor-assigned and undocumented",
			ExIllegalFunction)
	case reservedFCs[fc]:
		return deny(fc, ReasonReserved, "reserved function code", ExIllegalFunction)
	case fc >= 0x80:
		// The high bit marks an exception response. Seeing one in a request
		// stream means the peer is confused or probing.
		return deny(fc, ReasonUnknown,
			"exception-response function code seen in a request", ExIllegalFunction)
	default:
		return deny(fc, ReasonUnknown, "function code not permitted", ExIllegalFunction)
	}
}

// Name returns the human-readable name of a function code for logging.
func Name(fc byte) string {
	if c, ok := fcTable[fc]; ok {
		return c.name
	}
	return fmt.Sprintf("unassigned(0x%02X)", fc)
}
