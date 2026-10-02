package modbus

import (
	"encoding/binary"
	"fmt"
)

// Quantity limits from the specification. A device may be stricter; none may be
// looser, so enforcing the specification's ceiling here is always safe.
const (
	MaxReadCoils     = 2000 // FC 1, FC 2
	MaxReadRegisters = 125  // FC 3, FC 4
)

// Limits is the per-target parsing posture. The zero value is the strict one:
// diagnostics off, device identification on, private objects refused.
type Limits struct {
	// AllowDiagnostics enables FC 8. Off by default. The readable subfunctions
	// carry counter statistics of little operational value, while the writable
	// ones include a single-packet denial of service.
	AllowDiagnostics bool

	// DiagSubFunctions is the explicit allowlist used when AllowDiagnostics is
	// set. Nil means nothing is permitted even with diagnostics enabled.
	DiagSubFunctions map[uint16]bool

	// DenyDeviceID disables FC 43 / MEI 14 Read Device Identification, which is
	// otherwise permitted since it is genuinely read-only.
	DenyDeviceID bool

	// DenyEventCounter disables FC 11 Get Comm Event Counter.
	DenyEventCounter bool

	// MaxDeviceIDObject bounds the object identifier accepted in an FC 43 /
	// MEI 14 request. Zero means the default of 0x06, the last standard object.
	// Objects 0x80-0xFF are product-dependent private space and on some devices
	// expose credentials.
	MaxDeviceIDObject byte
}

// DefaultLimits returns the recommended read-only posture.
func DefaultLimits() Limits {
	return Limits{
		AllowDiagnostics: false,
		DenyDeviceID:     false,
		// Counter reads, for the deployment that opts into diagnostics.
		DiagSubFunctions: map[uint16]bool{
			0x0002: true, 0x000B: true, 0x000C: true, 0x000D: true,
			0x000E: true, 0x000F: true, 0x0010: true, 0x0011: true, 0x0012: true,
		},
		MaxDeviceIDObject: 0x06,
	}
}

// Request is a decoded, validated request PDU. Every implementation carries
// enough structure to be re-serialized canonically; nothing retains a reference
// to the input bytes.
type Request interface {
	FunctionCode() byte
	// Encode serializes the request from its parsed fields. The enforcement
	// path forwards the output of this method, never the bytes it received.
	Encode() []byte
}

// ReadRequest covers FC 1, 2, 3 and 4, which share a wire shape.
type ReadRequest struct {
	FC       byte
	Start    uint16
	Quantity uint16
}

func (r ReadRequest) FunctionCode() byte { return r.FC }

func (r ReadRequest) Encode() []byte {
	b := make([]byte, 5)
	b[0] = r.FC
	binary.BigEndian.PutUint16(b[1:3], r.Start)
	binary.BigEndian.PutUint16(b[3:5], r.Quantity)
	return b
}

// End returns the first address past the request, as a uint32 so that the
// caller can range-check without wrapping.
func (r ReadRequest) End() uint32 { return uint32(r.Start) + uint32(r.Quantity) }

// EventCounterRequest is FC 11, which has no payload.
type EventCounterRequest struct{}

func (EventCounterRequest) FunctionCode() byte { return 0x0B }
func (EventCounterRequest) Encode() []byte     { return []byte{0x0B} }

// DiagnosticRequest is FC 8, permitted only when explicitly enabled and only
// for allowlisted subfunctions.
type DiagnosticRequest struct {
	SubFunction uint16
	Data        uint16
}

func (DiagnosticRequest) FunctionCode() byte { return 0x08 }

func (d DiagnosticRequest) Encode() []byte {
	b := make([]byte, 5)
	b[0] = 0x08
	binary.BigEndian.PutUint16(b[1:3], d.SubFunction)
	binary.BigEndian.PutUint16(b[3:5], d.Data)
	return b
}

// DeviceIDRequest is FC 43 with MEI type 14, Read Device Identification.
type DeviceIDRequest struct {
	ReadDevIDCode byte
	ObjectID      byte
}

func (DeviceIDRequest) FunctionCode() byte { return 0x2B }

func (d DeviceIDRequest) Encode() []byte {
	return []byte{0x2B, 0x0E, d.ReadDevIDCode, d.ObjectID}
}

// DecodeRequest classifies and then decodes a request PDU.
//
// A non-nil *Denial is the expected outcome for anything this tool refuses; the
// caller turns it into an exception response and an audit record. Classification
// runs first and unconditionally, so a denied function code's payload is never
// parsed.
func DecodeRequest(pdu []byte, lim Limits) (Request, *Denial) {
	if len(pdu) == 0 {
		return nil, deny(0, ReasonMalformed, "empty PDU", ExIllegalDataValue)
	}
	fc := pdu[0]

	if d := Classify(fc, lim); d != nil {
		return nil, d
	}

	switch fc {
	case 0x01, 0x02, 0x03, 0x04:
		return decodeRead(fc, pdu)
	case 0x0B:
		if len(pdu) != 1 {
			return nil, malformed(fc, 1, len(pdu))
		}
		return EventCounterRequest{}, nil
	case 0x08:
		return decodeDiagnostic(pdu, lim)
	case 0x2B:
		return decodeEncapsulated(pdu, lim)
	default:
		// Unreachable: Classify returns nil only for the cases above. Kept as a
		// fail-closed backstop so that adding a code to fcTable without adding
		// a decoder denies rather than panics.
		return nil, deny(fc, ReasonUnknown, "classified as permitted but no decoder is registered", ExIllegalFunction)
	}
}

func decodeRead(fc byte, pdu []byte) (Request, *Denial) {
	if len(pdu) != 5 {
		return nil, malformed(fc, 5, len(pdu))
	}
	r := ReadRequest{
		FC:       fc,
		Start:    binary.BigEndian.Uint16(pdu[1:3]),
		Quantity: binary.BigEndian.Uint16(pdu[3:5]),
	}

	max := uint16(MaxReadRegisters)
	if fc == 0x01 || fc == 0x02 {
		max = MaxReadCoils
	}
	if r.Quantity < 1 || r.Quantity > max {
		return nil, deny(fc, ReasonQuantity,
			fmt.Sprintf("quantity %d outside 1..%d", r.Quantity, max), ExIllegalDataValue)
	}

	// Start + quantity must not run past the 16-bit address space. A device
	// that wraps would serve a different range than the one the policy checked,
	// so this is a policy-integrity check rather than a courtesy.
	if r.End() > 0x10000 {
		return nil, deny(fc, ReasonAddressOverflow,
			fmt.Sprintf("start %d + quantity %d exceeds the 16-bit address space", r.Start, r.Quantity),
			ExIllegalDataAddress)
	}
	return r, nil
}

func decodeDiagnostic(pdu []byte, lim Limits) (Request, *Denial) {
	// Reaching here means AllowDiagnostics is set; Classify enforces that.
	if len(pdu) != 5 {
		return nil, malformed(0x08, 5, len(pdu))
	}
	sub := binary.BigEndian.Uint16(pdu[1:3])
	if !lim.DiagSubFunctions[sub] {
		return nil, deny(0x08, ReasonDiagSubFunction,
			fmt.Sprintf("subfunction 0x%04X is not in the allowlist%s", sub, diagNote(sub)),
			ExIllegalDataValue)
	}
	data := binary.BigEndian.Uint16(pdu[3:5])
	// Every allowlisted subfunction is a counter read and carries no data. A
	// non-zero data field means the request is not what its subfunction claims.
	if data != 0 {
		return nil, deny(0x08, ReasonMalformed,
			fmt.Sprintf("subfunction 0x%04X carries data 0x%04X; counter reads carry zero", sub, data),
			ExIllegalDataValue)
	}
	return DiagnosticRequest{SubFunction: sub, Data: 0}, nil
}

// diagNote annotates the subfunctions whose denial an operator is most likely
// to question, so the log explains itself.
func diagNote(sub uint16) string {
	switch sub {
	case 0x0000:
		return " (Return Query Data echoes arbitrary bytes: a covert channel and an amplifier)"
	case 0x0001:
		return " (Restart Communications Option reinitializes the comms stack and can clear the event log)"
	case 0x0003:
		return " (Change ASCII Input Delimiter is a persistent configuration change)"
	case 0x0004:
		return " (Force Listen Only Mode isolates the device and returns no response: a single-packet denial of service)"
	case 0x000A, 0x0014:
		return " (clears counters: anti-forensic)"
	}
	return ""
}

func decodeEncapsulated(pdu []byte, lim Limits) (Request, *Denial) {
	if len(pdu) < 2 {
		return nil, malformed(0x2B, 2, len(pdu))
	}
	mei := pdu[1]

	// The MEI type, not the function code, decides what this PDU is. MEI 13 is
	// a read and write path into the CANopen object dictionary — a tunnel
	// straight through a filter that gates on FC 43 alone.
	if mei != 0x0E {
		detail := fmt.Sprintf("MEI type 0x%02X is not permitted", mei)
		if mei == 0x0D {
			detail += " (CANopen General Reference: a read and write tunnel)"
		}
		return nil, deny(0x2B, ReasonMEINotAllowed, detail, ExIllegalDataValue)
	}
	if lim.DenyDeviceID {
		return nil, deny(0x2B, ReasonMEINotAllowed,
			"Read Device Identification is disabled for this unit", ExIllegalFunction)
	}
	if len(pdu) != 4 {
		return nil, malformed(0x2B, 4, len(pdu))
	}

	code, obj := pdu[2], pdu[3]
	// 01 basic, 02 regular, 03 extended, 04 individual. Individual access is
	// how a client reaches one specific object, including a private one, so it
	// is refused along with the private range itself.
	if code < 0x01 || code > 0x03 {
		return nil, deny(0x2B, ReasonMEINotAllowed,
			fmt.Sprintf("read device id code 0x%02X not permitted (01-03 only)", code), ExIllegalDataValue)
	}

	maxObj := lim.MaxDeviceIDObject
	if maxObj == 0 {
		maxObj = 0x06
	}
	if obj > maxObj {
		return nil, deny(0x2B, ReasonMEIObjectPrivate,
			fmt.Sprintf("object 0x%02X is above the permitted maximum 0x%02X (private vendor space)",
				obj, maxObj),
			ExIllegalDataAddress)
	}
	return DeviceIDRequest{ReadDevIDCode: code, ObjectID: obj}, nil
}

func malformed(fc byte, want, got int) *Denial {
	return deny(fc, ReasonMalformed,
		fmt.Sprintf("%s: expected a %d-byte PDU, got %d", Name(fc), want, got),
		ExIllegalDataValue)
}

// ExceptionPDU builds the response PDU for a denial.
func ExceptionPDU(fc, code byte) []byte {
	return []byte{fc | 0x80, code}
}
