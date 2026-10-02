package modbus

import (
	"encoding/binary"
	"fmt"
)

// Why the response direction is validated at all.
//
// Two reasons, and the second is the one people forget.
//
//  1. It closes the other half of the length-desync surface. A response carries
//     its own byte count, which can disagree with the MBAP length exactly as a
//     request's can. Framing alone does not catch that; only decoding the PDU
//     and re-serializing it from parsed fields does.
//
//  2. A read-only proxy that validates only requests protects the device from
//     the client and leaves the client undefended against the device. In the
//     deployment this tool is for — a vendor or engineer reaching a PLC through
//     a gateway — the engineering workstation is an asset too, and a
//     compromised or faulty device is precisely the threat the gateway was
//     installed to contain. Unsolicited replies, function codes nobody asked
//     for, and over-long object payloads all reach the client unless something
//     in the path refuses them.

// Additional exception codes used when the proxy answers on the device's behalf.
const (
	ExServerDeviceFailure = 0x04
	ExServerDeviceBusy    = 0x06
)

// Response-side reason codes.
const (
	ReasonRespUnsolicited    = "resp.unsolicited"
	ReasonRespMismatch       = "resp.function_mismatch"
	ReasonRespMalformed      = "resp.malformed"
	ReasonRespByteCount      = "resp.byte_count_mismatch"
	ReasonRespObject         = "resp.object_not_permitted"
	ReasonRespExceptionCode  = "resp.invalid_exception_code"
	ReasonTooManyOutstanding = "req.too_many_outstanding"
)

// validExceptionCodes is the set defined by the specification. A device
// returning anything else is not speaking Modbus, and passing the byte through
// would let it smuggle a value to a lenient client.
var validExceptionCodes = map[byte]bool{
	0x01: true, // Illegal Function
	0x02: true, // Illegal Data Address
	0x03: true, // Illegal Data Value
	0x04: true, // Server Device Failure
	0x05: true, // Acknowledge
	0x06: true, // Server Device Busy
	0x08: true, // Memory Parity Error
	0x0A: true, // Gateway Path Unavailable
	0x0B: true, // Gateway Target Device Failed To Respond
}

// Response is a decoded, validated response PDU.
type Response interface {
	FunctionCode() byte
	// Encode re-serializes from parsed fields. As on the request side, the
	// enforcement path forwards this, never the bytes it received.
	Encode() []byte
}

// ReadResponse covers FC 1, 2, 3 and 4. Data is the payload beyond the byte
// count, whose length the decoder has already checked against the quantity the
// matching request asked for.
type ReadResponse struct {
	FC   byte
	Data []byte
}

func (r ReadResponse) FunctionCode() byte { return r.FC }

func (r ReadResponse) Encode() []byte {
	out := make([]byte, 2+len(r.Data))
	out[0] = r.FC
	out[1] = byte(len(r.Data))
	copy(out[2:], r.Data)
	return out
}

// EventCounterResponse is FC 11.
type EventCounterResponse struct {
	Status uint16
	Count  uint16
}

func (EventCounterResponse) FunctionCode() byte { return 0x0B }

func (r EventCounterResponse) Encode() []byte {
	out := make([]byte, 5)
	out[0] = 0x0B
	binary.BigEndian.PutUint16(out[1:3], r.Status)
	binary.BigEndian.PutUint16(out[3:5], r.Count)
	return out
}

// DiagnosticResponse is FC 8. The subfunction must echo the request's.
type DiagnosticResponse struct {
	SubFunction uint16
	Data        uint16
}

func (DiagnosticResponse) FunctionCode() byte { return 0x08 }

func (r DiagnosticResponse) Encode() []byte {
	out := make([]byte, 5)
	out[0] = 0x08
	binary.BigEndian.PutUint16(out[1:3], r.SubFunction)
	binary.BigEndian.PutUint16(out[3:5], r.Data)
	return out
}

// DeviceIDObject is one entry in an FC 43 / MEI 14 response.
type DeviceIDObject struct {
	ID    byte
	Value []byte
}

// DeviceIDResponse is FC 43 with MEI type 14.
type DeviceIDResponse struct {
	ReadDevIDCode   byte
	ConformityLevel byte
	MoreFollows     byte
	NextObjectID    byte
	Objects         []DeviceIDObject
}

func (DeviceIDResponse) FunctionCode() byte { return 0x2B }

func (r DeviceIDResponse) Encode() []byte {
	out := []byte{0x2B, 0x0E, r.ReadDevIDCode, r.ConformityLevel,
		r.MoreFollows, r.NextObjectID, byte(len(r.Objects))}
	for _, o := range r.Objects {
		out = append(out, o.ID, byte(len(o.Value)))
		out = append(out, o.Value...)
	}
	return out
}

// ExceptionResponse is a device-originated error. FC is the original function
// code without the high bit.
type ExceptionResponse struct {
	FC   byte
	Code byte
}

func (r ExceptionResponse) FunctionCode() byte { return r.FC }
func (r ExceptionResponse) Encode() []byte     { return []byte{r.FC | 0x80, r.Code} }

// DecodeResponse validates a response against the request that produced it.
//
// The request is not optional. Almost every meaningful check here is relational
// — does the byte count match the quantity that was asked for, does the
// subfunction echo, is this even the function code the client sent — and none
// of them can be made by looking at the response alone.
func DecodeResponse(pdu []byte, req Request, lim Limits) (Response, *Denial) {
	if req == nil {
		return nil, deny(0, ReasonRespUnsolicited,
			"response with no matching outstanding request", ExServerDeviceFailure)
	}
	if len(pdu) == 0 {
		return nil, deny(req.FunctionCode(), ReasonRespMalformed, "empty response PDU", ExServerDeviceFailure)
	}

	fc := pdu[0]
	want := req.FunctionCode()

	// Device-reported exception.
	if fc&0x80 != 0 {
		base := fc &^ 0x80
		if base != want {
			return nil, deny(want, ReasonRespMismatch,
				fmt.Sprintf("exception for function 0x%02X, request was 0x%02X", base, want),
				ExServerDeviceFailure)
		}
		if len(pdu) != 2 {
			return nil, respMalformed(want, 2, len(pdu))
		}
		if !validExceptionCodes[pdu[1]] {
			return nil, deny(want, ReasonRespExceptionCode,
				fmt.Sprintf("exception code 0x%02X is not defined by the specification", pdu[1]),
				ExServerDeviceFailure)
		}
		return ExceptionResponse{FC: base, Code: pdu[1]}, nil
	}

	if fc != want {
		return nil, deny(want, ReasonRespMismatch,
			fmt.Sprintf("response function 0x%02X does not match request 0x%02X", fc, want),
			ExServerDeviceFailure)
	}

	switch r := req.(type) {
	case ReadRequest:
		return decodeReadResponse(pdu, r)
	case EventCounterRequest:
		if len(pdu) != 5 {
			return nil, respMalformed(fc, 5, len(pdu))
		}
		return EventCounterResponse{
			Status: binary.BigEndian.Uint16(pdu[1:3]),
			Count:  binary.BigEndian.Uint16(pdu[3:5]),
		}, nil
	case DiagnosticRequest:
		return decodeDiagnosticResponse(pdu, r)
	case DeviceIDRequest:
		return decodeDeviceIDResponse(pdu, r, lim)
	default:
		return nil, deny(fc, ReasonRespMalformed,
			"no response decoder for this request type", ExServerDeviceFailure)
	}
}

func decodeReadResponse(pdu []byte, req ReadRequest) (Response, *Denial) {
	if len(pdu) < 2 {
		return nil, respMalformed(req.FC, 2, len(pdu))
	}
	declared := int(pdu[1])

	// The declared byte count must agree with the actual PDU length. This is
	// the response-side twin of the MBAP length desync: a device and a client
	// that resolve a disagreement differently see different data.
	if len(pdu) != 2+declared {
		return nil, deny(req.FC, ReasonRespByteCount,
			fmt.Sprintf("byte count %d implies a %d-byte PDU, got %d", declared, 2+declared, len(pdu)),
			ExServerDeviceFailure)
	}

	// And it must match what the request asked for.
	var expect int
	switch req.FC {
	case 0x01, 0x02:
		expect = (int(req.Quantity) + 7) / 8
	default:
		expect = int(req.Quantity) * 2
	}
	if declared != expect {
		return nil, deny(req.FC, ReasonRespByteCount,
			fmt.Sprintf("byte count %d does not match the %d requested (expected %d bytes)",
				declared, req.Quantity, expect),
			ExServerDeviceFailure)
	}

	return ReadResponse{FC: req.FC, Data: append([]byte(nil), pdu[2:]...)}, nil
}

func decodeDiagnosticResponse(pdu []byte, req DiagnosticRequest) (Response, *Denial) {
	if len(pdu) != 5 {
		return nil, respMalformed(0x08, 5, len(pdu))
	}
	sub := binary.BigEndian.Uint16(pdu[1:3])
	if sub != req.SubFunction {
		return nil, deny(0x08, ReasonRespMismatch,
			fmt.Sprintf("subfunction 0x%04X does not echo the requested 0x%04X", sub, req.SubFunction),
			ExServerDeviceFailure)
	}
	return DiagnosticResponse{SubFunction: sub, Data: binary.BigEndian.Uint16(pdu[3:5])}, nil
}

func decodeDeviceIDResponse(pdu []byte, req DeviceIDRequest, lim Limits) (Response, *Denial) {
	const headerLen = 7 // FC, MEI, code, conformity, more, next, count
	if len(pdu) < headerLen {
		return nil, respMalformed(0x2B, headerLen, len(pdu))
	}
	if pdu[1] != 0x0E {
		return nil, deny(0x2B, ReasonRespMismatch,
			fmt.Sprintf("MEI type 0x%02X in response, request was 0x0E", pdu[1]), ExServerDeviceFailure)
	}
	if pdu[2] != req.ReadDevIDCode {
		return nil, deny(0x2B, ReasonRespMismatch,
			fmt.Sprintf("read device id code 0x%02X does not echo the requested 0x%02X",
				pdu[2], req.ReadDevIDCode), ExServerDeviceFailure)
	}
	if more := pdu[4]; more != 0x00 && more != 0xFF {
		return nil, deny(0x2B, ReasonRespMalformed,
			fmt.Sprintf("MoreFollows 0x%02X is neither 0x00 nor 0xFF", more), ExServerDeviceFailure)
	}

	maxObj := lim.MaxDeviceIDObject
	if maxObj == 0 {
		maxObj = 0x06
	}

	count := int(pdu[6])
	objects := make([]DeviceIDObject, 0, count)
	off := headerLen
	for i := 0; i < count; i++ {
		if off+2 > len(pdu) {
			return nil, deny(0x2B, ReasonRespMalformed,
				fmt.Sprintf("object %d header runs past the PDU", i), ExServerDeviceFailure)
		}
		id, length := pdu[off], int(pdu[off+1])
		off += 2
		if off+length > len(pdu) {
			return nil, deny(0x2B, ReasonRespMalformed,
				fmt.Sprintf("object 0x%02X declares %d bytes, which runs past the PDU", id, length),
				ExServerDeviceFailure)
		}
		// A device may return objects the client did not ask for. The private
		// range is refused on the way back as well as on the way out.
		if id > maxObj {
			return nil, deny(0x2B, ReasonRespObject,
				fmt.Sprintf("device returned object 0x%02X, above the permitted maximum 0x%02X", id, maxObj),
				ExServerDeviceFailure)
		}
		objects = append(objects, DeviceIDObject{ID: id, Value: append([]byte(nil), pdu[off:off+length]...)})
		off += length
	}
	// Trailing bytes after the declared objects are exactly the place to hide
	// content a lenient client might parse.
	if off != len(pdu) {
		return nil, deny(0x2B, ReasonRespMalformed,
			fmt.Sprintf("%d trailing bytes after %d declared objects", len(pdu)-off, count),
			ExServerDeviceFailure)
	}

	return DeviceIDResponse{
		ReadDevIDCode:   pdu[2],
		ConformityLevel: pdu[3],
		MoreFollows:     pdu[4],
		NextObjectID:    pdu[5],
		Objects:         objects,
	}, nil
}

func respMalformed(fc byte, want, got int) *Denial {
	return deny(fc, ReasonRespMalformed,
		fmt.Sprintf("%s response: expected a %d-byte PDU, got %d", Name(fc), want, got),
		ExServerDeviceFailure)
}
