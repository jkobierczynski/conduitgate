package modbus

import (
	"bytes"
	"testing"
)

func denyResp(t *testing.T, pdu []byte, req Request, wantReason string) *Denial {
	t.Helper()
	resp, d := DecodeResponse(pdu, req, DefaultLimits())
	if d == nil {
		t.Fatalf("response % x was permitted, want denial %s (decoded as %#v)", pdu, wantReason, resp)
	}
	if d.Reason != wantReason {
		t.Fatalf("response % x denied with %q, want %q (%s)", pdu, d.Reason, wantReason, d.Detail)
	}
	if resp != nil {
		t.Errorf("denial returned a non-nil response: %#v", resp)
	}
	return d
}

func allowResp(t *testing.T, pdu []byte, req Request) Response {
	t.Helper()
	resp, d := DecodeResponse(pdu, req, DefaultLimits())
	if d != nil {
		t.Fatalf("response % x denied unexpectedly: %v", pdu, d)
	}
	if !bytes.Equal(resp.Encode(), pdu) {
		t.Errorf("re-encode = % x, want % x", resp.Encode(), pdu)
	}
	return resp
}

func TestReadResponseAccepted(t *testing.T) {
	// FC 3, three registers requested, six data bytes returned.
	req := ReadRequest{FC: 0x03, Start: 0x6B, Quantity: 3}
	allowResp(t, []byte{0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64}, req)

	// FC 1, thirteen coils requested, two packed bytes returned.
	allowResp(t, []byte{0x01, 0x02, 0xCD, 0x0B}, ReadRequest{FC: 0x01, Start: 0x13, Quantity: 13})

	// Exactly eight coils still fits one byte.
	allowResp(t, []byte{0x01, 0x01, 0xFF}, ReadRequest{FC: 0x01, Start: 0, Quantity: 8})
}

// The response-side twin of the MBAP desync: the declared byte count and the
// actual PDU length must agree, or a device and a client resolving the
// disagreement differently see different data.
func TestResponseByteCountVersusPDULength(t *testing.T) {
	req := ReadRequest{FC: 0x03, Start: 0, Quantity: 2}
	// Declares four bytes, carries six.
	denyResp(t, []byte{0x03, 0x04, 0, 1, 0, 2, 0xDE, 0xAD}, req, ReasonRespByteCount)
	// Declares six bytes, carries four.
	denyResp(t, []byte{0x03, 0x06, 0, 1, 0, 2}, req, ReasonRespByteCount)
}

// And the byte count must match what was actually asked for. A device returning
// more registers than requested is either faulty or answering someone else.
func TestResponseByteCountVersusRequest(t *testing.T) {
	req := ReadRequest{FC: 0x03, Start: 0, Quantity: 2}
	denyResp(t, []byte{0x03, 0x08, 0, 1, 0, 2, 0, 3, 0, 4}, req, ReasonRespByteCount)

	// Coil packing is checked the same way: 13 coils is 2 bytes, not 3.
	denyResp(t, []byte{0x01, 0x03, 0xFF, 0xFF, 0xFF},
		ReadRequest{FC: 0x01, Start: 0, Quantity: 13}, ReasonRespByteCount)
}

func TestResponseFunctionMismatch(t *testing.T) {
	req := ReadRequest{FC: 0x03, Start: 0, Quantity: 1}
	denyResp(t, []byte{0x04, 0x02, 0x00, 0x01}, req, ReasonRespMismatch)
	// A write response to a read request — the device answering something the
	// proxy never forwarded.
	denyResp(t, []byte{0x06, 0x00, 0x0A, 0xDE, 0xAD}, req, ReasonRespMismatch)
}

func TestExceptionResponses(t *testing.T) {
	req := ReadRequest{FC: 0x03, Start: 0, Quantity: 1}

	// A legitimate device exception is relayed unchanged.
	resp := allowResp(t, []byte{0x83, 0x02}, req)
	if ex, ok := resp.(ExceptionResponse); !ok || ex.Code != 0x02 || ex.FC != 0x03 {
		t.Errorf("decoded as %#v", resp)
	}

	// An exception for a different function code.
	denyResp(t, []byte{0x84, 0x02}, req, ReasonRespMismatch)
	// Codes outside the specification's set.
	denyResp(t, []byte{0x83, 0x07}, req, ReasonRespExceptionCode)
	denyResp(t, []byte{0x83, 0x99}, req, ReasonRespExceptionCode)
	denyResp(t, []byte{0x83, 0x00}, req, ReasonRespExceptionCode)
	// Trailing bytes on an exception.
	denyResp(t, []byte{0x83, 0x02, 0xFF}, req, ReasonRespMalformed)
}

func TestUnsolicitedResponse(t *testing.T) {
	denyResp(t, []byte{0x03, 0x02, 0x00, 0x01}, nil, ReasonRespUnsolicited)
}

func TestEventCounterResponse(t *testing.T) {
	allowResp(t, []byte{0x0B, 0xFF, 0xFF, 0x01, 0x08}, EventCounterRequest{})
	denyResp(t, []byte{0x0B, 0xFF, 0xFF, 0x01}, EventCounterRequest{}, ReasonRespMalformed)
}

func TestDiagnosticResponseEchoesSubFunction(t *testing.T) {
	req := DiagnosticRequest{SubFunction: 0x000B}
	allowResp(t, []byte{0x08, 0x00, 0x0B, 0x01, 0x2C}, req)
	// A device answering a different subfunction than it was asked.
	denyResp(t, []byte{0x08, 0x00, 0x04, 0x00, 0x00}, req, ReasonRespMismatch)
}

func deviceIDResponse(objects ...[]byte) []byte {
	out := []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, byte(len(objects))}
	for _, o := range objects {
		out = append(out, o...)
	}
	return out
}

func TestDeviceIDResponse(t *testing.T) {
	req := DeviceIDRequest{ReadDevIDCode: 0x01, ObjectID: 0x00}

	ok := deviceIDResponse(
		append([]byte{0x00, 0x07}, []byte("Acme Co")...),
		append([]byte{0x01, 0x04}, []byte("M340")...),
	)
	allowResp(t, ok, req)

	// A device returning an object from the private range, which the client
	// never asked for and which exposes credentials on some hardware.
	priv := deviceIDResponse(append([]byte{0x80, 0x04}, []byte("s3cr")...))
	denyResp(t, priv, req, ReasonRespObject)

	// An object whose declared length runs past the PDU.
	denyResp(t, []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x20, 0x41},
		req, ReasonRespMalformed)

	// Trailing bytes after the declared objects.
	trailing := append(deviceIDResponse(append([]byte{0x00, 0x02}, []byte("hi")...)), 0xDE, 0xAD)
	denyResp(t, trailing, req, ReasonRespMalformed)

	// MoreFollows must be 0x00 or 0xFF.
	denyResp(t, []byte{0x2B, 0x0E, 0x01, 0x01, 0x42, 0x00, 0x00}, req, ReasonRespMalformed)

	// The read device id code must echo.
	denyResp(t, []byte{0x2B, 0x0E, 0x03, 0x01, 0x00, 0x00, 0x00}, req, ReasonRespMismatch)

	// The MEI type must echo.
	denyResp(t, []byte{0x2B, 0x0D, 0x01, 0x01, 0x00, 0x00, 0x00}, req, ReasonRespMismatch)
}

func TestDeniedResponsesCarryAnException(t *testing.T) {
	req := ReadRequest{FC: 0x03, Start: 0, Quantity: 1}
	d := denyResp(t, []byte{0x03, 0x04, 0, 1}, req, ReasonRespByteCount)
	if d.Exception != ExServerDeviceFailure {
		t.Errorf("exception = 0x%02X, want 0x04 so the client sees a device fault", d.Exception)
	}
}

// Anything accepted must re-encode to exactly its input, for the same reason as
// on the request side: a divergence is where a device and a client come to
// disagree about what was said.
func FuzzResponseRoundTrip(f *testing.F) {
	f.Add([]byte{0x03, 0x06, 0x02, 0x2B, 0x00, 0x00, 0x00, 0x64})
	f.Add([]byte{0x83, 0x02})
	f.Add([]byte{0x03, 0x04, 0, 1, 0, 2})

	req := ReadRequest{FC: 0x03, Start: 0, Quantity: 3}
	lim := DefaultLimits()

	f.Fuzz(func(t *testing.T, pdu []byte) {
		resp, d := DecodeResponse(pdu, req, lim)
		if d != nil {
			if resp != nil {
				t.Fatalf("denial returned a response: %#v", resp)
			}
			if d.Exception == 0 {
				t.Fatalf("denial without an exception code: %v", d)
			}
			return
		}
		if out := resp.Encode(); !bytes.Equal(out, pdu) {
			t.Fatalf("accepted % x but re-encoded to % x", pdu, out)
		}
	})
}
