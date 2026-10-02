package modbus

import (
	"bytes"
	"testing"
)

func mustDeny(t *testing.T, pdu []byte, lim Limits, wantReason string) *Denial {
	t.Helper()
	req, d := DecodeRequest(pdu, lim)
	if d == nil {
		t.Fatalf("pdu % x was permitted, want denial %s (decoded as %#v)", pdu, wantReason, req)
	}
	if d.Reason != wantReason {
		t.Fatalf("pdu % x denied with %q, want %q (%s)", pdu, d.Reason, wantReason, d.Detail)
	}
	if req != nil {
		t.Errorf("denial returned a non-nil request: %#v", req)
	}
	return d
}

func mustAllow(t *testing.T, pdu []byte, lim Limits) Request {
	t.Helper()
	req, d := DecodeRequest(pdu, lim)
	if d != nil {
		t.Fatalf("pdu % x denied unexpectedly: %v", pdu, d)
	}
	return req
}

func TestPermittedReads(t *testing.T) {
	lim := DefaultLimits()
	cases := []struct {
		name string
		pdu  []byte
	}{
		{"read coils", []byte{0x01, 0x00, 0x13, 0x00, 0x13}},
		{"read discrete inputs", []byte{0x02, 0x00, 0xC4, 0x00, 0x16}},
		{"read holding registers", []byte{0x03, 0x00, 0x6B, 0x00, 0x03}},
		{"read input registers", []byte{0x04, 0x00, 0x08, 0x00, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := mustAllow(t, tc.pdu, lim)
			if !bytes.Equal(req.Encode(), tc.pdu) {
				t.Errorf("re-encode = % x, want % x", req.Encode(), tc.pdu)
			}
		})
	}
}

func TestWritesDenied(t *testing.T) {
	lim := DefaultLimits()
	for _, fc := range []byte{0x05, 0x06, 0x0F, 0x10, 0x15, 0x16} {
		pdu := append([]byte{fc}, make([]byte, 8)...)
		d := mustDeny(t, pdu, lim, ReasonWrite)
		if d.Exception != ExIllegalFunction {
			t.Errorf("fc 0x%02X: exception = 0x%02X, want 0x01", fc, d.Exception)
		}
	}
}

// FC 23 performs the write before the read and returns only read data, so a
// permitted one is invisible to the operator. There is no read-only subset.
func TestReadWriteMultipleDenied(t *testing.T) {
	pdu := []byte{
		0x17,
		0x00, 0x03, // read start
		0x00, 0x06, // read quantity
		0x00, 0x0E, // write start
		0x00, 0x03, // write quantity
		0x06, // write byte count
		0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF,
	}
	mustDeny(t, pdu, DefaultLimits(), ReasonHybrid)
}

// Reading a file record is a program upload on Modicon-family devices.
func TestFileRecordReadDenied(t *testing.T) {
	mustDeny(t, []byte{0x14, 0x0E, 0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02},
		DefaultLimits(), ReasonProgramTransfer)
}

// The headline case: 0x5A is reserved, not user-defined, so a filter that
// denies only the user-defined ranges passes Schneider's engineering protocol.
// Denial happens at classification, so the UMAS layer is never parsed.
func TestUMASDenied(t *testing.T) {
	// UMAS 0x41 ex_StopTask — stops the PLC, no reservation required.
	pdu := []byte{0x5A, 0x00, 0x41, 0x00}
	d := mustDeny(t, pdu, DefaultLimits(), ReasonUMAS)
	if d.Exception != ExIllegalFunction {
		t.Errorf("exception = 0x%02X, want 0x01", d.Exception)
	}
}

func TestVendorAndReservedRangesDenied(t *testing.T) {
	lim := DefaultLimits()
	for _, fc := range []byte{0x41, 0x45, 0x48, 0x64, 0x6A, 0x6E} {
		mustDeny(t, []byte{fc, 0x00}, lim, ReasonVendorDefined)
	}
	for _, fc := range []byte{0x09, 0x0A, 0x0D, 0x0E, 0x29, 0x2A, 0x5B, 0x7D, 0x7E, 0x7F} {
		mustDeny(t, []byte{fc, 0x00}, lim, ReasonReserved)
	}
}

func TestUnknownFunctionCodeDenied(t *testing.T) {
	mustDeny(t, []byte{0x33, 0x00}, DefaultLimits(), ReasonUnknown)
	// An exception-response code arriving in a request stream.
	mustDeny(t, []byte{0x83, 0x02}, DefaultLimits(), ReasonUnknown)
}

func TestQuantityLimits(t *testing.T) {
	lim := DefaultLimits()
	// Zero quantity is illegal for every read.
	mustDeny(t, []byte{0x03, 0x00, 0x00, 0x00, 0x00}, lim, ReasonQuantity)
	// 126 registers exceeds the 125 ceiling.
	mustDeny(t, []byte{0x03, 0x00, 0x00, 0x00, 0x7E}, lim, ReasonQuantity)
	// 125 is the boundary and must pass.
	mustAllow(t, []byte{0x03, 0x00, 0x00, 0x00, 0x7D}, lim)
	// Coils allow 2000, not 2001.
	mustAllow(t, []byte{0x01, 0x00, 0x00, 0x07, 0xD0}, lim)
	mustDeny(t, []byte{0x01, 0x00, 0x00, 0x07, 0xD1}, lim, ReasonQuantity)
}

// A request whose range wraps past 0xFFFF would be served differently by a
// device that wraps than by the policy check, so it is refused.
func TestAddressOverflow(t *testing.T) {
	mustDeny(t, []byte{0x03, 0xFF, 0xFF, 0x00, 0x02}, DefaultLimits(), ReasonAddressOverflow)
	// Exactly reaching the top of the address space is legal.
	mustAllow(t, []byte{0x03, 0xFF, 0xFE, 0x00, 0x02}, DefaultLimits())
}

func TestStrictPDULengths(t *testing.T) {
	lim := DefaultLimits()
	// Trailing byte beyond the fixed shape: the classic place to hide content
	// that a lenient device might act on.
	mustDeny(t, []byte{0x03, 0x00, 0x00, 0x00, 0x01, 0xFF}, lim, ReasonMalformed)
	mustDeny(t, []byte{0x03, 0x00, 0x00, 0x00}, lim, ReasonMalformed)
	mustDeny(t, []byte{0x0B, 0x00}, lim, ReasonMalformed)
	mustDeny(t, []byte{}, lim, ReasonMalformed)
}

func TestDiagnosticsDisabledByDefault(t *testing.T) {
	d := mustDeny(t, []byte{0x08, 0x00, 0x0B, 0x00, 0x00}, DefaultLimits(), ReasonDiagDisabled)
	if d.FC != 0x08 {
		t.Errorf("fc = 0x%02X", d.FC)
	}
}

func TestDiagnosticsSubFunctionGate(t *testing.T) {
	lim := DefaultLimits()
	lim.AllowDiagnostics = true

	// An allowlisted counter read passes.
	req := mustAllow(t, []byte{0x08, 0x00, 0x0B, 0x00, 0x00}, lim)
	if !bytes.Equal(req.Encode(), []byte{0x08, 0x00, 0x0B, 0x00, 0x00}) {
		t.Errorf("re-encode = % x", req.Encode())
	}

	// Force Listen Only Mode stays denied even with diagnostics enabled: one
	// packet, no response, device isolated.
	d := mustDeny(t, []byte{0x08, 0x00, 0x04, 0x00, 0x00}, lim, ReasonDiagSubFunction)
	if !bytes.Contains([]byte(d.Detail), []byte("denial of service")) {
		t.Errorf("detail should explain the risk, got %q", d.Detail)
	}

	// Return Query Data is an echo primitive.
	mustDeny(t, []byte{0x08, 0x00, 0x00, 0x00, 0x00}, lim, ReasonDiagSubFunction)
	// Restart Communications Option.
	mustDeny(t, []byte{0x08, 0x00, 0x01, 0xFF, 0x00}, lim, ReasonDiagSubFunction)
	// Clear counters.
	mustDeny(t, []byte{0x08, 0x00, 0x0A, 0x00, 0x00}, lim, ReasonDiagSubFunction)

	// An allowlisted subfunction carrying a payload is not what it claims.
	mustDeny(t, []byte{0x08, 0x00, 0x0B, 0xDE, 0xAD}, lim, ReasonMalformed)
}

// FC 43 is decided by the MEI byte. MEI 13 is a read and write path into the
// CANopen object dictionary and must not ride through on the function code.
func TestEncapsulatedMEIGate(t *testing.T) {
	lim := DefaultLimits()

	req := mustAllow(t, []byte{0x2B, 0x0E, 0x01, 0x00}, lim)
	if !bytes.Equal(req.Encode(), []byte{0x2B, 0x0E, 0x01, 0x00}) {
		t.Errorf("re-encode = % x", req.Encode())
	}

	d := mustDeny(t, []byte{0x2B, 0x0D, 0x00, 0x00}, lim, ReasonMEINotAllowed)
	if !bytes.Contains([]byte(d.Detail), []byte("CANopen")) {
		t.Errorf("detail should name the CANopen tunnel, got %q", d.Detail)
	}

	for _, mei := range []byte{0x00, 0x01, 0x0C, 0x0F, 0xFF} {
		mustDeny(t, []byte{0x2B, mei, 0x00, 0x00}, lim, ReasonMEINotAllowed)
	}
}

func TestDeviceIDObjectBounds(t *testing.T) {
	lim := DefaultLimits()
	mustAllow(t, []byte{0x2B, 0x0E, 0x01, 0x06}, lim)
	// Private vendor space.
	mustDeny(t, []byte{0x2B, 0x0E, 0x01, 0x80}, lim, ReasonMEIObjectPrivate)
	mustDeny(t, []byte{0x2B, 0x0E, 0x01, 0x07}, lim, ReasonMEIObjectPrivate)
	// Individual access (code 04) is how a client reaches one specific object.
	mustDeny(t, []byte{0x2B, 0x0E, 0x04, 0x00}, lim, ReasonMEINotAllowed)

	lim.DenyDeviceID = true
	mustDeny(t, []byte{0x2B, 0x0E, 0x01, 0x00}, lim, ReasonMEINotAllowed)
}

func TestExceptionPDU(t *testing.T) {
	got := ExceptionPDU(0x17, ExIllegalFunction)
	if !bytes.Equal(got, []byte{0x97, 0x01}) {
		t.Errorf("ExceptionPDU = % x, want 97 01", got)
	}
}

// Every request this tool accepts must re-encode to exactly the bytes it was
// given. A divergence means the decoder discarded or normalized something,
// which is precisely where a device and a filter come to disagree.
func FuzzRequestRoundTrip(f *testing.F) {
	f.Add([]byte{0x03, 0x00, 0x6B, 0x00, 0x03})
	f.Add([]byte{0x01, 0x00, 0x13, 0x00, 0x13})
	f.Add([]byte{0x2B, 0x0E, 0x01, 0x00})
	f.Add([]byte{0x08, 0x00, 0x0B, 0x00, 0x00})
	f.Add([]byte{0x17, 0x00, 0x03, 0x00, 0x06, 0x00, 0x0E, 0x00, 0x03, 0x06, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x5A, 0x00, 0x41, 0x00})

	lim := DefaultLimits()
	lim.AllowDiagnostics = true

	f.Fuzz(func(t *testing.T, pdu []byte) {
		req, d := DecodeRequest(pdu, lim)
		if d != nil {
			if req != nil {
				t.Fatalf("denial returned a request: %#v", req)
			}
			if d.Exception == 0 {
				t.Fatalf("denial without an exception code: %v", d)
			}
			return
		}
		out := req.Encode()
		if !bytes.Equal(out, pdu) {
			t.Fatalf("accepted % x but re-encoded to % x", pdu, out)
		}
		// An accepted request must survive a second decode unchanged.
		again, d2 := DecodeRequest(out, lim)
		if d2 != nil {
			t.Fatalf("re-encoded request rejected on second pass: %v", d2)
		}
		if !bytes.Equal(again.Encode(), out) {
			t.Fatalf("second pass differs: % x vs % x", again.Encode(), out)
		}
	})
}
