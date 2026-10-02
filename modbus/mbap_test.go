package modbus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// build assembles a frame on the wire. It deliberately takes the length field
// as a parameter rather than deriving it, so that tests can construct the
// self-inconsistent frames an attacker would send.
func build(txid uint16, proto uint16, length uint16, uid byte, pdu []byte) []byte {
	b := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(b[0:2], txid)
	binary.BigEndian.PutUint16(b[2:4], proto)
	binary.BigEndian.PutUint16(b[4:6], length)
	b[6] = uid
	return append(b, pdu...)
}

// good builds a well-formed frame with a consistent length field.
func good(txid uint16, uid byte, pdu []byte) []byte {
	return build(txid, ProtocolID, uint16(len(pdu)+1), uid, pdu)
}

// readHoldingRegisters is FC 3, start 0, quantity 1 — the most ordinary request
// on any Modbus network, used as the benign carrier in evasion tests.
var readHoldingRegisters = []byte{0x03, 0x00, 0x00, 0x00, 0x01}

func drain(t *testing.T, f *Framer) ([]Frame, error) {
	t.Helper()
	var out []Frame
	for {
		fr, err := f.Next()
		if errors.Is(err, ErrNeedMore) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, fr)
	}
}

func TestSingleFrame(t *testing.T) {
	f := NewFramer()
	if err := f.Feed(good(0x1234, 0x01, readHoldingRegisters)); err != nil {
		t.Fatal(err)
	}
	frames, err := drain(t, f)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	fr := frames[0]
	if fr.TxID != 0x1234 || fr.UnitID != 0x01 {
		t.Errorf("header mismatch: txid=%#x uid=%#x", fr.TxID, fr.UnitID)
	}
	if !bytes.Equal(fr.PDU, readHoldingRegisters) {
		t.Errorf("pdu = % x, want % x", fr.PDU, readHoldingRegisters)
	}
	if fc, ok := fr.FunctionCode(); !ok || fc != 0x03 {
		t.Errorf("function code = %#x ok=%v", fc, ok)
	}
	if f.Buffered() != 0 {
		t.Errorf("buffer not drained: %d bytes left", f.Buffered())
	}
}

// Pipelining is legal and expected: the transaction identifier exists precisely
// so a client may have several requests outstanding on one connection.
func TestPipelinedInOneSegment(t *testing.T) {
	f := NewFramer()
	var wire []byte
	wire = append(wire, good(1, 0x01, readHoldingRegisters)...)
	wire = append(wire, good(2, 0x07, []byte{0x04, 0x00, 0x10, 0x00, 0x02})...)
	wire = append(wire, good(3, 0xFF, []byte{0x01, 0x00, 0x00, 0x00, 0x08})...)
	if err := f.Feed(wire); err != nil {
		t.Fatal(err)
	}
	frames, err := drain(t, f)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3", len(frames))
	}
	for i, want := range []uint16{1, 2, 3} {
		if frames[i].TxID != want {
			t.Errorf("frame %d txid = %d, want %d", i, frames[i].TxID, want)
		}
	}
}

// The central evasion test. Every per-packet Modbus filter is defeated by
// splitting the stream so that the function-code byte arrives alone, or so that
// the MBAP header is severed from its PDU. Framing must be identical at every
// possible split point.
func TestSplitAtEveryBoundary(t *testing.T) {
	wire := good(0xABCD, 0x2A, readHoldingRegisters)
	for split := 1; split < len(wire); split++ {
		f := NewFramer()
		if err := f.Feed(wire[:split]); err != nil {
			t.Fatalf("split %d: feed head: %v", split, err)
		}
		if _, err := f.Next(); !errors.Is(err, ErrNeedMore) {
			t.Fatalf("split %d: premature frame, err=%v", split, err)
		}
		if err := f.Feed(wire[split:]); err != nil {
			t.Fatalf("split %d: feed tail: %v", split, err)
		}
		fr, err := f.Next()
		if err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		if fr.TxID != 0xABCD || fr.UnitID != 0x2A || !bytes.Equal(fr.PDU, readHoldingRegisters) {
			t.Fatalf("split %d: frame mismatch: %+v", split, fr)
		}
	}
}

func TestByteAtATime(t *testing.T) {
	wire := good(9, 0x01, readHoldingRegisters)
	f := NewFramer()
	var frames []Frame
	for i := 0; i < len(wire); i++ {
		if err := f.Feed(wire[i : i+1]); err != nil {
			t.Fatal(err)
		}
		got, err := drain(t, f)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, got...)
	}
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
}

// A second frame arriving byte-by-byte behind a complete first one must not be
// mistaken for a continuation of it.
func TestInterleavedPartialFollowingComplete(t *testing.T) {
	f := NewFramer()
	first := good(1, 0x01, readHoldingRegisters)
	second := good(2, 0x01, readHoldingRegisters)
	if err := f.Feed(append(first, second[:3]...)); err != nil {
		t.Fatal(err)
	}
	frames, err := drain(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].TxID != 1 {
		t.Fatalf("got %+v, want one frame with txid 1", frames)
	}
	if f.Buffered() != 3 {
		t.Errorf("buffered = %d, want 3", f.Buffered())
	}
	if err := f.Feed(second[3:]); err != nil {
		t.Fatal(err)
	}
	frames, err = drain(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].TxID != 2 {
		t.Fatalf("got %+v, want one frame with txid 2", frames)
	}
}

func TestRejectNonZeroProtocolID(t *testing.T) {
	f := NewFramer()
	if err := f.Feed(build(1, 0x0001, uint16(len(readHoldingRegisters)+1), 0x01, readHoldingRegisters)); err != nil {
		t.Fatal(err)
	}
	_, err := f.Next()
	if !errors.Is(err, ErrProtocolID) {
		t.Fatalf("err = %v, want ErrProtocolID", err)
	}
	if !errors.Is(err, ErrDesynced) {
		t.Errorf("err = %v, want it to also wrap ErrDesynced", err)
	}
}

func TestRejectLengthOutOfRange(t *testing.T) {
	cases := []struct {
		name   string
		length uint16
		want   error
	}{
		{"zero", 0, ErrLengthTooSmall},
		{"one", 1, ErrLengthTooSmall},
		{"over max", MaxLengthField + 1, ErrLengthTooLarge},
		{"absurd", 0xFFFF, ErrLengthTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFramer()
			if err := f.Feed(build(1, ProtocolID, tc.length, 0x01, readHoldingRegisters)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Next(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// Length is validated from the header alone, before the declared bytes arrive.
// An oversized declaration must be rejected immediately rather than after the
// framer has been persuaded to buffer for it.
func TestOversizedLengthRejectedBeforePayload(t *testing.T) {
	f := NewFramer()
	hdr := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(hdr[4:6], 0x8000)
	if err := f.Feed(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Next(); !errors.Is(err, ErrLengthTooLarge) {
		t.Fatalf("err = %v, want ErrLengthTooLarge", err)
	}
}

// MBAP has no sync pattern, so a desynchronized stream cannot be recovered —
// an attacker would choose where the framer resumes. The error must latch.
func TestErrorIsSticky(t *testing.T) {
	f := NewFramer()
	if err := f.Feed(build(1, 0x0099, 6, 0x01, readHoldingRegisters)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Next(); err == nil {
		t.Fatal("expected failure")
	}
	if err := f.Feed(good(2, 0x01, readHoldingRegisters)); !errors.Is(err, ErrDesynced) {
		t.Fatalf("Feed after desync = %v, want ErrDesynced", err)
	}
	if _, err := f.Next(); !errors.Is(err, ErrDesynced) {
		t.Fatalf("Next after desync = %v, want ErrDesynced", err)
	}
	if f.Err() == nil {
		t.Error("Err() should report the latched failure")
	}
}

// A peer that declares a large PDU and then stalls holds a buffer open. The
// framer bounds it; the caller pairs Buffered() with a timeout.
func TestBufferOverflow(t *testing.T) {
	f := NewFramer()
	f.SetMaxBuffered(MaxFrameLen)
	hdr := build(1, ProtocolID, MaxLengthField, 0x01, nil)
	if err := f.Feed(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Next(); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("err = %v, want ErrNeedMore", err)
	}
	if f.Buffered() != HeaderLen {
		t.Errorf("buffered = %d, want %d", f.Buffered(), HeaderLen)
	}
	if err := f.Feed(make([]byte, MaxFrameLen)); !errors.Is(err, ErrBufferOverflow) {
		t.Fatalf("err = %v, want ErrBufferOverflow", err)
	}
}

func TestMaxSizeFrame(t *testing.T) {
	pdu := make([]byte, MaxPDU)
	pdu[0] = 0x03
	f := NewFramer()
	if err := f.Feed(good(1, 0x01, pdu)); err != nil {
		t.Fatal(err)
	}
	fr, err := f.Next()
	if err != nil {
		t.Fatalf("max-size frame rejected: %v", err)
	}
	if len(fr.PDU) != MaxPDU {
		t.Errorf("pdu len = %d, want %d", len(fr.PDU), MaxPDU)
	}
}

// The transaction identifier is not required to be unique, monotonic or
// non-zero. Nothing in the framer may key state on it.
func TestDuplicateTransactionIDs(t *testing.T) {
	f := NewFramer()
	var wire []byte
	for i := 0; i < 4; i++ {
		wire = append(wire, good(0, 0x01, readHoldingRegisters)...)
	}
	if err := f.Feed(wire); err != nil {
		t.Fatal(err)
	}
	frames, err := drain(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 {
		t.Fatalf("got %d frames, want 4", len(frames))
	}
}

// Returned PDUs must not alias the internal buffer, which compaction rewrites.
func TestPDUIsNotAliased(t *testing.T) {
	f := NewFramer()
	var wire []byte
	wire = append(wire, good(1, 0x01, readHoldingRegisters)...)
	wire = append(wire, good(2, 0x01, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF})...)
	if err := f.Feed(wire); err != nil {
		t.Fatal(err)
	}
	first, err := f.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Next(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PDU, readHoldingRegisters) {
		t.Errorf("first PDU corrupted by later framing: % x", first.PDU)
	}
}

// Marshal must produce a frame that re-frames to the same value, and must
// derive the length field rather than trusting any input.
func TestMarshalRoundTrip(t *testing.T) {
	want := Frame{TxID: 0x7F7F, UnitID: 0x0B, PDU: readHoldingRegisters}
	wire, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(wire[4:6]); int(got) != len(want.PDU)+1 {
		t.Errorf("length field = %d, want %d", got, len(want.PDU)+1)
	}
	if got := binary.BigEndian.Uint16(wire[2:4]); got != ProtocolID {
		t.Errorf("protocol id = %#x, want 0", got)
	}
	f := NewFramer()
	if err := f.Feed(wire); err != nil {
		t.Fatal(err)
	}
	got, err := f.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.TxID != want.TxID || got.UnitID != want.UnitID || !bytes.Equal(got.PDU, want.PDU) {
		t.Errorf("round trip mismatch: %+v != %+v", got, want)
	}
}

func TestMarshalRejectsIllegalPDU(t *testing.T) {
	if _, err := (Frame{}).Marshal(); !errors.Is(err, ErrLengthTooSmall) {
		t.Errorf("empty PDU: err = %v", err)
	}
	if _, err := (Frame{PDU: make([]byte, MaxPDU+1)}).Marshal(); !errors.Is(err, ErrLengthTooLarge) {
		t.Errorf("oversized PDU: err = %v", err)
	}
}

// FuzzFramer is the seed for differential testing against the C++
// implementation: the same corpus must produce the same framing in both, and
// any divergence is a bug in one of them.
func FuzzFramer(f *testing.F) {
	f.Add(good(1, 0x01, readHoldingRegisters))
	f.Add(append(good(1, 0x01, readHoldingRegisters), good(2, 0x01, readHoldingRegisters)...))
	f.Add(build(1, 0x0001, 6, 0x01, readHoldingRegisters))
	f.Add(build(1, ProtocolID, 0xFFFF, 0x01, nil))
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		fr := NewFramer()
		fr.SetMaxBuffered(len(data) + MaxFrameLen)
		if err := fr.Feed(data); err != nil {
			return
		}
		for {
			frame, err := fr.Next()
			if err != nil {
				return
			}
			// Invariant: a frame the framer accepts must be representable.
			if len(frame.PDU) < 1 || len(frame.PDU) > MaxPDU {
				t.Fatalf("accepted frame with PDU length %d", len(frame.PDU))
			}
			// Invariant: canonical re-serialization must re-frame identically.
			wire, err := frame.Marshal()
			if err != nil {
				t.Fatalf("accepted frame failed to marshal: %v", err)
			}
			check := NewFramer()
			if err := check.Feed(wire); err != nil {
				t.Fatalf("marshalled frame rejected by Feed: %v", err)
			}
			again, err := check.Next()
			if err != nil {
				t.Fatalf("marshalled frame failed to re-frame: %v", err)
			}
			if again.TxID != frame.TxID || again.UnitID != frame.UnitID ||
				!bytes.Equal(again.PDU, frame.PDU) {
				t.Fatalf("re-framing changed the frame: %+v != %+v", again, frame)
			}
			if check.Buffered() != 0 {
				t.Fatalf("canonical frame left %d trailing bytes", check.Buffered())
			}
		}
	})
}
