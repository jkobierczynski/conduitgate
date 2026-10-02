// Package modbus implements strict MBAP framing for Modbus/TCP.
//
// Design posture: this is the front door of an inline enforcement element. It
// runs on hostile input, in the path of a control system, so it fails closed on
// anything it does not fully understand. Three properties matter more than
// throughput:
//
//  1. It frames a byte stream, never individual packets. A PDU may span any
//     number of TCP segments, and any number of PDUs may coalesce into one.
//     Every per-packet Modbus filter is evaded by placing the function-code
//     byte in a segment of its own; this one cannot be.
//
//  2. It never resynchronizes. MBAP has no sync pattern and no frame
//     delimiter, so once a stream is desynchronized there is no sound way to
//     find the next frame boundary — the attacker chooses where you land. A
//     framing error is therefore sticky, and the caller must tear the
//     connection down rather than attempt recovery.
//
//  3. It hands out copies, not views. Returning a subslice of the internal
//     buffer would alias memory that the next compaction overwrites. At Modbus
//     rates the copy costs nothing and removes a whole class of bug.
//
// What this layer does NOT do: it enforces that the PDU is exactly the length
// the MBAP header declares, but it does not cross-check that length against a
// PDU-internal byte-count field (the FC 3 response byte count, the FC 20
// sub-request lengths, and so on). That check belongs to the PDU decoder,
// because only the decoder knows the shape of each function code. It is the
// other half of the length-desync smuggling defence and must not be forgotten:
// the framer closes the outer boundary, the decoder closes the inner one, and
// re-serialization from parsed fields closes the gap between them.
package modbus

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire constants from the Modbus Messaging on TCP/IP Implementation Guide.
const (
	// HeaderLen is the MBAP header: TxID(2) ProtoID(2) Length(2) UnitID(1).
	HeaderLen = 7

	// MaxPDU is the maximum Modbus PDU, derived from the 253-byte limit the
	// serial line protocol imposes and which TCP inherits for compatibility.
	MaxPDU = 253

	// The Length field counts the UnitID byte plus the PDU. It therefore
	// cannot be smaller than 2 (UnitID + function code) nor larger than 254.
	MinLengthField = 2
	MaxLengthField = 1 + MaxPDU

	// MaxFrameLen is the largest legal frame on the wire.
	MaxFrameLen = HeaderLen + MaxPDU

	// ProtocolID must be zero. Non-zero values have been observed used to
	// tunnel other payloads past naive filters, so this is enforced, not
	// merely logged.
	ProtocolID = 0x0000

	// UnitIDNone is the conventional value for a device addressed directly
	// over TCP rather than through a serial gateway. It is not special-cased
	// here: policy is keyed on the unit ID whatever its value, because behind
	// a gateway or a backplane bridge the unit ID selects a different physical
	// device at the same address and port.
	UnitIDNone = 0xFF

	// defaultMaxBuffered bounds how much unframed input may accumulate. A
	// legal frame is at most 260 bytes; this allows a modest amount of
	// pipelining without letting a peer make the proxy hold memory on its
	// behalf.
	defaultMaxBuffered = 4096
)

// Framing errors. Each is distinct so that a denial can be attributed to a
// specific check in the audit log rather than to a generic parse failure.
var (
	// ErrNeedMore is not a failure. It reports that the buffered bytes do not
	// yet contain a complete frame. Callers distinguish it with errors.Is.
	ErrNeedMore = errors.New("modbus: need more bytes")

	ErrProtocolID     = errors.New("modbus: protocol identifier is not zero")
	ErrLengthTooSmall = errors.New("modbus: length field below minimum")
	ErrLengthTooLarge = errors.New("modbus: length field above maximum")
	ErrBufferOverflow = errors.New("modbus: unframed input exceeds buffer limit")
	ErrDesynced       = errors.New("modbus: stream desynchronized, connection must be closed")
)

// Frame is one decoded MBAP frame. PDU is owned by the caller.
type Frame struct {
	TxID   uint16
	UnitID uint8
	PDU    []byte
}

// FunctionCode returns the PDU's function code. The framer guarantees a PDU of
// at least one byte, so ok is false only for a zero-valued Frame.
func (f Frame) FunctionCode() (byte, bool) {
	if len(f.PDU) == 0 {
		return 0, false
	}
	return f.PDU[0], true
}

// Marshal serializes the frame canonically.
//
// This is the half of the re-origination design that makes the smuggling class
// unreachable. The Length field is recomputed from the PDU rather than carried
// over from the input, and the protocol identifier is written as zero, so a
// frame emitted by this function can never disagree with itself. An enforcement
// path must build its egress bytes here, from fields it parsed and validated,
// and must never forward the ingress buffer.
func (f Frame) Marshal() ([]byte, error) {
	if len(f.PDU) == 0 {
		return nil, ErrLengthTooSmall
	}
	if len(f.PDU) > MaxPDU {
		return nil, ErrLengthTooLarge
	}
	out := make([]byte, HeaderLen+len(f.PDU))
	binary.BigEndian.PutUint16(out[0:2], f.TxID)
	binary.BigEndian.PutUint16(out[2:4], ProtocolID)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(f.PDU)+1))
	out[6] = f.UnitID
	copy(out[HeaderLen:], f.PDU)
	return out, nil
}

// Framer reassembles MBAP frames from a TCP byte stream in one direction.
// A Framer is not safe for concurrent use; give each direction of each
// connection its own.
type Framer struct {
	buf         []byte
	maxBuffered int
	err         error // sticky; once set the stream is unusable
}

// NewFramer returns a Framer with the default buffer bound.
func NewFramer() *Framer {
	return &Framer{maxBuffered: defaultMaxBuffered}
}

// SetMaxBuffered overrides the limit on unframed input. Values below
// MaxFrameLen are raised to it, since otherwise a legal frame could never be
// assembled.
func (f *Framer) SetMaxBuffered(n int) {
	if n < MaxFrameLen {
		n = MaxFrameLen
	}
	f.maxBuffered = n
}

// Feed appends freshly read bytes. It returns ErrBufferOverflow if the peer has
// sent more unframed data than the limit allows, which happens only if the
// caller is not draining with Next or if the peer is deliberately withholding
// the remainder of a frame.
func (f *Framer) Feed(p []byte) error {
	if f.err != nil {
		return f.err
	}
	if len(f.buf)+len(p) > f.maxBuffered {
		f.err = fmt.Errorf("%w: have %d, adding %d, limit %d",
			ErrBufferOverflow, len(f.buf), len(p), f.maxBuffered)
		return f.err
	}
	f.buf = append(f.buf, p...)
	return nil
}

// Next returns the oldest complete frame.
//
// It returns ErrNeedMore when more input is required — the normal case, not an
// error condition. Any other error is terminal: the Framer latches it and every
// later call returns it, because MBAP cannot be resynchronized. The caller must
// close the connection.
//
// Callers drain in a loop until ErrNeedMore.
func (f *Framer) Next() (Frame, error) {
	if f.err != nil {
		return Frame{}, f.err
	}
	if len(f.buf) < HeaderLen {
		return Frame{}, ErrNeedMore
	}

	proto := binary.BigEndian.Uint16(f.buf[2:4])
	if proto != ProtocolID {
		return Frame{}, f.fail(fmt.Errorf("%w: got 0x%04x", ErrProtocolID, proto))
	}

	length := int(binary.BigEndian.Uint16(f.buf[4:6]))
	switch {
	case length < MinLengthField:
		return Frame{}, f.fail(fmt.Errorf("%w: got %d, minimum %d",
			ErrLengthTooSmall, length, MinLengthField))
	case length > MaxLengthField:
		return Frame{}, f.fail(fmt.Errorf("%w: got %d, maximum %d",
			ErrLengthTooLarge, length, MaxLengthField))
	}

	// Length counts the UnitID byte, which the header already contains, so the
	// PDU is length-1 bytes beyond the header.
	total := HeaderLen + length - 1
	if len(f.buf) < total {
		return Frame{}, ErrNeedMore
	}

	fr := Frame{
		TxID:   binary.BigEndian.Uint16(f.buf[0:2]),
		UnitID: f.buf[6],
		PDU:    append([]byte(nil), f.buf[HeaderLen:total]...),
	}

	f.consume(total)
	return fr, nil
}

// Buffered reports how many bytes are held but not yet framed. A caller
// enforcing the half-open PDU timeout watches this together with the time since
// the last complete frame: a peer that sends a seven-byte header declaring 253
// bytes and then stops is holding a buffer open, and enough such peers exhaust
// the proxy.
func (f *Framer) Buffered() int { return len(f.buf) }

// Err returns the latched framing error, if any.
func (f *Framer) Err() error { return f.err }

// fail latches a terminal framing error. Both ErrDesynced and the specific
// cause are wrapped, so a caller can test for the class (tear the connection
// down) and for the reason (attribute the denial in the audit log) with the
// same error value. Wrapping the cause with %v instead would collapse every
// distinct check into one indistinguishable failure.
func (f *Framer) fail(err error) error {
	f.err = fmt.Errorf("%w: %w", ErrDesynced, err)
	f.buf = nil
	return f.err
}

func (f *Framer) consume(n int) {
	rest := len(f.buf) - n
	copy(f.buf, f.buf[n:])
	f.buf = f.buf[:rest]
}
