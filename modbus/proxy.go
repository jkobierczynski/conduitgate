package modbus

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Direction of a decision, for the audit trail.
const (
	DirRequest  = "request"
	DirResponse = "response"
)

// Event is one decision, emitted for the audit trail.
type Event struct {
	// Target names the proxy that made the decision. With several listeners
	// running from one policy, a log line without it is ambiguous.
	Target  string
	Dir     string
	Remote  string
	TxID    uint16
	UnitID  uint8
	FC      byte
	Name    string
	Allowed bool
	Reason  string
	Detail  string
}

// Proxy is a strictly one-to-one Modbus/TCP enforcement proxy: each accepted
// client connection opens exactly one connection to the target.
//
// One-to-one is a deliberate v1 constraint. Multiplexing several clients onto
// one target connection — which real deployments want, because many PLCs accept
// only two or three connections — requires rewriting transaction identifiers
// and keeping a correlation table keyed on a field the specification does not
// require to be unique, non-zero or monotonic. That is a large class of bug for
// a feature nobody has asked for yet.
//
// Both directions are enforced. The request path decides what may reach the
// device; the response path decides what may reach the client. Validating only
// the first would leave the engineering workstation — an asset in its own right
// — exposed to whatever the device chooses to send back.
type Proxy struct {
	// Name identifies this proxy in the audit trail; Policy.NewProxy sets it
	// from the target's name.
	Name string

	Target      string
	Limits      Limits
	DialTimeout time.Duration
	IdleTimeout time.Duration

	// MaxOutstanding bounds in-flight requests per connection; zero means
	// DefaultMaxOutstanding. PendingTTL is how long an unanswered request is
	// remembered; zero means DefaultPendingTTL.
	MaxOutstanding int
	PendingTTL     time.Duration

	// MaxConnsPerSource bounds concurrent connections from one address; zero
	// means unbounded.
	MaxConnsPerSource int

	// HalfOpenTimeout bounds how long a client may hold an incomplete frame.
	// Zero means DefaultHalfOpenTimeout; a negative value disables the check.
	//
	// This is separate from, and much shorter than, IdleTimeout. A peer that
	// sends a header declaring 253 bytes and then stops is not idle — bytes
	// arrived, just never enough to decide anything about — so the idle timeout
	// does not cover it.
	HalfOpenTimeout time.Duration

	// Rules is this target's scoping. When nil the proxy applies Limits
	// globally with no scoping, which is the bench posture, not a deployment
	// one: every unit id is reachable and every address is in range.
	Rules *TargetPolicy

	OnEvent  func(Event)
	FailOpen bool // never set this without a documented reason

	mu    sync.Mutex
	conns map[string]int // live connections per source address
}

// Serve accepts connections until the listener is closed.
//
// Admission happens before anything is read from the socket: a client the
// policy does not list never gets the chance to send a PDU, and a client that
// has already opened its allowance of connections is refused rather than
// queued. Both are cheaper than deciding later and both are properly a firewall
// function rather than a protocol one.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if !p.admit(c) {
			c.Close()
			continue
		}
		go func() {
			defer p.release(c)
			defer c.Close()
			_ = p.handle(c)
		}()
	}
}

func sourceIP(c net.Conn) (net.IP, string) {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		host = c.RemoteAddr().String()
	}
	return net.ParseIP(host), host
}

func (p *Proxy) admit(c net.Conn) bool {
	ip, host := sourceIP(c)
	remote := c.RemoteAddr().String()

	if p.Rules != nil && (ip == nil || !p.Rules.AllowSource(ip)) {
		p.emit(Event{Dir: DirRequest, Remote: remote, Allowed: false,
			Reason: ReasonSourceNotAllowed,
			Detail: "source address is not listed for this target"})
		return false
	}

	// Decide under the lock, report outside it: OnEvent is caller-supplied and
	// must never be invoked while holding proxy state.
	p.mu.Lock()
	if p.conns == nil {
		p.conns = make(map[string]int)
	}
	over := p.MaxConnsPerSource > 0 && p.conns[host] >= p.MaxConnsPerSource
	if !over {
		p.conns[host]++
	}
	p.mu.Unlock()

	if over {
		p.emit(Event{Dir: DirRequest, Remote: remote, Allowed: false,
			Reason: ReasonTooManyConns,
			Detail: fmt.Sprintf("source already holds %d connections, the configured maximum",
				p.MaxConnsPerSource)})
		return false
	}
	return true
}

func (p *Proxy) release(c net.Conn) {
	_, host := sourceIP(c)
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := p.conns[host]; n <= 1 {
		delete(p.conns, host)
	} else {
		p.conns[host] = n - 1
	}
}

func (p *Proxy) handle(client net.Conn) error {
	dialTimeout := p.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second
	}
	server, err := net.DialTimeout("tcp", p.Target, dialTimeout)
	if err != nil {
		return err
	}
	defer server.Close()

	// Both directions may write to the client: responses relayed from the
	// target, and exception responses this proxy synthesizes.
	var clientWrite sync.Mutex
	writeClient := func(b []byte) error {
		clientWrite.Lock()
		defer clientWrite.Unlock()
		_, err := client.Write(b)
		return err
	}

	tracker := NewTracker(p.MaxOutstanding, p.PendingTTL)
	remote := client.RemoteAddr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Closing the client when the response side ends is what tells a
		// waiting client that the device is gone. Without it the request
		// goroutine stays blocked on its read until the idle timeout, so a PLC
		// dropping the connection looks to the client like a very slow reply
		// rather than a fault — minutes of silence instead of an immediate
		// close. Found by TestProxyDeviceDisconnectsMidTransaction.
		defer client.Close()
		p.filterResponses(server, remote, tracker, writeClient)
	}()

	err = p.filterRequests(client, server, remote, tracker, writeClient)
	server.Close()
	<-done
	return err
}

// filterRequests decides what may reach the device.
func (p *Proxy) filterRequests(client, server net.Conn, remote string,
	tracker *Tracker, writeClient func([]byte) error) error {

	fr := NewFramer()
	buf := make([]byte, 4096)

	halfOpen := p.HalfOpenTimeout
	if halfOpen == 0 {
		halfOpen = DefaultHalfOpenTimeout
	}

	// partialSince is when the framer first held an incomplete frame, reset
	// every time the buffer drains.
	var partialSince time.Time

	for {
		// The read deadline is the earlier of the idle deadline and the
		// half-open deadline. Without folding the latter in, a peer holding an
		// incomplete frame would simply block here until the idle timeout,
		// which is the whole problem.
		deadline := time.Time{}
		if p.IdleTimeout > 0 {
			deadline = time.Now().Add(p.IdleTimeout)
		}
		if !partialSince.IsZero() && halfOpen > 0 {
			if d := partialSince.Add(halfOpen); deadline.IsZero() || d.Before(deadline) {
				deadline = d
			}
		}
		_ = client.SetReadDeadline(deadline)

		n, err := client.Read(buf)
		if n > 0 {
			if ferr := fr.Feed(buf[:n]); ferr != nil {
				p.emit(Event{Dir: DirRequest, Remote: remote, Allowed: false,
					Reason: ReasonMalformed, Detail: ferr.Error()})
				return ferr
			}
			for {
				frame, ferr := fr.Next()
				if errors.Is(ferr, ErrNeedMore) {
					break
				}
				if ferr != nil {
					// Framing failure is terminal: MBAP cannot be resynchronized.
					p.emit(Event{Dir: DirRequest, Remote: remote, Allowed: false,
						Reason: ReasonMalformed, Detail: ferr.Error()})
					return ferr
				}
				if derr := p.decideRequest(frame, remote, server, tracker, writeClient); derr != nil {
					return derr
				}
			}

			if fr.Buffered() > 0 {
				if partialSince.IsZero() {
					partialSince = time.Now()
				}
			} else {
				partialSince = time.Time{}
			}
		}

		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() &&
				!partialSince.IsZero() && halfOpen > 0 &&
				time.Since(partialSince) >= halfOpen {
				p.emit(Event{Dir: DirRequest, Remote: remote, Allowed: false,
					Reason: ReasonHalfOpenPDU,
					Detail: fmt.Sprintf("held %d bytes of an incomplete frame for %s without completing it",
						fr.Buffered(), halfOpen)})
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (p *Proxy) decideRequest(frame Frame, remote string, server net.Conn,
	tracker *Tracker, writeClient func([]byte) error) error {

	fc, _ := frame.FunctionCode()

	// The unit id decides which rules apply, so it is resolved before the PDU
	// is decoded: behind a gateway it selects different physical hardware, and
	// a unit the policy does not list is not a device this proxy fronts.
	lim := p.Limits
	var unit *UnitPolicy
	if p.Rules != nil {
		u, ok := p.Rules.Unit(frame.UnitID)
		if !ok {
			d := deny(fc, ReasonUnitNotAllowed,
				fmt.Sprintf("unit id %d is not listed for this target", frame.UnitID),
				ExIllegalFunction)
			p.emitDenial(DirRequest, remote, frame, fc, d)
			return p.answerClient(frame, fc, d.Exception, writeClient)
		}
		unit, lim = u, u.Limits()
	}

	req, denial := DecodeRequest(frame.PDU, lim)
	if denial == nil && unit != nil {
		denial = unit.Check(req)
	}
	if denial != nil {
		p.emitDenial(DirRequest, remote, frame, fc, denial)
		if p.FailOpen {
			// Present only so that the failure mode is a visible configuration
			// choice rather than an accident of implementation.
			out, err := frame.Marshal()
			if err != nil {
				return err
			}
			_, err = server.Write(out)
			return err
		}
		return p.answerClient(frame, fc, denial.Exception, writeClient)
	}

	// Record the request before forwarding, so a response cannot arrive before
	// there is anything to correlate it with.
	if !tracker.Add(frame.TxID, frame.UnitID, req, time.Now()) {
		d := deny(fc, ReasonTooManyOutstanding,
			"connection already has the maximum number of requests in flight",
			ExServerDeviceBusy)
		p.emitDenial(DirRequest, remote, frame, fc, d)
		return p.answerClient(frame, fc, d.Exception, writeClient)
	}

	p.emit(Event{Dir: DirRequest, Remote: remote, TxID: frame.TxID, UnitID: frame.UnitID,
		FC: fc, Name: Name(fc), Allowed: true})

	// Forward bytes built from the parsed fields, never the bytes received.
	out := Frame{TxID: frame.TxID, UnitID: frame.UnitID, PDU: req.Encode()}
	wire, err := out.Marshal()
	if err != nil {
		return err
	}
	_, err = server.Write(wire)
	return err
}

// filterResponses decides what may reach the client.
//
// A refused response does not tear the connection down. Framing is driven by
// the MBAP length, not by PDU content, so the stream stays synchronized even
// when a PDU is rejected; the client gets exception 0x04 for that transaction
// and the session continues.
func (p *Proxy) filterResponses(server net.Conn, remote string,
	tracker *Tracker, writeClient func([]byte) error) {

	fr := NewFramer()
	buf := make([]byte, 4096)

	for {
		n, err := server.Read(buf)
		if n > 0 {
			if ferr := fr.Feed(buf[:n]); ferr != nil {
				p.emit(Event{Dir: DirResponse, Remote: remote, Allowed: false,
					Reason: ReasonRespMalformed, Detail: ferr.Error()})
				return
			}
			for {
				frame, ferr := fr.Next()
				if errors.Is(ferr, ErrNeedMore) {
					break
				}
				if ferr != nil {
					p.emit(Event{Dir: DirResponse, Remote: remote, Allowed: false,
						Reason: ReasonRespMalformed, Detail: ferr.Error()})
					return
				}
				if werr := p.decideResponse(frame, remote, tracker, writeClient); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *Proxy) decideResponse(frame Frame, remote string,
	tracker *Tracker, writeClient func([]byte) error) error {

	fc, _ := frame.FunctionCode()

	req, ok := tracker.Take(frame.TxID, frame.UnitID, time.Now())
	if !ok {
		// Nothing asked for this. It cannot be relayed — the client has no
		// transaction to attach it to — and it is not attributable enough to
		// answer, so it is dropped and recorded.
		p.emit(Event{Dir: DirResponse, Remote: remote, TxID: frame.TxID, UnitID: frame.UnitID,
			FC: fc, Name: Name(fc), Allowed: false, Reason: ReasonRespUnsolicited,
			Detail: "no outstanding request with this transaction and unit id"})
		return nil
	}

	lim := p.Limits
	if p.Rules != nil {
		if u, ok := p.Rules.Unit(frame.UnitID); ok {
			lim = u.Limits()
		}
	}
	resp, denial := DecodeResponse(frame.PDU, req, lim)
	if denial != nil {
		p.emitDenial(DirResponse, remote, frame, req.FunctionCode(), denial)
		if p.FailOpen {
			wire, err := frame.Marshal()
			if err != nil {
				return err
			}
			return writeClient(wire)
		}
		// The client is waiting on this transaction; leaving it to time out
		// would be indistinguishable from a network fault.
		return p.answerClient(frame, req.FunctionCode(), denial.Exception, writeClient)
	}

	p.emit(Event{Dir: DirResponse, Remote: remote, TxID: frame.TxID, UnitID: frame.UnitID,
		FC: fc, Name: Name(req.FunctionCode()), Allowed: true})

	out := Frame{TxID: frame.TxID, UnitID: frame.UnitID, PDU: resp.Encode()}
	wire, err := out.Marshal()
	if err != nil {
		return err
	}
	return writeClient(wire)
}

// answerClient sends a well-formed exception for the transaction in question.
func (p *Proxy) answerClient(frame Frame, fc, exception byte, writeClient func([]byte) error) error {
	resp := Frame{TxID: frame.TxID, UnitID: frame.UnitID, PDU: ExceptionPDU(fc, exception)}
	wire, err := resp.Marshal()
	if err != nil {
		return err
	}
	return writeClient(wire)
}

func (p *Proxy) emitDenial(dir, remote string, frame Frame, fc byte, d *Denial) {
	p.emit(Event{
		Dir: dir, Remote: remote, TxID: frame.TxID, UnitID: frame.UnitID,
		FC: fc, Name: Name(fc), Allowed: false,
		Reason: d.Reason, Detail: d.Detail,
	})
}

func (p *Proxy) emit(e Event) {
	if p.OnEvent != nil {
		e.Target = p.Name
		p.OnEvent(e)
	}
}
