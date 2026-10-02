package modbus

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A device the tests can misbehave on demand.
// ---------------------------------------------------------------------------

type fakeDevice struct {
	ln net.Listener

	mu       sync.Mutex
	received []Frame

	silent   bool          // accept, read, never reply
	closeNow bool          // accept and close without reading
	hangup   bool          // read one request, then close without replying
	extra    bool          // reply, then send an unsolicited second frame
	delay    time.Duration // pause before replying
}

func newFakeDevice(t *testing.T, cfg func(*fakeDevice)) *fakeDevice {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDevice{ln: ln}
	if cfg != nil {
		cfg(d)
	}
	go d.serve()
	t.Cleanup(func() { ln.Close() })
	return d
}

func (d *fakeDevice) addr() string { return d.ln.Addr().String() }

func (d *fakeDevice) seen() []Frame {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Frame(nil), d.received...)
}

func (d *fakeDevice) serve() {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		go d.handle(c)
	}
}

func (d *fakeDevice) handle(c net.Conn) {
	defer c.Close()
	if d.closeNow {
		return
	}
	fr := NewFramer()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if fr.Feed(buf[:n]) != nil {
				return
			}
			for {
				frame, ferr := fr.Next()
				if errors.Is(ferr, ErrNeedMore) {
					break
				}
				if ferr != nil {
					return
				}
				d.mu.Lock()
				d.received = append(d.received, frame)
				d.mu.Unlock()

				if d.hangup {
					return
				}
				if d.silent {
					continue
				}
				if d.delay > 0 {
					time.Sleep(d.delay)
				}
				reply := Frame{TxID: frame.TxID, UnitID: frame.UnitID, PDU: cannedReply(frame.PDU)}
				wire, _ := reply.Marshal()
				if _, werr := c.Write(wire); werr != nil {
					return
				}
				if d.extra {
					ghost := Frame{TxID: frame.TxID + 1000, UnitID: frame.UnitID, PDU: cannedReply(frame.PDU)}
					gw, _ := ghost.Marshal()
					c.Write(gw)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func cannedReply(pdu []byte) []byte {
	if len(pdu) != 5 {
		return append([]byte(nil), pdu...)
	}
	fc := pdu[0]
	qty := int(binary.BigEndian.Uint16(pdu[3:5]))
	count := qty * 2
	if fc == 0x01 || fc == 0x02 {
		count = (qty + 7) / 8
	}
	return append([]byte{fc, byte(count)}, make([]byte, count)...)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type eventSink struct {
	mu sync.Mutex
	ev []Event
}

func (s *eventSink) add(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
}

func (s *eventSink) withReason(reason string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.ev {
		if e.Reason == reason {
			out = append(out, e)
		}
	}
	return out
}

// waitFor polls until cond holds or the deadline passes. Tests assert on
// observable behaviour rather than sleeping a guessed interval.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func startProxy(t *testing.T, target string, cfg func(*Proxy)) (string, *eventSink) {
	t.Helper()
	sink := &eventSink{}
	p := &Proxy{
		Name:        "test",
		Target:      target,
		Limits:      DefaultLimits(),
		IdleTimeout: 5 * time.Second,
		OnEvent:     sink.add,
	}
	if cfg != nil {
		cfg(p)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), sink
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func send(t *testing.T, c net.Conn, txid uint16, uid uint8, pdu []byte) {
	t.Helper()
	wire, err := (Frame{TxID: txid, UnitID: uid, PDU: pdu}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
}

func recv(c net.Conn) (Frame, error) {
	head := make([]byte, HeaderLen)
	if _, err := io.ReadFull(c, head); err != nil {
		return Frame{}, err
	}
	length := int(binary.BigEndian.Uint16(head[4:6]))
	pdu := make([]byte, length-1)
	if _, err := io.ReadFull(c, pdu); err != nil {
		return Frame{}, err
	}
	return Frame{TxID: binary.BigEndian.Uint16(head[0:2]), UnitID: head[6], PDU: pdu}, nil
}

func readHolding(start, qty uint16) []byte {
	pdu := make([]byte, 5)
	pdu[0] = 0x03
	binary.BigEndian.PutUint16(pdu[1:3], start)
	binary.BigEndian.PutUint16(pdu[3:5], qty)
	return pdu
}

// ---------------------------------------------------------------------------
// Happy path and basic enforcement through the real loop
// ---------------------------------------------------------------------------

func TestProxyRelaysPermittedRead(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, _ := startProxy(t, dev.addr(), nil)

	c := dial(t, addr)
	send(t, c, 7, 1, readHolding(0, 3))
	got, err := recv(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.TxID != 7 || got.UnitID != 1 || got.PDU[0] != 0x03 || got.PDU[1] != 6 {
		t.Errorf("response = %+v", got)
	}
	if n := len(dev.seen()); n != 1 {
		t.Errorf("device saw %d requests, want 1", n)
	}
}

func TestProxyDeniedWriteNeverReachesDevice(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, sink := startProxy(t, dev.addr(), nil)

	c := dial(t, addr)
	send(t, c, 1, 1, []byte{0x06, 0x00, 0x0A, 0xDE, 0xAD})
	got, err := recv(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.PDU[0] != 0x86 || got.PDU[1] != ExIllegalFunction {
		t.Errorf("response = % x, want 86 01", got.PDU)
	}
	if n := len(dev.seen()); n != 0 {
		t.Fatalf("device saw %d requests; the write must not have been forwarded", n)
	}

	// The session survives the denial.
	send(t, c, 2, 1, readHolding(0, 1))
	if got, err = recv(c); err != nil || got.PDU[0] != 0x03 {
		t.Errorf("session did not survive: %+v %v", got, err)
	}
	if len(sink.withReason(ReasonWrite)) != 1 {
		t.Error("no denial event recorded")
	}
}

// ---------------------------------------------------------------------------
// Failure modes of the connection itself
// ---------------------------------------------------------------------------

func TestProxyTargetDown(t *testing.T) {
	// A port nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	addr, _ := startProxy(t, dead, func(p *Proxy) { p.DialTimeout = 300 * time.Millisecond })

	c := dial(t, addr)
	send(t, c, 1, 1, readHolding(0, 1))
	if _, err := recv(c); err == nil {
		t.Error("expected the connection to close when the device is unreachable")
	}
}

// When the device drops the connection, the client must be told promptly rather
// than left waiting for its own idle timeout.
func TestProxyDeviceDisconnectsMidTransaction(t *testing.T) {
	dev := newFakeDevice(t, func(d *fakeDevice) { d.hangup = true })
	addr, _ := startProxy(t, dev.addr(), func(p *Proxy) {
		p.IdleTimeout = 30 * time.Second // must not be what rescues us
	})

	c := dial(t, addr)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	send(t, c, 1, 1, readHolding(0, 1))

	if _, err := recv(c); err == nil {
		t.Error("expected an error once the device hung up")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("client was left hanging until its own deadline rather than being closed")
	}
}

func TestProxyIdleTimeout(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, _ := startProxy(t, dev.addr(), func(p *Proxy) {
		p.IdleTimeout = 150 * time.Millisecond
	})

	c := dial(t, addr)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := recv(c); err == nil {
		t.Error("expected the idle connection to be closed")
	}
}

// ---------------------------------------------------------------------------
// Resource bounds
// ---------------------------------------------------------------------------

// The Modbus shape of a slowloris: a header declaring a PDU, then silence. The
// idle timeout does not cover it, because bytes did arrive.
func TestProxyHalfOpenPDUTimeout(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, sink := startProxy(t, dev.addr(), func(p *Proxy) {
		p.IdleTimeout = 30 * time.Second // deliberately far longer
		p.HalfOpenTimeout = 150 * time.Millisecond
	})

	c := dial(t, addr)
	c.SetDeadline(time.Now().Add(3 * time.Second))

	// Seven bytes of header declaring 253 more, and nothing else ever.
	head := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(head[0:2], 1)
	binary.BigEndian.PutUint16(head[4:6], uint16(MaxLengthField))
	head[6] = 1
	if _, err := c.Write(head); err != nil {
		t.Fatal(err)
	}

	if _, err := recv(c); err == nil {
		t.Error("expected the half-open connection to be closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("connection was not closed; the half-open timeout did not fire")
	}
	if !waitFor(time.Second, func() bool { return len(sink.withReason(ReasonHalfOpenPDU)) == 1 }) {
		t.Error("no half-open timeout event recorded")
	}
}

// A well-behaved client that happens to split a frame across segments must not
// be caught by the half-open timeout.
func TestProxySlowButCompleteFrameIsFine(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, sink := startProxy(t, dev.addr(), func(p *Proxy) {
		p.HalfOpenTimeout = 400 * time.Millisecond
	})

	c := dial(t, addr)
	wire, _ := (Frame{TxID: 1, UnitID: 1, PDU: readHolding(0, 1)}).Marshal()
	for _, piece := range [][]byte{wire[:7], wire[7:8], wire[8:]} {
		if _, err := c.Write(piece); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	got, err := recv(c)
	if err != nil {
		t.Fatalf("a slow but complete frame was refused: %v", err)
	}
	if got.PDU[0] != 0x03 {
		t.Errorf("response = % x", got.PDU)
	}
	if n := len(sink.withReason(ReasonHalfOpenPDU)); n != 0 {
		t.Errorf("half-open timeout fired %d times on a legitimate client", n)
	}
}

func TestProxyMaxOutstanding(t *testing.T) {
	dev := newFakeDevice(t, func(d *fakeDevice) { d.silent = true })
	addr, _ := startProxy(t, dev.addr(), func(p *Proxy) { p.MaxOutstanding = 2 })

	c := dial(t, addr)
	for i := uint16(1); i <= 4; i++ {
		send(t, c, i, 1, readHolding(0, 1))
	}
	// The first two are forwarded to a device that never answers; the rest are
	// refused with Server Device Busy rather than held.
	for i := 0; i < 2; i++ {
		got, err := recv(c)
		if err != nil {
			t.Fatal(err)
		}
		if got.PDU[0] != 0x83 || got.PDU[1] != ExServerDeviceBusy {
			t.Errorf("response %d = % x, want 83 06", i, got.PDU)
		}
	}
	if !waitFor(time.Second, func() bool { return len(dev.seen()) == 2 }) {
		t.Errorf("device saw %d requests, want exactly the 2 within the limit", len(dev.seen()))
	}
}

func TestProxyMaxConnsPerSource(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, sink := startProxy(t, dev.addr(), func(p *Proxy) { p.MaxConnsPerSource = 2 })

	var keep []net.Conn
	for i := 0; i < 2; i++ {
		c := dial(t, addr)
		send(t, c, uint16(i), 1, readHolding(0, 1))
		if _, err := recv(c); err != nil {
			t.Fatalf("connection %d should have been admitted: %v", i, err)
		}
		keep = append(keep, c)
	}

	third, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	third.SetDeadline(time.Now().Add(2 * time.Second))
	third.Write([]byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1})
	if _, err := recv(third); err == nil {
		t.Error("the third connection should have been refused")
	}
	if !waitFor(time.Second, func() bool { return len(sink.withReason(ReasonTooManyConns)) >= 1 }) {
		t.Error("no refusal event recorded")
	}

	// Closing one frees a slot.
	keep[0].Close()
	if !waitFor(2*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte{0, 9, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1})
		_, err = recv(c)
		return err == nil
	}) {
		t.Error("a slot was not freed when a connection closed")
	}
}

// ---------------------------------------------------------------------------
// Policy applied through the loop
// ---------------------------------------------------------------------------

func TestProxyRefusesUnlistedSource(t *testing.T) {
	dev := newFakeDevice(t, nil)
	doc := `{"version":1,"sources":["10.0.0.0/8"],"targets":[
	  {"name":"x","listen":"127.0.0.1:1","address":"127.0.0.1:2",
	   "units":[{"id":1,"rules":[{"fc":[3],"start":0,"count":10}]}]}]}`
	pol := mustPolicy(t, doc)
	tp, _ := pol.Target("x")

	addr, sink := startProxy(t, dev.addr(), func(p *Proxy) { p.Rules = tp })

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1})
	if _, err := recv(c); err == nil {
		t.Error("a source outside the policy should never get to send a PDU")
	}
	if !waitFor(time.Second, func() bool { return len(sink.withReason(ReasonSourceNotAllowed)) == 1 }) {
		t.Error("no source refusal recorded")
	}
	if n := len(dev.seen()); n != 0 {
		t.Errorf("device saw %d requests from a refused source", n)
	}
}

func TestProxyAppliesAddressRules(t *testing.T) {
	dev := newFakeDevice(t, nil)
	tp, _ := mustPolicy(t, minimalPolicy).Target("line3")
	addr, _ := startProxy(t, dev.addr(), func(p *Proxy) { p.Rules = tp })

	c := dial(t, addr)
	send(t, c, 1, 1, readHolding(0, 1))
	if got, err := recv(c); err != nil || got.PDU[0] != 0x03 {
		t.Errorf("in-window read refused: %+v %v", got, err)
	}
	send(t, c, 2, 1, readHolding(100, 1))
	got, err := recv(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.PDU[0] != 0x83 || got.PDU[1] != ExIllegalDataAddress {
		t.Errorf("out-of-window read = % x, want 83 02", got.PDU)
	}
	if n := len(dev.seen()); n != 1 {
		t.Errorf("device saw %d requests, want only the permitted one", n)
	}
}

// ---------------------------------------------------------------------------
// Response side and concurrency
// ---------------------------------------------------------------------------

func TestProxyDropsUnsolicitedResponse(t *testing.T) {
	dev := newFakeDevice(t, func(d *fakeDevice) { d.extra = true })
	addr, sink := startProxy(t, dev.addr(), nil)

	c := dial(t, addr)
	send(t, c, 5, 1, readHolding(0, 1))
	got, err := recv(c)
	if err != nil || got.TxID != 5 {
		t.Fatalf("solicited response not relayed: %+v %v", got, err)
	}

	// The ghost must not arrive. Give it a window, then confirm the next real
	// exchange is the next thing on the wire.
	time.Sleep(200 * time.Millisecond)
	send(t, c, 6, 1, readHolding(0, 1))
	got, err = recv(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.TxID != 6 {
		t.Errorf("got txid %d, so an unsolicited frame reached the client", got.TxID)
	}
	if len(sink.withReason(ReasonRespUnsolicited)) == 0 {
		t.Error("unsolicited response was not recorded")
	}
}

func TestProxyConcurrentClients(t *testing.T) {
	dev := newFakeDevice(t, nil)
	addr, _ := startProxy(t, dev.addr(), nil)

	const clients, each = 8, 20
	var wg sync.WaitGroup
	errs := make(chan error, clients*each)

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			for j := 0; j < each; j++ {
				tx := uint16(id*1000 + j)
				wire, _ := (Frame{TxID: tx, UnitID: 1, PDU: readHolding(0, 2)}).Marshal()
				if _, err := c.Write(wire); err != nil {
					errs <- err
					return
				}
				got, err := recv(c)
				if err != nil {
					errs <- err
					return
				}
				if got.TxID != tx || got.PDU[0] != 0x03 || got.PDU[1] != 4 {
					errs <- errors.New("crossed or malformed response")
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent client: %v", err)
	}
	if n := len(dev.seen()); n != clients*each {
		t.Errorf("device saw %d requests, want %d", n, clients*each)
	}
}
