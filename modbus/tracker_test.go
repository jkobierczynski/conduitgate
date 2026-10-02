package modbus

import (
	"testing"
	"time"
)

var probe = ReadRequest{FC: 0x03, Start: 0, Quantity: 1}

func TestTrackerBasicCorrelation(t *testing.T) {
	now := time.Now()
	tr := NewTracker(4, time.Minute)

	if !tr.Add(7, 1, probe, now) {
		t.Fatal("Add rejected the first request")
	}
	if tr.Outstanding() != 1 {
		t.Errorf("outstanding = %d, want 1", tr.Outstanding())
	}
	if _, ok := tr.Take(7, 1, now); !ok {
		t.Fatal("Take missed the request it was given")
	}
	if tr.Outstanding() != 0 {
		t.Errorf("outstanding = %d, want 0", tr.Outstanding())
	}
	// Taking twice must not succeed: a second response for one request is
	// unsolicited.
	if _, ok := tr.Take(7, 1, now); ok {
		t.Error("Take succeeded twice for one request")
	}
}

// The specification does not require transaction identifiers to be unique, and
// real clients reuse them. Duplicates must queue, not collide.
func TestTrackerDuplicateTransactionIDs(t *testing.T) {
	now := time.Now()
	tr := NewTracker(8, time.Minute)

	first := ReadRequest{FC: 0x03, Start: 100, Quantity: 1}
	second := ReadRequest{FC: 0x04, Start: 200, Quantity: 2}
	tr.Add(0, 1, first, now)
	tr.Add(0, 1, second, now.Add(time.Millisecond))

	got, ok := tr.Take(0, 1, now)
	if !ok || got.(ReadRequest).Start != 100 {
		t.Fatalf("first Take = %#v, want the oldest entry", got)
	}
	got, ok = tr.Take(0, 1, now)
	if !ok || got.(ReadRequest).Start != 200 {
		t.Fatalf("second Take = %#v, want the newer entry", got)
	}
	if tr.Outstanding() != 0 {
		t.Errorf("outstanding = %d, want 0", tr.Outstanding())
	}
}

// A unit id selects a different physical device behind a gateway, so a reply
// carrying the wrong one is not an answer to this request.
func TestTrackerDiscriminatesUnitID(t *testing.T) {
	now := time.Now()
	tr := NewTracker(4, time.Minute)
	tr.Add(5, 1, probe, now)

	if _, ok := tr.Take(5, 2, now); ok {
		t.Error("a response for unit 2 matched a request to unit 1")
	}
	if _, ok := tr.Take(5, 1, now); !ok {
		t.Error("the correct unit id failed to match")
	}
}

func TestTrackerOutstandingLimit(t *testing.T) {
	now := time.Now()
	tr := NewTracker(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !tr.Add(uint16(i), 1, probe, now) {
			t.Fatalf("Add %d rejected below the limit", i)
		}
	}
	if tr.Add(99, 1, probe, now) {
		t.Error("Add succeeded past the limit")
	}
	// Retiring one makes room again.
	tr.Take(0, 1, now)
	if !tr.Add(99, 1, probe, now) {
		t.Error("Add failed after a slot was freed")
	}
}

// A device that never answers must not leak an entry per request.
func TestTrackerExpiry(t *testing.T) {
	start := time.Now()
	tr := NewTracker(8, 10*time.Second)

	tr.Add(1, 1, probe, start)
	tr.Add(2, 1, probe, start.Add(5*time.Second))

	// At +12s the first has aged out and the second has not.
	if dropped := tr.Expire(start.Add(12 * time.Second)); dropped != 1 {
		t.Errorf("dropped %d entries, want 1", dropped)
	}
	if tr.Outstanding() != 1 {
		t.Errorf("outstanding = %d, want 1", tr.Outstanding())
	}
	if _, ok := tr.Take(1, 1, start.Add(12*time.Second)); ok {
		t.Error("an expired request still matched")
	}
	if _, ok := tr.Take(2, 1, start.Add(12*time.Second)); !ok {
		t.Error("a live request was expired early")
	}
}

func TestTrackerExpiryFreesCapacity(t *testing.T) {
	start := time.Now()
	tr := NewTracker(2, 10*time.Second)
	tr.Add(1, 1, probe, start)
	tr.Add(2, 1, probe, start)

	if tr.Add(3, 1, probe, start) {
		t.Fatal("Add succeeded past the limit")
	}
	// Adding later sweeps the aged entries first.
	if !tr.Add(3, 1, probe, start.Add(time.Minute)) {
		t.Error("Add failed after the old entries should have expired")
	}
}

func TestTrackerDefaults(t *testing.T) {
	tr := NewTracker(0, 0)
	now := time.Now()
	for i := 0; i < DefaultMaxOutstanding; i++ {
		if !tr.Add(uint16(i), 1, probe, now) {
			t.Fatalf("Add %d rejected below the default limit", i)
		}
	}
	if tr.Add(1000, 1, probe, now) {
		t.Error("default limit not applied")
	}
}
