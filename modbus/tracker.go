package modbus

import (
	"sync"
	"time"
)

// DefaultMaxOutstanding bounds how many requests may be in flight on one
// connection. The specification places no limit; this one exists so that a
// client cannot make the proxy hold state on its behalf indefinitely.
const DefaultMaxOutstanding = 16

// DefaultPendingTTL is how long an unanswered request is remembered. A device
// that never replies would otherwise leak an entry per request.
const DefaultPendingTTL = 30 * time.Second

type pendingReq struct {
	txid   uint16
	unitID uint8
	req    Request
	at     time.Time
}

// Tracker correlates responses with the requests that produced them.
//
// It is keyed on (transaction id, unit id) rather than transaction id alone,
// because a unit id selects a different physical device behind a gateway and a
// reply from the wrong one is not an answer to this request.
//
// Duplicate keys are expected, not exceptional: the specification does not
// require transaction identifiers to be unique, non-zero or monotonic, and real
// clients reuse them. Each key therefore holds a FIFO queue and a response
// retires the oldest entry — which is the best correlation the protocol
// actually supports. A tracker keyed on a uniqueness assumption the wire does
// not guarantee is a state-corruption bug waiting for a badly behaved client.
type Tracker struct {
	mu      sync.Mutex
	pending map[uint32][]pendingReq
	count   int
	max     int
	ttl     time.Duration
}

func NewTracker(max int, ttl time.Duration) *Tracker {
	if max <= 0 {
		max = DefaultMaxOutstanding
	}
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	return &Tracker{pending: make(map[uint32][]pendingReq), max: max, ttl: ttl}
}

func key(txid uint16, unitID uint8) uint32 {
	return uint32(txid)<<8 | uint32(unitID)
}

// Add records a forwarded request. It reports false when the connection already
// has the maximum number of requests in flight, which the caller answers with
// exception 0x06 rather than by forwarding.
func (t *Tracker) Add(txid uint16, unitID uint8, req Request, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.expireLocked(now)
	if t.count >= t.max {
		return false
	}
	k := key(txid, unitID)
	t.pending[k] = append(t.pending[k], pendingReq{txid: txid, unitID: unitID, req: req, at: now})
	t.count++
	return true
}

// Take retires and returns the oldest outstanding request for this key. The
// second result is false for a response nothing asked for.
func (t *Tracker) Take(txid uint16, unitID uint8, now time.Time) (Request, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.expireLocked(now)
	k := key(txid, unitID)
	q := t.pending[k]
	if len(q) == 0 {
		return nil, false
	}
	head := q[0]
	if len(q) == 1 {
		delete(t.pending, k)
	} else {
		t.pending[k] = q[1:]
	}
	t.count--
	return head.req, true
}

// Outstanding reports how many requests are in flight.
func (t *Tracker) Outstanding() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

// Expire drops entries older than the TTL and returns how many were dropped.
func (t *Tracker) Expire(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.expireLocked(now)
}

func (t *Tracker) expireLocked(now time.Time) int {
	if t.count == 0 {
		return 0
	}
	dropped := 0
	cutoff := now.Add(-t.ttl)
	for k, q := range t.pending {
		// Entries within a key are appended in time order, so the survivors are
		// a suffix of the queue.
		i := 0
		for i < len(q) && q[i].at.Before(cutoff) {
			i++
		}
		if i == 0 {
			continue
		}
		dropped += i
		t.count -= i
		if i == len(q) {
			delete(t.pending, k)
		} else {
			t.pending[k] = q[i:]
		}
	}
	return dropped
}
