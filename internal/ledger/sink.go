package ledger

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"log/slog"
	"sync"
)

// Sink appends records as JSON lines, chaining each record's hash to the
// previous so the log is tamper-evident. Records are queued to a single writer
// goroutine and never dropped, so disk latency does not block a session's
// response path until the queue fills, after which Write blocks (backpressure)
// rather than dropping a record.
type Sink struct {
	ch     chan Record
	done   chan struct{}
	w      writer
	key    []byte
	keyID  string
	logger *slog.Logger

	mu   sync.Mutex
	prev string
}

type writer interface {
	Write(p []byte) (int, error)
}

// Options configure a Sink.
type Options struct {
	// Prev is the hash of the last record already in the output, so appending
	// across restarts keeps one unbroken chain. Empty starts a new chain.
	Prev string
	// Key, when set, makes the chain an HMAC so it cannot be recomputed without
	// the key. Empty falls back to a plain SHA-256 chain.
	Key    []byte
	Logger *slog.Logger
}

const queueDepth = 1024

// NewSink writes records to w and starts its writer goroutine. Close it to flush.
func NewSink(w writer, opts Options) *Sink {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	s := &Sink{
		ch:     make(chan Record, queueDepth),
		done:   make(chan struct{}),
		w:      w,
		key:    opts.Key,
		keyID:  keyID(opts.Key),
		logger: logger,
		prev:   opts.Prev,
	}
	go s.run()

	return s
}

// Write queues one record. It returns at once; the writer goroutine chains and
// appends it. Records are chained in the order Write is called.
func (s *Sink) Write(rec Record) {
	s.ch <- rec
}

// Close stops accepting records and waits for the queue to drain.
func (s *Sink) Close() {
	close(s.ch)
	<-s.done
}

// LastHash reports the hash of the most recently written record, for a caller
// that wants to seed a later Sink. Safe to call after Close.
func (s *Sink) LastHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.prev
}

func (s *Sink) run() {
	defer close(s.done)

	for rec := range s.ch {
		rec.KeyID = s.keyID
		rec.PrevHash = s.prev
		rec.Hash = s.hashRecord(rec)

		line, err := json.Marshal(rec)
		if err != nil {
			s.logger.Error("ledger marshal", "error", err)

			continue
		}
		if _, err := s.w.Write(append(line, '\n')); err != nil {
			s.logger.Error("ledger write", "error", err)

			continue
		}

		s.setPrev(rec.Hash)
	}
}

// keyID is a short, non-reversible name for a chain key: a prefix of its hash,
// or empty when unkeyed.
func keyID(key []byte) string {
	if len(key) == 0 {
		return ""
	}

	sum := sha256.Sum256(key)

	return hex.EncodeToString(sum[:6])
}

// hashRecord hashes the record with its Hash field cleared, so the chain covers
// order and content. With a key it is an HMAC; without, a plain SHA-256.
func (s *Sink) hashRecord(rec Record) string {
	rec.Hash = ""
	data, err := json.Marshal(rec)
	if err != nil {
		return ""
	}

	var h hash.Hash
	if len(s.key) > 0 {
		h = hmac.New(sha256.New, s.key)
	} else {
		h = sha256.New()
	}
	_, _ = h.Write(data)

	return hex.EncodeToString(h.Sum(nil))
}

func (s *Sink) setPrev(h string) {
	s.mu.Lock()
	s.prev = h
	s.mu.Unlock()
}
