package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Sink appends records to an output as JSON lines, chaining each record's hash
// to the previous so the log is tamper-evident. It is safe for concurrent use.
type Sink struct {
	mu   sync.Mutex
	w    io.Writer
	prev string
}

// NewSink writes records to w.
func NewSink(w io.Writer) *Sink {
	return &Sink{w: w}
}

// Write chains and appends one record. It fills in PrevHash and Hash.
func (s *Sink) Write(rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec.PrevHash = s.prev
	rec.Hash = hashRecord(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	if _, err := s.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write record: %w", err)
	}

	s.prev = rec.Hash

	return nil
}

// hashRecord hashes the record with its Hash field cleared, over PrevHash, so
// the chain covers order and content.
func hashRecord(rec Record) string {
	rec.Hash = ""
	data, err := json.Marshal(rec)
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}
