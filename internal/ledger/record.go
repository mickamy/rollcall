// Package ledger records which agent ran which statement, when, and to what
// effect. Records carry no statement literals and no result values: SQL is
// stored as a fingerprint, and the ledger is chained so tampering shows.
package ledger

import "github.com/mickamy/rollcall/internal/wire"

// Record is one ledger entry: one statement handled by one session.
type Record struct {
	Time        string        `json:"time"`
	Agent       string        `json:"agent,omitempty"`
	Purpose     string        `json:"purpose,omitempty"`
	User        string        `json:"user"`
	Database    string        `json:"database"`
	Application string        `json:"application,omitempty"`
	Kind        string        `json:"kind"`
	Fingerprint string        `json:"fingerprint"`
	Decision    wire.Decision `json:"decision"`
	Rows        int           `json:"rows"`
	// PrevHash and Hash chain the records; Hash covers this record and PrevHash.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}
