package ledger

import (
	"strings"

	"github.com/mickamy/rollcall/internal/sqlscan"
	"github.com/mickamy/rollcall/internal/wire"
)

// Guard wraps another guard, recording each session's statements to Sink.
type Guard struct {
	Inner wire.Guard
	Sink  *Sink
}

var _ wire.Guard = Guard{}

func (g Guard) Resolve(startup wire.Startup) wire.Enforcement {
	enf := g.Inner.Resolve(startup)
	enf.Recorder = recorder{principal: enf.Principal, sink: g.Sink}

	return enf
}

// now is overridable in tests; the ledger stamps records with the wall clock.
var now = defaultNow

// statementKind names the kinds in sql. A single statement gives its kind; a
// multi-statement query lists each distinct kind in order, so a
// "SELECT 1; DELETE FROM t" is not recorded as a plain SELECT.
func statementKind(sql string) string {
	kinds := sqlscan.Classify(sql)
	if len(kinds) == 0 {
		return sqlscan.Empty.String()
	}

	seen := make(map[string]bool, len(kinds))
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		if k == sqlscan.Empty {
			continue
		}
		name := k.String()
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return sqlscan.Empty.String()
	}

	return strings.Join(names, ", ")
}

type recorder struct {
	principal wire.Principal
	sink      *Sink
}

var _ wire.Recorder = recorder{}

func (r recorder) Begin(sql string, decision wire.Decision) wire.Result {
	kind := statementKind(sql)

	rec := Record{
		Time:        now(),
		Agent:       r.principal.Agent,
		Purpose:     r.principal.Purpose,
		User:        r.principal.User,
		Database:    r.principal.Database,
		Application: r.principal.Application,
		Kind:        kind,
		Fingerprint: sqlscan.Fingerprint(sql),
		Decision:    decision,
	}

	return &result{rec: rec, sink: r.sink}
}

// result accumulates a statement's outcome and writes the record when the
// statement finishes.
type result struct {
	rec  Record
	sink *Sink
	done bool
}

var _ wire.Result = (*result)(nil)

// Columns captures nothing yet; subject extraction is a later step.
func (result) Columns([]string) []int {
	return nil
}

func (result) Row([][]byte) {}

func (r *result) Complete(tag string) {
	r.rec.Rows += rowsFromTag(tag)
}

func (r *result) Done() {
	if r.done {
		return
	}
	r.done = true

	r.sink.Write(r.rec)
}
