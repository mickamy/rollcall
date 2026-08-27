package ledger

import (
	"log/slog"

	"github.com/mickamy/rollcall/internal/sqlscan"
	"github.com/mickamy/rollcall/internal/wire"
)

// Guard wraps another guard, recording each session's statements to Sink.
type Guard struct {
	Inner  wire.Guard
	Sink   *Sink
	Logger *slog.Logger
}

var _ wire.Guard = Guard{}

func (g Guard) Resolve(startup wire.Startup) wire.Enforcement {
	enf := g.Inner.Resolve(startup)
	enf.Recorder = recorder{principal: enf.Principal, sink: g.Sink, logger: g.logger()}

	return enf
}

func (g Guard) logger() *slog.Logger {
	if g.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}

	return g.Logger
}

// now is overridable in tests; the ledger stamps records with the wall clock.
var now = defaultNow

type recorder struct {
	principal wire.Principal
	sink      *Sink
	logger    *slog.Logger
}

var _ wire.Recorder = recorder{}

func (r recorder) Begin(sql string, decision wire.Decision) wire.Result {
	kinds := sqlscan.Classify(sql)
	kind := "empty"
	if len(kinds) > 0 {
		kind = kinds[0].String()
	}

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

	return &result{rec: rec, sink: r.sink, logger: r.logger}
}

// result accumulates a statement's outcome and writes the record when the
// statement finishes.
type result struct {
	rec    Record
	sink   *Sink
	logger *slog.Logger
	done   bool
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

	if err := r.sink.Write(r.rec); err != nil {
		r.logger.Error("ledger write", "error", err)
	}
}
