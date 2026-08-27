package ledger_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mickamy/rollcall/internal/ledger"
	"github.com/mickamy/rollcall/internal/wire"
)

func TestGuardRecordsStatements(t *testing.T) {
	t.Parallel()

	defer ledger.SetNow(func() string { return "2026-08-27T00:00:00Z" })()

	var buf bytes.Buffer
	inner := wire.GuardFunc(func(s wire.Startup) wire.Enforcement {
		return wire.Enforcement{
			Principal: wire.Principal{
				Agent: "claude-ops", Purpose: "incident", User: s.User, Database: s.Database,
			},
			Handler: wire.HandlerFunc(func(wire.Statement) wire.Verdict { return wire.Verdict{} }),
		}
	})
	g := ledger.Guard{Inner: inner, Sink: ledger.NewSink(&buf)}

	enf := g.Resolve(wire.Startup{User: "agent_ops", Database: "prod"})

	// An allowed SELECT that returns three rows.
	res := enf.Recorder.Begin("select id from orders where email = 'a@b.com'", wire.Allowed)
	res.Columns([]string{"id"})
	res.Complete("SELECT 3")
	res.Done()

	// A denied UPDATE.
	enf.Recorder.Begin("update orders set x = 1", wire.Denied).Done()

	recs := decode(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("records: got %d, want 2", len(recs))
	}

	first := recs[0]
	gotPrincipal := [4]string{first.Agent, first.Purpose, first.User, first.Database}
	if gotPrincipal != [4]string{"claude-ops", "incident", "agent_ops", "prod"} {
		t.Errorf("first record principal: got %v", gotPrincipal)
	}
	if first.Kind != "SELECT" || first.Rows != 3 {
		t.Errorf("first record: got kind=%q rows=%d, want SELECT/3", first.Kind, first.Rows)
	}
	if first.Fingerprint != "SELECT ID FROM ORDERS WHERE EMAIL = ?" {
		t.Errorf("first fingerprint: got %q", first.Fingerprint)
	}
	if strings.Contains(first.Fingerprint, "a@b.com") {
		t.Error("fingerprint leaked a literal")
	}
	if recs[1].Decision != wire.Denied || recs[1].Kind != "UPDATE" {
		t.Errorf("second record: got decision=%q kind=%q", recs[1].Decision, recs[1].Kind)
	}
}

func TestSinkChainsHashes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	s := ledger.NewSink(&buf)
	for range 3 {
		if err := s.Write(ledger.Record{User: "u", Kind: "SELECT"}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	recs := decode(t, &buf)
	if recs[0].PrevHash != "" {
		t.Errorf("first PrevHash: got %q, want empty", recs[0].PrevHash)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].PrevHash != recs[i-1].Hash {
			t.Errorf("record %d PrevHash %q != previous Hash %q", i, recs[i].PrevHash, recs[i-1].Hash)
		}
		if recs[i].Hash == "" || recs[i].Hash == recs[i-1].Hash {
			t.Errorf("record %d Hash %q not distinct", i, recs[i].Hash)
		}
	}
}

func decode(t *testing.T, buf *bytes.Buffer) []ledger.Record {
	t.Helper()

	var out []ledger.Record
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		var rec ledger.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal %q: %v", sc.Text(), err)
		}
		out = append(out, rec)
	}

	return out
}
