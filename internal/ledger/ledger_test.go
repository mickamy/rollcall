package ledger_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mickamy/rollcall/internal/ledger"
	"github.com/mickamy/rollcall/internal/wire"
)

func TestGuardRecordsStatements(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	inner := wire.GuardFunc(func(s wire.Startup) wire.Enforcement {
		return wire.Enforcement{
			Principal: wire.Principal{
				Agent: "claude-ops", Purpose: "incident", User: s.User, Database: s.Database,
			},
			Handler: wire.HandlerFunc(func(wire.Statement) wire.Verdict { return wire.Verdict{} }),
		}
	})
	sink := ledger.NewSink(&buf, ledger.Options{})
	g := ledger.Guard{Inner: inner, Sink: sink}

	enf := g.Resolve(wire.Startup{User: "agent_ops", Database: "prod"})

	// An allowed SELECT that returns three rows.
	res := enf.Recorder.Begin("select id from orders where email = 'a@b.com'", wire.Allowed)
	res.Columns([]string{"id"})
	res.Complete("SELECT 3")
	res.Done()

	// A denied UPDATE.
	enf.Recorder.Begin("update orders set x = 1", wire.Denied).Done()

	sink.Close()
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
	s := ledger.NewSink(&buf, ledger.Options{})
	for range 3 {
		s.Write(ledger.Record{User: "u", Kind: "SELECT"})
	}
	s.Close()

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

func TestSinkResumesChainWithPrevAndKey(t *testing.T) {
	t.Parallel()

	var first bytes.Buffer
	s1 := ledger.NewSink(&first, ledger.Options{Key: []byte("secret")})
	s1.Write(ledger.Record{User: "u", Kind: "SELECT"})
	s1.Write(ledger.Record{User: "u", Kind: "SELECT"})
	s1.Close()
	firstRecs := decode(t, &first)
	last := firstRecs[len(firstRecs)-1].Hash

	// A new sink seeded with the last hash continues the same chain.
	var second bytes.Buffer
	s2 := ledger.NewSink(&second, ledger.Options{Prev: last, Key: []byte("secret")})
	s2.Write(ledger.Record{User: "u", Kind: "DELETE"})
	s2.Close()
	next := decode(t, &second)

	if next[0].PrevHash != last {
		t.Errorf("resumed PrevHash: got %q, want %q", next[0].PrevHash, last)
	}
	if next[0].Hash == "" {
		t.Error("resumed record has no hash")
	}
}

func TestFingerprintIsBounded(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	inner := wire.GuardFunc(func(wire.Startup) wire.Enforcement {
		return wire.Enforcement{Handler: wire.HandlerFunc(func(wire.Statement) wire.Verdict { return wire.Verdict{} })}
	})
	sink := ledger.NewSink(&buf, ledger.Options{})
	enf := ledger.Guard{Inner: inner, Sink: sink}.Resolve(wire.Startup{User: "u"})

	huge := "select " + strings.Repeat("col_a, ", 5000) + "col_z from t"
	enf.Recorder.Begin(huge, wire.Allowed).Done()
	sink.Close()

	rec := decode(t, &buf)[0]
	if len(rec.Fingerprint) > 4200 {
		t.Errorf("fingerprint length %d not bounded", len(rec.Fingerprint))
	}
	if !strings.Contains(rec.Fingerprint, "#") {
		t.Error("truncated fingerprint has no hash suffix")
	}
}

func TestRecordsCarryKeyID(t *testing.T) {
	t.Parallel()

	var keyed, plain bytes.Buffer
	k := ledger.NewSink(&keyed, ledger.Options{Key: []byte("secret")})
	k.Write(ledger.Record{User: "u", Kind: "SELECT"})
	k.Close()
	p := ledger.NewSink(&plain, ledger.Options{})
	p.Write(ledger.Record{User: "u", Kind: "SELECT"})
	p.Close()

	if id := decode(t, &keyed)[0].KeyID; id == "" {
		t.Error("keyed record has no key_id")
	}
	if id := decode(t, &plain)[0].KeyID; id != "" {
		t.Errorf("unkeyed record key_id: got %q, want empty", id)
	}
}

func TestLastHashReadsTheTail(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	sink := ledger.NewSink(f, ledger.Options{})
	for range 5 {
		sink.Write(ledger.Record{User: "u", Kind: "SELECT"})
	}
	sink.Close()
	last := sink.LastHash()
	_ = f.Close()

	got, err := ledger.LastHash(path)
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if got != last {
		t.Errorf("LastHash: got %q, want %q", got, last)
	}

	// A partial trailing write must fall back to the last complete record.
	appendString(t, path, `{"partial":`)
	got, err = ledger.LastHash(path)
	if err != nil {
		t.Fatalf("LastHash after partial write: %v", err)
	}
	if got != last {
		t.Errorf("LastHash ignored a partial line: got %q, want %q", got, last)
	}
}

func TestLastHashMissingFile(t *testing.T) {
	t.Parallel()

	got, err := ledger.LastHash(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil || got != "" {
		t.Errorf("LastHash on a missing file: got %q, %v; want empty, nil", got, err)
	}
}

func appendString(t *testing.T, path, s string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(s); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestChainResumesAcrossAKeyChange mirrors what the CLI does on restart: read
// the file's last hash, then continue the chain with a possibly different key.
func TestChainResumesAcrossAKeyChange(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ledger.jsonl")

	writeWith := func(key []byte, kind string) {
		prev, err := ledger.LastHash(path)
		if err != nil {
			t.Fatalf("LastHash: %v", err)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		s := ledger.NewSink(f, ledger.Options{Prev: prev, Key: key})
		s.Write(ledger.Record{User: "u", Kind: kind})
		s.Close()
		_ = f.Close()
	}

	writeWith([]byte("alpha"), "SELECT")
	writeWith([]byte("alpha"), "SELECT")
	writeWith([]byte("beta"), "DELETE") // restart with a different key

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	recs := decode(t, bufferOf(t, f))

	if len(recs) != 3 {
		t.Fatalf("records: got %d, want 3", len(recs))
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].PrevHash != recs[i-1].Hash {
			t.Errorf("record %d does not link to the previous", i)
		}
	}
	if recs[0].KeyID == recs[2].KeyID {
		t.Error("key_id did not change when the key changed")
	}
	if recs[0].KeyID != recs[1].KeyID {
		t.Error("key_id changed while the key stayed the same")
	}
}

func bufferOf(t *testing.T, f *os.File) *bytes.Buffer {
	t.Helper()

	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	return bytes.NewBuffer(data)
}
