package pg_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mickamy/rollcall/internal/pg"
	"github.com/mickamy/rollcall/internal/wire"
)

const (
	timeout          = 5 * time.Second
	protocolVersion3 = 196608
	cancelRequest    = 80877102
	sslRequest       = 80877103
)

func TestHandshakeRelaysPasswordAuthentication(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	result := p.handshake()
	startup := startupPacket("user", "alice", "database", "app", "application_name", "psql")

	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, startup); err != nil {
			return err
		}
		if err := write(s, auth(3)); err != nil {
			return err
		}
		if err := expectBytes(s, msg('p', cstr("secret"))); err != nil {
			return err
		}

		return write(s,
			auth(0),
			msg('S', cstr("server_version"), cstr("16")),
			msg('K', be32(7), be32(9)),
			msg('Z', []byte("I")),
		)
	})

	mustWrite(t, p.client, packet(sslRequest))
	if got := readN(t, p.client, 1); got[0] != 'N' {
		t.Fatalf("SSLRequest answer: got %q, want 'N'", got)
	}
	mustWrite(t, p.client, startup)

	expectMsg(t, p.client, auth(3))
	mustWrite(t, p.client, msg('p', cstr("secret")))
	expectMsg(t, p.client, auth(0))
	expectMsg(t, p.client, msg('S', cstr("server_version"), cstr("16")))
	expectMsg(t, p.client, msg('K', be32(7), be32(9)))
	expectMsg(t, p.client, msg('Z', []byte("I")))

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	got := <-result
	if got.err != nil {
		t.Fatalf("Handshake: %v", got.err)
	}
	want := wire.Startup{User: "alice", Database: "app", Application: "psql"}
	if got.startup.Params["application_name"] != "psql" {
		t.Errorf("Params: got %v, want application_name=psql", got.startup.Params)
	}
	gotIdentity := [3]string{got.startup.User, got.startup.Database, got.startup.Application}
	wantIdentity := [3]string{want.User, want.Database, want.Application}
	if gotIdentity != wantIdentity {
		t.Errorf("Handshake: got %v, want %v", gotIdentity, wantIdentity)
	}
}

func TestHandshakeRelaysSASLWithoutExpectingAReplyToTheFinalMessage(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	result := p.handshake()

	server := p.serve(func(s net.Conn) error {
		if _, err := readStartup(s); err != nil {
			return err
		}
		if err := write(s, auth(10, cstr("SCRAM-SHA-256"), []byte{0})); err != nil {
			return err
		}
		if err := expectBytes(s, msg('p', cstr("SCRAM-SHA-256"), be32(3), []byte("n,,"))); err != nil {
			return err
		}
		if err := write(s, auth(11, []byte("r=nonce"))); err != nil {
			return err
		}
		if err := expectBytes(s, msg('p', []byte("c=biws"))); err != nil {
			return err
		}

		return write(s, auth(12, []byte("v=proof")), auth(0), msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, startupPacket("user", "alice"))
	expectMsg(t, p.client, auth(10, cstr("SCRAM-SHA-256"), []byte{0}))
	mustWrite(t, p.client, msg('p', cstr("SCRAM-SHA-256"), be32(3), []byte("n,,")))
	expectMsg(t, p.client, auth(11, []byte("r=nonce")))
	mustWrite(t, p.client, msg('p', []byte("c=biws")))
	expectMsg(t, p.client, auth(12, []byte("v=proof")))
	expectMsg(t, p.client, auth(0))
	expectMsg(t, p.client, msg('Z', []byte("I")))

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}
	if got := <-result; got.err != nil {
		t.Fatalf("Handshake: %v", got.err)
	}
}

func TestHandshakeDefaultsDatabaseToUser(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	got := p.connect(t, "user", "alice")

	if got.Database != "alice" {
		t.Errorf("Database: got %q, want %q", got.Database, "alice")
	}
}

func TestHandshakeForwardsCancelRequest(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	result := p.handshake()
	cancel := packet(cancelRequest, be32(1234), be32(5678))

	server := p.serve(func(s net.Conn) error {
		return expectBytes(s, cancel)
	})

	mustWrite(t, p.client, cancel)

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}
	if got := <-result; !errors.Is(got.err, wire.ErrNoSession) {
		t.Errorf("Handshake: got %v, want %v", got.err, wire.ErrNoSession)
	}
}

func TestHandshakeReportsRejection(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	result := p.handshake()
	rejection := msg('E',
		[]byte("SFATAL\x00"), []byte("C28P01\x00"), []byte("Mpassword authentication failed\x00"), []byte{0},
	)

	server := p.serve(func(s net.Conn) error {
		if _, err := readStartup(s); err != nil {
			return err
		}

		return write(s, rejection)
	})

	mustWrite(t, p.client, startupPacket("user", "alice"))
	expectMsg(t, p.client, rejection)

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}
	got := <-result
	if !errors.Is(got.err, wire.ErrRejected) {
		t.Errorf("Handshake: got %v, want %v", got.err, wire.ErrRejected)
	}
	if !strings.Contains(got.err.Error(), "password authentication failed") {
		t.Errorf("Handshake: got %v, want it to carry the upstream message", got.err)
	}
	if got.startup.User != "alice" {
		t.Errorf("Handshake: got user %q with the rejection, want %q", got.startup.User, "alice")
	}
}

func TestHandshakeRejectsUnknownProtocol(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	result := p.handshake()

	mustWrite(t, p.client, packet(131072, cstr("user"), cstr("alice"), []byte{0}))

	if got := <-result; got.err == nil || !strings.Contains(got.err.Error(), "unsupported protocol 2.0") {
		t.Errorf("Handshake: got %v, want an unsupported protocol error", got.err)
	}
}

func TestFrontendForwardsAllowedQueriesAndTerminate(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")

	var seen []string
	done := p.frontend(wire.HandlerFunc(func(stmt wire.Statement) wire.Verdict {
		seen = append(seen, stmt.SQL)

		return wire.Verdict{}
	}))

	query := msg('Q', cstr("select 1"))
	mustWrite(t, p.client, query)
	expectMsg(t, p.upstream, query)

	mustWrite(t, p.client, msg('X'))
	expectMsg(t, p.upstream, msg('X'))

	if err := <-done; err != nil {
		t.Fatalf("Frontend: %v", err)
	}
	if len(seen) != 1 || seen[0] != "select 1" {
		t.Errorf("handler saw %q, want [\"select 1\"]", seen)
	}
}

func TestFrontendDeniesQueriesWithoutForwarding(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")

	done := p.frontend(wire.HandlerFunc(func(wire.Statement) wire.Verdict {
		return wire.Verdict{Deny: true, Message: "writes are not allowed", Hint: "ask for approval"}
	}))

	mustWrite(t, p.client, msg('Q', cstr("delete from orders")))

	typ, body := readMsgT(t, p.client)
	if typ != 'E' {
		t.Fatalf("first reply: got %q, want ErrorResponse", typ)
	}
	fields := errorFields(body)
	want := map[byte]string{'S': "ERROR", 'C': "42501", 'M': "writes are not allowed", 'H': "ask for approval"}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("ErrorResponse field %q: got %q, want %q", k, fields[k], v)
		}
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))
	expectNothing(t, p.upstream)

	mustWrite(t, p.client, msg('X'))
	expectMsg(t, p.upstream, msg('X'))
	if err := <-done; err != nil {
		t.Fatalf("Frontend: %v", err)
	}
}

func TestFrontendDeniesOversizedQueriesAndStaysInSync(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{MaxStatement: 8})
	p.connect(t, "user", "alice")
	done := p.frontend(allow)

	mustWrite(t, p.client, msg('Q', cstr("select 1")))
	typ, body := readMsgT(t, p.client)
	if typ != 'E' || !strings.Contains(errorFields(body)['M'], "exceeds the 8 byte limit") {
		t.Fatalf("oversized query reply: got %q %q, want a limit error", typ, body)
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))

	short := msg('Q', cstr("x"))
	mustWrite(t, p.client, short)
	expectMsg(t, p.upstream, short)

	mustWrite(t, p.client, msg('X'))
	expectMsg(t, p.upstream, msg('X'))
	if err := <-done; err != nil {
		t.Fatalf("Frontend: %v", err)
	}
}

func TestFrontendForwardsCopyDataImmediately(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	done := p.frontend(wire.HandlerFunc(func(wire.Statement) wire.Verdict {
		t.Error("handler called for a message that carries no SQL")

		return wire.Verdict{}
	}))

	for _, m := range [][]byte{msg('d', []byte("1\ttwo\n")), msg('c')} {
		mustWrite(t, p.client, m)
		expectMsg(t, p.upstream, m)
	}

	mustWrite(t, p.client, msg('X'))
	expectMsg(t, p.upstream, msg('X'))
	if err := <-done; err != nil {
		t.Fatalf("Frontend: %v", err)
	}
}

func TestFrontendRejectsMalformedHeader(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	done := p.frontend(allow)

	mustWrite(t, p.client, []byte{'Q', 0, 0, 0, 2})

	if err := <-done; err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("Frontend: got %v, want a malformed message error", err)
	}
}

func TestBackendForwardsAndTracksTransactionStatus(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(denyContaining("update"))

	begin := msg('Q', cstr("begin"))
	replies := [][]byte{msg('C', cstr("BEGIN")), msg('Z', []byte("T"))}
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, begin); err != nil {
			return err
		}

		return write(s, replies...)
	})

	mustWrite(t, p.client, begin)
	for _, want := range replies {
		expectMsg(t, p.client, want)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	mustWrite(t, p.client, msg('Q', cstr("update t set x = 1")))
	if typ, _ := readMsgT(t, p.client); typ != 'E' {
		t.Fatalf("denied query reply: got %q, want ErrorResponse", typ)
	}
	expectMsg(t, p.client, msg('Z', []byte("T")))

	_ = p.upstream.Close()
	if err := <-backend; err != nil {
		t.Errorf("Backend: got %v, want nil after upstream EOF", err)
	}
	_ = p.client.Close()
	<-frontend
}

func TestBackendRejectsUnexpectedReadyForQuery(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	mustWrite(t, p.upstream, msg('Z', []byte("I")))

	if err := <-backend; err == nil || !strings.Contains(err.Error(), "without a pending request") {
		t.Errorf("Backend: got %v, want an unexpected ReadyForQuery error", err)
	}
}

func TestFrontendHoldsDenialsUntilEarlierQueriesAreAnswered(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(denyContaining("delete"))

	first := msg('Q', cstr("select 1"))
	second := msg('Q', cstr("delete from orders"))
	replies := [][]byte{msg('C', cstr("SELECT 1")), msg('Z', []byte("I"))}
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, first); err != nil {
			return err
		}

		return write(s, replies...)
	})

	mustWrite(t, p.client, append(first, second...))

	for _, want := range replies {
		expectMsg(t, p.client, want)
	}
	if typ, body := readMsgT(t, p.client); typ != 'E' || errorFields(body)['M'] != "denied" {
		t.Fatalf("after the first query's replies: got %q %q, want the denial", typ, body)
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}
	expectNothing(t, p.upstream)

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend
}

func TestFrontendForwardsAllowedBatchAtSync(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var seen []string
	frontend := p.frontend(wire.HandlerFunc(func(stmt wire.Statement) wire.Verdict {
		seen = append(seen, stmt.SQL)

		return wire.Verdict{}
	}))

	batch := extendedBatch("select $1")
	replies := [][]byte{msg('1'), msg('2'), msg('C', cstr("SELECT 1")), msg('Z', []byte("I"))}
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, bytes.Join(batch, nil)); err != nil {
			return err
		}

		return write(s, replies...)
	})

	mustWrite(t, p.client, bytes.Join(batch, nil))
	for _, want := range replies {
		expectMsg(t, p.client, want)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}
	if len(seen) != 1 || seen[0] != "select $1" {
		t.Errorf("handler saw %q, want [\"select $1\"]", seen)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend
}

func TestFrontendRejectsAWholeBatchWhenOneStatementIsDenied(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(denyContaining("delete"))

	// An allowed statement precedes a denied one in the same batch. Nothing but
	// a Sync must reach the upstream, so the allowed statement never executes.
	batch := bytes.Join([][]byte{
		pMsg("select 1"), bindMsg, execMsg,
		pMsg("delete from orders"), bindMsg, execMsg,
		syncMsg,
	}, nil)

	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, syncMsg); err != nil {
			return err
		}

		return write(s, msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, batch)

	typ, body := readMsgT(t, p.client)
	if typ != 'E' || errorFields(body)['C'] != "42501" {
		t.Fatalf("batch denial: got %q %q, want ErrorResponse 42501", typ, body)
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend
}

func TestFrontendDeniesParseThenAcceptsTheNextBatch(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(denyContaining("delete"))

	allowed := extendedBatch("select 1")
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, syncMsg); err != nil { // the denied batch forwards only its Sync
			return err
		}
		if err := write(s, msg('Z', []byte("I"))); err != nil {
			return err
		}
		if err := expectBytes(s, bytes.Join(allowed, nil)); err != nil {
			return err
		}

		return write(s, msg('1'), msg('2'), msg('C', cstr("SELECT 1")), msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, bytes.Join(extendedBatch("delete from orders"), nil))
	if typ, body := readMsgT(t, p.client); typ != 'E' || errorFields(body)['C'] != "42501" {
		t.Fatalf("Parse denial: got %q %q, want ErrorResponse 42501", typ, body)
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))

	mustWrite(t, p.client, bytes.Join(allowed, nil))
	for _, want := range [][]byte{msg('1'), msg('2'), msg('C', cstr("SELECT 1")), msg('Z', []byte("I"))} {
		expectMsg(t, p.client, want)
	}

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend
}

func TestFrontendRejectsFunctionCalls(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	done := p.frontend(allow)

	mustWrite(t, p.client, msg('F', be32(1), be16(0), be16(0), be16(0)))

	typ, body := readMsgT(t, p.client)
	if typ != 'E' || errorFields(body)['C'] != "0A000" {
		t.Fatalf("FunctionCall reply: got %q %q, want ErrorResponse 0A000", typ, body)
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))
	expectNothing(t, p.upstream)

	mustWrite(t, p.client, msg('X'))
	expectMsg(t, p.upstream, msg('X'))
	if err := <-done; err != nil {
		t.Fatalf("Frontend: %v", err)
	}
}

func TestExtendedCopyInDropsTheIgnoredSyncSlot(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(denyContaining("delete"))

	// Extended COPY FROM STDIN: the server ignores this batch's Sync while
	// reading copy data and answers a later Sync instead, so two Syncs yield
	// one ReadyForQuery. The proxy must not leave a phantom slot behind.
	copyBatch := bytes.Join([][]byte{pMsg("copy t from stdin"), bindMsg, execMsg, syncMsg}, nil)
	copyIn := msg('G', []byte{0}, be16(1), be16(0))
	data := bytes.Join([][]byte{msg('d', []byte("1\n")), msg('c'), syncMsg}, nil)

	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, copyBatch); err != nil {
			return err
		}
		if err := write(s, msg('1'), msg('2'), copyIn); err != nil { // ParseComplete, BindComplete, CopyInResponse; no Z
			return err
		}
		if err := expectBytes(s, data); err != nil {
			return err
		}

		return write(s, msg('C', cstr("COPY 1")), msg('Z', []byte("I"))) // one Z for the second Sync
	})

	mustWrite(t, p.client, copyBatch)
	for _, want := range [][]byte{msg('1'), msg('2'), copyIn} {
		expectMsg(t, p.client, want)
	}
	mustWrite(t, p.client, data)
	expectMsg(t, p.client, msg('C', cstr("COPY 1")))
	expectMsg(t, p.client, msg('Z', []byte("I")))
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	// The queue is balanced: a following denial is reported at once, not stuck
	// behind a phantom slot.
	mustWrite(t, p.client, msg('Q', cstr("delete from x")))
	if typ, body := readMsgT(t, p.client); typ != 'E' || errorFields(body)['C'] != "42501" {
		t.Fatalf("denial after COPY: got %q %q, want ErrorResponse 42501", typ, body)
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend
}

func TestSimpleCopyInKeepsItsSlot(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(allow)

	// A simple-protocol COPY has one ReadyForQuery at the end, so its slot must
	// survive the CopyInResponse.
	q := msg('Q', cstr("copy t from stdin"))
	copyIn := msg('G', []byte{0}, be16(1), be16(0))
	data := bytes.Join([][]byte{msg('d', []byte("1\n")), msg('c')}, nil)

	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, q); err != nil {
			return err
		}
		if err := write(s, copyIn); err != nil {
			return err
		}
		if err := expectBytes(s, data); err != nil {
			return err
		}

		return write(s, msg('C', cstr("COPY 1")), msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, q)
	expectMsg(t, p.client, copyIn)
	mustWrite(t, p.client, data)
	expectMsg(t, p.client, msg('C', cstr("COPY 1")))
	expectMsg(t, p.client, msg('Z', []byte("I")))
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend
}

func TestDenyAfterEarlyForwardTearsDownTheSession(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()
	frontend := p.frontend(denyContaining("delete"))

	// An explicit Flush forwards the first statement, then a denied Parse
	// arrives. The proxy reports the denial and tears down, so the upstream
	// rolls back instead of committing at a plain Sync.
	first := bytes.Join([][]byte{pMsg("select 1"), bindMsg, execMsg, msg('H')}, nil)
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, first); err != nil {
			return err
		}

		return write(s, msg('1'), msg('2'), msg('C', cstr("SELECT 1")))
	})

	mustWrite(t, p.client, first)
	for _, want := range [][]byte{msg('1'), msg('2'), msg('C', cstr("SELECT 1"))} {
		expectMsg(t, p.client, want)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	mustWrite(t, p.client, pMsg("delete from orders"))
	if typ, body := readMsgT(t, p.client); typ != 'E' || errorFields(body)['C'] != "42501" {
		t.Fatalf("denial: got %q %q, want ErrorResponse 42501", typ, body)
	}

	if err := <-frontend; err == nil {
		t.Error("Frontend: got nil, want a teardown error after denying a partially forwarded batch")
	}
	_ = p.client.Close()
	_ = p.upstream.Close()
	<-backend
}

type capture struct {
	sql      string
	decision wire.Decision
	rows     int
	done     bool
}

type capturingRecorder struct{ records *[]*capture }

func (r capturingRecorder) Begin(sql string, d wire.Decision) wire.Result {
	c := &capture{sql: sql, decision: d}
	*r.records = append(*r.records, c)

	return c
}

func (capture) Columns([]string) []int { return nil }
func (capture) Row([][]byte)           {}
func (c *capture) Complete(tag string) { c.rows += tagRows(tag) }
func (c *capture) Done()               { c.done = true }

func tagRows(tag string) int {
	fields := splitSpace(tag)
	if len(fields) == 0 {
		return 0
	}

	n := 0
	for _, c := range fields[len(fields)-1] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}

	return n
}

func splitSpace(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}

			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}

	return out
}

func TestFrontendRecordsSimpleQueryOutcome(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	query := msg('Q', cstr("select id from t"))
	reply := [][]byte{
		msg('T', be16(1), cstr("id"), be32(0), be16(0), be32(23), be16(4), be32(0xffffffff), be16(0)),
		msg('D', be16(1), be32(1), []byte("7")),
		msg('D', be16(1), be32(1), []byte("8")),
		msg('C', cstr("SELECT 2")),
		msg('Z', []byte("I")),
	}
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, query); err != nil {
			return err
		}

		return write(s, reply...)
	})

	mustWrite(t, p.client, query)
	for _, want := range reply {
		expectMsg(t, p.client, want)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 1 {
		t.Fatalf("records: got %d, want 1", len(records))
	}
	rec := records[0]
	if rec.sql != "select id from t" || rec.decision != wire.Allowed || rec.rows != 2 || !rec.done {
		t.Errorf("record: got %+v, want allowed select with 2 rows, done", rec)
	}
}

func TestFrontendRecordsDenial(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	var records []*capture
	done := p.frontendRec(denyContaining("delete"), capturingRecorder{records: &records})

	mustWrite(t, p.client, msg('Q', cstr("delete from t")))
	if typ, _ := readMsgT(t, p.client); typ != 'E' {
		t.Fatal("expected ErrorResponse")
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))

	mustWrite(t, p.client, msg('X'))
	expectMsg(t, p.upstream, msg('X'))
	<-done

	if len(records) != 1 || records[0].decision != wire.Denied || !records[0].done {
		t.Errorf("records: got %+v, want one denied+done record", records)
	}
}

func TestFrontendRecordsExtendedSingleStatement(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	batch := bytes.Join([][]byte{pMsg("select id from t"), bindMsg, execMsg, syncMsg}, nil)
	reply := [][]byte{
		msg('1'), msg('2'),
		msg('T', be16(1), cstr("id"), be32(0), be16(0), be32(23), be16(4), be32(0xffffffff), be16(0)),
		msg('D', be16(1), be32(1), []byte("7")),
		msg('C', cstr("SELECT 1")),
		msg('Z', []byte("I")),
	}
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, batch); err != nil {
			return err
		}

		return write(s, reply...)
	})

	mustWrite(t, p.client, batch)
	for _, want := range reply {
		expectMsg(t, p.client, want)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 1 {
		t.Fatalf("records: got %d, want 1", len(records))
	}
	if r := records[0]; r.sql != "select id from t" || r.decision != wire.Allowed || r.rows != 1 || !r.done {
		t.Errorf("record: got %+v, want allowed select id from t with 1 row", r)
	}
}

func TestFrontendRecordsOnlyTheDenialOfARejectedBatch(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(denyContaining("delete"), capturingRecorder{records: &records})

	// An allowed Parse precedes a denied one; the batch is rejected, so only the
	// denial is recorded and the earlier statement, which never ran, is not.
	batch := bytes.Join([][]byte{
		pMsg("select 1"), bindMsg, execMsg,
		pMsg("delete from t"), bindMsg, execMsg,
		syncMsg,
	}, nil)
	server := p.serve(func(s net.Conn) error {
		if err := expectBytes(s, syncMsg); err != nil {
			return err
		}

		return write(s, msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, batch)
	if typ, _ := readMsgT(t, p.client); typ != 'E' {
		t.Fatal("expected ErrorResponse for the denied batch")
	}
	expectMsg(t, p.client, msg('Z', []byte("I")))
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 1 {
		t.Fatalf("records: got %d (%+v), want 1", len(records), records)
	}
	if r := records[0]; r.sql != "delete from t" || r.decision != wire.Denied {
		t.Errorf("record: got %+v, want the delete recorded as denied", r)
	}
}

func namedParse(name, sql string) []byte {
	return msg('P', cstr(name), cstr(sql), be16(0))
}

func namedBind(portal, stmt string) []byte {
	return msg('B', cstr(portal), cstr(stmt), be16(0), be16(0), be16(0))
}

// TestFrontendRecordsReExecutionOfAPreparedStatement is the driver case: the
// statement is prepared once, then re-executed in a later batch with no Parse.
// Both executions must be recorded.
func TestFrontendRecordsReExecutionOfAPreparedStatement(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	prepare := bytes.Join([][]byte{namedParse("s1", "select id from t"), namedBind("", "s1"), execMsg, syncMsg}, nil)
	reuse := bytes.Join([][]byte{namedBind("", "s1"), execMsg, syncMsg}, nil)
	result := func(withParse bool) [][]byte {
		out := [][]byte{}
		if withParse {
			out = append(out, msg('1'))
		}
		out = append(out,
			msg('2'),
			msg('T', be16(1), cstr("id"), be32(0), be16(0), be32(23), be16(4), be32(0xffffffff), be16(0)),
			msg('D', be16(1), be32(1), []byte("7")),
			msg('C', cstr("SELECT 1")),
			msg('Z', []byte("I")),
		)

		return out
	}

	server := p.serve(func(sc net.Conn) error {
		if err := expectBytes(sc, prepare); err != nil {
			return err
		}
		if err := write(sc, result(true)...); err != nil {
			return err
		}
		if err := expectBytes(sc, reuse); err != nil {
			return err
		}

		return write(sc, result(false)...)
	})

	mustWrite(t, p.client, prepare)
	for _, w := range result(true) {
		expectMsg(t, p.client, w)
	}
	mustWrite(t, p.client, reuse)
	for _, w := range result(false) {
		expectMsg(t, p.client, w)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 2 {
		t.Fatalf("records: got %d, want 2 (prepare+reuse)", len(records))
	}
	for i, r := range records {
		if r.sql != "select id from t" || r.decision != wire.Allowed || r.rows != 1 || !r.done {
			t.Errorf("record %d: got %+v, want allowed select id from t, 1 row", i, r)
		}
	}
}

// TestFrontendDoesNotRecordAPrepareOnlyBatch checks that preparing a statement
// without executing it is not recorded as an execution.
func TestFrontendDoesNotRecordAPrepareOnlyBatch(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	batch := bytes.Join([][]byte{namedParse("s1", "select id from t"), msg('D', []byte("S"), cstr("s1")), syncMsg}, nil)
	reply := [][]byte{
		msg('1'),
		msg('t', be16(0)),
		msg('T', be16(1), cstr("id"), be32(0), be16(0), be32(23), be16(4), be32(0xffffffff), be16(0)),
		msg('Z', []byte("I")),
	}
	server := p.serve(func(sc net.Conn) error {
		if err := expectBytes(sc, batch); err != nil {
			return err
		}

		return write(sc, reply...)
	})

	mustWrite(t, p.client, batch)
	for _, w := range reply {
		expectMsg(t, p.client, w)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 0 {
		t.Errorf("records: got %d (%+v), want 0 for a prepare-only batch", len(records), records)
	}
}

func execPortal(portal string) []byte {
	return msg('E', cstr(portal), be32(0))
}

// TestExecuteOfAnUnknownPortalIsNotMisattributed guards against resolving an
// unknown portal to the unnamed prepared statement.
func TestExecuteOfAnUnknownPortalIsNotMisattributed(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	prepare := bytes.Join([][]byte{namedParse("", "select id from t"), namedBind("", ""), execMsg, syncMsg}, nil)
	ghost := bytes.Join([][]byte{execPortal("ghost"), syncMsg}, nil)
	commandZ := [][]byte{msg('C', cstr("SELECT 1")), msg('Z', []byte("I"))}

	server := p.serve(func(sc net.Conn) error {
		if err := expectBytes(sc, prepare); err != nil {
			return err
		}
		if err := write(sc, commandZ...); err != nil {
			return err
		}
		if err := expectBytes(sc, ghost); err != nil {
			return err
		}

		return write(sc, msg('C', cstr("SELECT 0")), msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, prepare)
	for _, w := range commandZ {
		expectMsg(t, p.client, w)
	}
	mustWrite(t, p.client, ghost)
	expectMsg(t, p.client, msg('C', cstr("SELECT 0")))
	expectMsg(t, p.client, msg('Z', []byte("I")))
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 1 {
		t.Fatalf("records: got %d (%+v), want 1 (the unknown-portal Execute must not record)", len(records), records)
	}
	if records[0].sql != "select id from t" {
		t.Errorf("record: got sql %q, want the prepared statement", records[0].sql)
	}
}

// TestUnrecordedExecuteDoesNotStealTheNextResult checks that a placeholder keeps
// an unrecorded Execute's result set from being credited to a later record.
func TestUnrecordedExecuteDoesNotStealTheNextResult(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	// One batch: an Execute of an unbound portal (unresolved), then an Execute of
	// a freshly prepared statement. The server returns a result set for each.
	batch := bytes.Join([][]byte{
		namedBind("p1", "nope"), execPortal("p1"),
		namedParse("s2", "select v from t"), namedBind("p2", "s2"), execPortal("p2"),
		syncMsg,
	}, nil)
	reply := [][]byte{
		msg('C', cstr("SELECT 5")), // for the unresolved Execute
		msg('C', cstr("SELECT 3")), // for the recorded Execute
		msg('Z', []byte("I")),
	}
	server := p.serve(func(sc net.Conn) error {
		if err := expectBytes(sc, batch); err != nil {
			return err
		}

		return write(sc, reply...)
	})

	mustWrite(t, p.client, batch)
	for _, w := range reply {
		expectMsg(t, p.client, w)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 1 {
		t.Fatalf("records: got %d, want 1", len(records))
	}
	if records[0].sql != "select v from t" || records[0].rows != 3 {
		t.Errorf("record: got %+v, want select v from t with 3 rows (not the unresolved Execute's 5)", records[0])
	}
}

// TestCloseForgetsThePreparedStatement checks that after a Close, re-executing
// the statement's old name is no longer attributed to it.
func TestCloseForgetsThePreparedStatement(t *testing.T) {
	t.Parallel()

	p := newPipes(t, pg.Dialect{})
	p.connect(t, "user", "alice")
	backend := p.backend()

	var records []*capture
	frontend := p.frontendRec(allow, capturingRecorder{records: &records})

	// Prepare s1, then close it; a later Bind/Execute of s1 must not record.
	prepare := bytes.Join([][]byte{namedParse("s1", "select id from t"), namedBind("", "s1"), execMsg, syncMsg}, nil)
	closeIt := bytes.Join([][]byte{msg('C', []byte("S"), cstr("s1")), syncMsg}, nil)
	reuse := bytes.Join([][]byte{namedBind("", "s1"), execMsg, syncMsg}, nil)
	commandZ := [][]byte{msg('C', cstr("SELECT 1")), msg('Z', []byte("I"))}

	server := p.serve(func(sc net.Conn) error {
		if err := expectBytes(sc, prepare); err != nil {
			return err
		}
		if err := write(sc, commandZ...); err != nil {
			return err
		}
		if err := expectBytes(sc, closeIt); err != nil {
			return err
		}
		if err := write(sc, msg('3'), msg('Z', []byte("I"))); err != nil { // CloseComplete, ReadyForQuery
			return err
		}
		if err := expectBytes(sc, reuse); err != nil {
			return err
		}

		return write(sc, commandZ...)
	})

	mustWrite(t, p.client, prepare)
	for _, w := range commandZ {
		expectMsg(t, p.client, w)
	}
	mustWrite(t, p.client, closeIt)
	expectMsg(t, p.client, msg('3'))
	expectMsg(t, p.client, msg('Z', []byte("I")))
	mustWrite(t, p.client, reuse)
	for _, w := range commandZ {
		expectMsg(t, p.client, w)
	}
	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}

	_ = p.client.Close()
	_ = p.upstream.Close()
	<-frontend
	<-backend

	if len(records) != 1 {
		t.Errorf("records: got %d, want 1 (reuse after Close must not record)", len(records))
	}
}

// pipes connects a session to a fake client and a fake upstream over net.Pipe.
type pipes struct {
	sess     wire.Session
	client   net.Conn
	upstream net.Conn
}

type handshakeResult struct {
	startup wire.Startup
	err     error
}

func newPipes(t *testing.T, d pg.Dialect) pipes {
	t.Helper()

	clientSide, clientPeer := net.Pipe()
	upstreamSide, upstreamPeer := net.Pipe()
	for _, c := range []net.Conn{clientSide, clientPeer, upstreamSide, upstreamPeer} {
		if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}

	return pipes{sess: d.NewSession(clientSide, upstreamSide), client: clientPeer, upstream: upstreamPeer}
}

func (p pipes) handshake() <-chan handshakeResult {
	result := make(chan handshakeResult, 1)
	go func() {
		startup, err := p.sess.Handshake()
		result <- handshakeResult{startup: startup, err: err}
	}()

	return result
}

func (p pipes) frontend(h wire.Handler) <-chan error {
	return p.frontendRec(h, nil)
}

func (p pipes) frontendRec(h wire.Handler, rec wire.Recorder) <-chan error {
	done := make(chan error, 1)
	go func() { done <- p.sess.Frontend(h, rec) }()

	return done
}

func (p pipes) backend() <-chan error {
	done := make(chan error, 1)
	go func() { done <- p.sess.Backend() }()

	return done
}

// serve runs script against the upstream end on its own goroutine.
func (p pipes) serve(script func(s net.Conn) error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- script(p.upstream) }()

	return done
}

// connect completes a trust-authenticated handshake for the given startup parameters.
func (p pipes) connect(t *testing.T, params ...string) wire.Startup {
	t.Helper()

	result := p.handshake()
	server := p.serve(func(s net.Conn) error {
		if _, err := readStartup(s); err != nil {
			return err
		}

		return write(s, auth(0), msg('Z', []byte("I")))
	})

	mustWrite(t, p.client, startupPacket(params...))
	expectMsg(t, p.client, auth(0))
	expectMsg(t, p.client, msg('Z', []byte("I")))

	if err := <-server; err != nil {
		t.Fatalf("fake server: %v", err)
	}
	got := <-result
	if got.err != nil {
		t.Fatalf("Handshake: %v", got.err)
	}

	return got.startup
}

var allow = wire.HandlerFunc(func(wire.Statement) wire.Verdict { return wire.Verdict{} })

func denyContaining(word string) wire.Handler {
	return wire.HandlerFunc(func(stmt wire.Statement) wire.Verdict {
		if strings.Contains(stmt.SQL, word) {
			return wire.Verdict{Deny: true, Message: "denied"}
		}

		return wire.Verdict{}
	})
}

var (
	bindMsg = msg('B', cstr(""), cstr(""), be16(0), be16(0), be16(0))
	execMsg = msg('E', cstr(""), be32(0))
	syncMsg = msg('S')
)

func pMsg(sql string) []byte {
	return msg('P', cstr(""), cstr(sql), be16(0))
}

// extendedBatch is Parse, Bind, Execute, Sync for an unnamed statement.
func extendedBatch(sql string) [][]byte {
	return [][]byte{pMsg(sql), bindMsg, execMsg, syncMsg}
}

func be16(v uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, v)
}

func be32(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

func cstr(s string) []byte {
	return append([]byte(s), 0)
}

func msg(typ byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	out := []byte{typ}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // test payloads are tiny

	return append(out, body...)
}

func auth(code uint32, parts ...[]byte) []byte {
	return msg('R', append([][]byte{be32(code)}, parts...)...)
}

// packet builds an untyped startup-phase packet: length, code, payload.
func packet(code uint32, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)+8)) //nolint:gosec // test payloads are tiny
	out = binary.BigEndian.AppendUint32(out, code)

	return append(out, body...)
}

func startupPacket(params ...string) []byte {
	parts := make([][]byte, 0, len(params)+1)
	for _, p := range params {
		parts = append(parts, cstr(p))
	}
	parts = append(parts, []byte{0})

	return packet(protocolVersion3, parts...)
}

func write(w io.Writer, msgs ...[]byte) error {
	for _, m := range msgs {
		if _, err := w.Write(m); err != nil {
			return err //nolint:wrapcheck // test helper surfaces the raw pipe error
		}
	}

	return nil
}

func mustWrite(t *testing.T, w io.Writer, b []byte) {
	t.Helper()

	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}

	return buf
}

// readStartup reads one untyped startup-phase packet and returns it whole.
func readStartup(r io.Reader) ([]byte, error) {
	length := make([]byte, 4)
	if _, err := io.ReadFull(r, length); err != nil {
		return nil, err //nolint:wrapcheck // test helper surfaces the raw pipe error
	}

	out := make([]byte, binary.BigEndian.Uint32(length))
	copy(out, length)
	if _, err := io.ReadFull(r, out[4:]); err != nil {
		return nil, err //nolint:wrapcheck // test helper surfaces the raw pipe error
	}

	return out, nil
}

// readMsg reads one typed message and returns it whole, header included.
func readMsg(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err //nolint:wrapcheck // test helper surfaces the raw pipe error
	}

	n := binary.BigEndian.Uint32(header[1:])
	out := make([]byte, 5+int(n)-4)
	copy(out, header)
	if _, err := io.ReadFull(r, out[5:]); err != nil {
		return nil, err //nolint:wrapcheck // test helper surfaces the raw pipe error
	}

	return out, nil
}

func readMsgT(t *testing.T, r io.Reader) (typ byte, body []byte) {
	t.Helper()

	m, err := readMsg(r)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	return m[0], m[5:]
}

func expectMsg(t *testing.T, r io.Reader, want []byte) {
	t.Helper()

	got, err := readMsg(r)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("message: got %q, want %q", got, want)
	}
}

func expectBytes(r io.Reader, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return err //nolint:wrapcheck // test helper surfaces the raw pipe error
	}
	if !bytes.Equal(got, want) {
		return errors.New("unexpected bytes: " + string(got))
	}

	return nil
}

func expectNothing(t *testing.T, c net.Conn) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	defer func() { _ = c.SetReadDeadline(time.Now().Add(timeout)) }()

	buf := make([]byte, 1)
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read: got %v, want nothing to arrive", err)
	}
}

func errorFields(body []byte) map[byte]string {
	fields := make(map[byte]string)
	for len(body) > 0 && body[0] != 0 {
		end := bytes.IndexByte(body[1:], 0)
		if end < 0 {
			break
		}
		fields[body[0]] = string(body[1 : 1+end])
		body = body[2+end:]
	}

	return fields
}
