// Package pg implements wire.Dialect for the PostgreSQL frontend/backend protocol, version 3.
package pg

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/mickamy/rollcall/internal/wire"
)

const (
	defaultMaxStatement = 16 << 20

	readBufferSize  = 64 << 10
	writeBufferSize = 32 << 10

	// maxPending bounds the extended-protocol messages held before a Sync so a
	// batch can be rejected atomically; a batch larger than this is forwarded
	// early (see stage) rather than buffered without limit.
	maxPending = 8 << 20
	// maxQueue bounds outstanding responses. Reaching it blocks the frontend
	// until the backend drains one, applying backpressure like the server does.
	maxQueue = 512
	// smallBody bounds the messages Backend reads fully before taking the
	// client write lock, so a stalled upstream cannot hold denials hostage.
	smallBody = 32 << 10
)

// errDeniedAfterForward ends a session when a statement is denied after part of
// its batch already reached the upstream. Closing the connection makes the
// upstream roll back the implicit transaction instead of committing at Sync.
var errDeniedAfterForward = errors.New("statement denied after its batch was partially forwarded")

type Dialect struct {
	// MaxStatement caps the SQL text of a Query or Parse message; longer
	// statements are denied without being forwarded. Zero means 16 MiB.
	MaxStatement uint32
}

var _ wire.Dialect = (*Dialect)(nil)

func (d Dialect) NewSession(client, upstream net.Conn) wire.Session {
	maxStatement := d.MaxStatement
	if maxStatement == 0 {
		maxStatement = defaultMaxStatement
	}

	s := &session{
		maxStatement: maxStatement,
		cr:           bufio.NewReaderSize(client, readBufferSize),
		cw:           bufio.NewWriterSize(client, writeBufferSize),
		ur:           bufio.NewReaderSize(upstream, readBufferSize),
		uw:           bufio.NewWriterSize(upstream, writeBufferSize),
		small:        make([]byte, smallBody),
	}
	s.drained = sync.NewCond(&s.mu)

	return s
}

// slot is one client request awaiting its answer, in request order. A
// forwarded slot is settled by the upstream's ReadyForQuery; simple marks the
// simple query protocol, whose ReadyForQuery survives COPY. A synthesized slot
// (not forwarded) is written by the proxy once every slot ahead of it is
// answered.
type slot struct {
	forwarded bool
	simple    bool
	code      string
	message   string
	hint      string
	ready     bool
}

type session struct {
	maxStatement uint32

	// Frontend goroutine only.
	cr        *bufio.Reader
	uw        *bufio.Writer
	pending   bytes.Buffer
	forwarded bool // part of the current batch was already sent upstream
	denied    bool // a statement in the current batch was denied

	// Backend goroutine only.
	ur    *bufio.Reader
	small []byte

	// mu serializes writes to the client, which Frontend (denials) and Backend
	// (forwarded messages) both perform, and guards tx and queue alongside them.
	// drained wakes the frontend when the backend frees a queue slot.
	mu      sync.Mutex
	drained *sync.Cond
	cw      *bufio.Writer
	tx      byte
	queue   []slot
}

func (s *session) Handshake() (wire.Startup, error) {
	for {
		packet, err := readStartupPacket(s.cr)
		if err != nil {
			return wire.Startup{}, err
		}

		switch code := binary.BigEndian.Uint32(packet[lengthLen:]); code {
		case sslRequestCode, gssEncRequestCode:
			// The proxy speaks plaintext to its clients; refusing makes libpq fall back.
			if err := s.writeClientRaw([]byte{'N'}); err != nil {
				return wire.Startup{}, err
			}
		case cancelRequestCode:
			if err := s.writeUpstreamRaw(packet); err != nil {
				return wire.Startup{}, err
			}

			return wire.Startup{}, wire.ErrNoSession
		case protocolVersion3:
			startup, err := parseStartup(packet[2*lengthLen:])
			if err != nil {
				return wire.Startup{}, err
			}
			if err := s.writeUpstreamRaw(packet); err != nil {
				return startup, err
			}

			return startup, s.relayAuth()
		default:
			return wire.Startup{}, fmt.Errorf("unsupported protocol %d.%d", code>>16, code&0xffff)
		}
	}
}

// Frontend relays client messages, consulting h for every statement. Extended
// messages are held until their Sync so a batch can be accepted or rejected as
// a unit. Output is flushed whenever the client has nothing more buffered.
func (s *session) Frontend(h wire.Handler) error {
	for {
		if s.cr.Buffered() == 0 {
			if err := flush(s.uw); err != nil {
				return err
			}
		}

		typ, n, err := readHeader(s.cr)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read client: %w", err)
		}

		done, err := s.dispatch(h, typ, n)
		if err != nil {
			return err
		}
		if done {
			return flush(s.uw)
		}
	}
}

// Backend relays upstream messages and settles the request queue on every
// ReadyForQuery, writing any denials that were waiting their turn.
func (s *session) Backend() error {
	for {
		if s.ur.Buffered() == 0 {
			if err := s.flushClient(); err != nil {
				return err
			}
		}

		typ, n, err := readHeader(s.ur)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read upstream: %w", err)
		}

		switch typ {
		case typeReadyForQuery:
			err = s.readyForQuery(n)
		case typeCopyInResponse:
			// The server ignores the batch's Sync while reading COPY data, so
			// the extended-protocol slot for it will never be answered; drop it.
			if err = s.forwardToClient(typ, n); err == nil {
				s.copyInStarted()
			}
		default:
			err = s.forwardToClient(typ, n)
		}
		if err != nil {
			return err
		}
	}
}

// relayAuth passes the authentication exchange through untouched until the
// upstream reports ReadyForQuery or refuses the connection.
func (s *session) relayAuth() error {
	for {
		typ, body, err := readMessage(s.ur, maxAuthMessage)
		if err != nil {
			return fmt.Errorf("read upstream during handshake: %w", err)
		}
		if err := s.writeClient(typ, body); err != nil {
			return err
		}

		switch typ {
		case typeReadyForQuery:
			if len(body) != 1 {
				return fmt.Errorf("%w: ReadyForQuery with %d byte body", errMalformed, len(body))
			}
			s.setTx(body[0])

			return nil
		case typeErrorResponse:
			return fmt.Errorf("%w: %s", wire.ErrRejected, errorMessage(body))
		case typeAuthentication:
			if len(body) < lengthLen {
				return fmt.Errorf("%w: Authentication with %d byte body", errMalformed, len(body))
			}
			if !expectsResponse(binary.BigEndian.Uint32(body)) {
				continue
			}

			typ, body, err := readMessage(s.cr, maxAuthMessage)
			if err != nil {
				return fmt.Errorf("read client during handshake: %w", err)
			}
			if err := writeMessage(s.uw, typ, body); err != nil {
				return err
			}
			if err := flush(s.uw); err != nil {
				return err
			}
		}
	}
}

// dispatch routes one client message. It reports whether the session is done.
func (s *session) dispatch(h wire.Handler, typ byte, n uint32) (bool, error) {
	switch typ {
	case typeQuery:
		return false, s.query(h, n)
	case typeParse:
		return false, s.parse(h, n)
	case typeBind, typeDescribe, typeExecute, typeClose:
		return false, s.buffer(typ, n)
	case typeFlush:
		return false, s.flushBatch(n)
	case typeSync:
		return false, s.sync(n)
	case typeFunctionCall:
		return false, s.functionCall(n)
	case typeTerminate:
		if err := s.forwardPending(); err != nil {
			return false, err
		}

		return true, forward(s.uw, typ, n, s.cr)
	default:
		// Copy sub-protocol (CopyData/CopyDone/CopyFail) and anything else that
		// carries no SQL: forward immediately, after any buffered batch.
		if err := s.forwardPending(); err != nil {
			return false, err
		}

		return false, forward(s.uw, typ, n, s.cr)
	}
}

func (s *session) query(h wire.Handler, n uint32) error {
	if err := s.forwardPending(); err != nil {
		return err
	}

	if n > s.maxStatement {
		if err := discard(s.cr, n); err != nil {
			return err
		}

		return s.respond(readySlot(s.tooLarge(n)))
	}

	body, err := readBody(s.cr, n)
	if err != nil {
		return err
	}

	sql := string(bytes.TrimSuffix(body, []byte{0}))
	if v := h.Statement(wire.Statement{SQL: sql}); v.Deny {
		return s.respond(readySlot(denial(v)))
	}

	// Enqueue before the statement can reach the upstream, so Backend never sees
	// the reply before the slot that accounts for it. A simple query's
	// ReadyForQuery survives COPY, so mark it.
	s.enqueue(slot{forwarded: true, simple: true})

	return writeMessage(s.uw, typeQuery, body)
}

// parse handles the extended protocol's Parse message, the one place where SQL
// enters that path. A denial rejects the whole batch: earlier buffered messages
// are dropped and later ones ignored until Sync.
func (s *session) parse(h wire.Handler, n uint32) error {
	if s.denied {
		return discard(s.cr, n)
	}
	if n > s.maxStatement {
		if err := discard(s.cr, n); err != nil {
			return err
		}

		return s.denyBatch(s.tooLarge(n))
	}

	body, err := readBody(s.cr, n)
	if err != nil {
		return err
	}

	sql, err := parseSQL(body)
	if err != nil {
		return err
	}

	if v := h.Statement(wire.Statement{SQL: sql}); v.Deny {
		return s.denyBatch(denial(v))
	}

	return s.stage(typeParse, body)
}

func (s *session) buffer(typ byte, n uint32) error {
	if s.denied {
		return discard(s.cr, n)
	}
	if s.forwarded || int64(n) > maxPending {
		if err := s.forwardPending(); err != nil {
			return err
		}
		s.forwarded = true

		return forward(s.uw, typ, n, s.cr)
	}

	body, err := readBody(s.cr, n)
	if err != nil {
		return err
	}

	return s.stage(typ, body)
}

// stage buffers one message until the batch's Sync, forwarding what is already
// buffered when the buffer would grow past maxPending.
func (s *session) stage(typ byte, body []byte) error {
	if s.forwarded {
		return writeMessage(s.uw, typ, body)
	}
	if s.pending.Len() > 0 && s.pending.Len()+headerLen+len(body) > maxPending {
		if err := s.forwardPending(); err != nil {
			return err
		}
		s.forwarded = true

		return writeMessage(s.uw, typ, body)
	}

	stageHeader(&s.pending, typ, len(body))
	s.pending.Write(body)

	return nil
}

func (s *session) flushBatch(n uint32) error {
	if err := discard(s.cr, n); err != nil {
		return err
	}
	if s.denied {
		return nil
	}
	if err := s.forwardPending(); err != nil {
		return err
	}
	s.forwarded = true
	if err := writeMessage(s.uw, typeFlush, nil); err != nil {
		return err
	}

	return flush(s.uw)
}

// sync ends a batch. A clean batch is forwarded together with its Sync; a
// denied batch (which never forwarded anything) sends only a Sync so the
// client's ReadyForQuery still comes from a real upstream response.
func (s *session) sync(n uint32) error {
	if err := discard(s.cr, n); err != nil {
		return err
	}

	if !s.denied {
		if err := s.forwardPending(); err != nil {
			return err
		}
	}

	s.denied = false
	s.forwarded = false

	// Enqueue before the Sync reaches the upstream, so Backend never sees the
	// ReadyForQuery before the slot that accounts for it.
	s.enqueue(slot{forwarded: true})
	if err := writeMessage(s.uw, typeSync, nil); err != nil {
		return err
	}

	return flush(s.uw)
}

func (s *session) functionCall(n uint32) error {
	if err := discard(s.cr, n); err != nil {
		return err
	}
	if s.denied {
		return nil
	}
	if err := s.forwardPending(); err != nil {
		return err
	}

	return s.respond(readySlot(slot{
		code:    sqlStateFeatureNotSupported,
		message: "the function call protocol is not supported through the proxy",
	}))
}

// denyBatch rejects the current batch. When nothing has been forwarded it is
// rejected atomically. When part of it already reached the upstream, the
// session is torn down so the upstream rolls back rather than committing at Sync.
func (s *session) denyBatch(sl slot) error {
	s.denied = true
	s.resetPending()

	if s.forwarded {
		s.emitError(sl)

		return errDeniedAfterForward
	}

	return s.respond(sl)
}

func (s *session) forwardPending() error {
	if s.pending.Len() == 0 {
		return nil
	}
	if _, err := s.uw.Write(s.pending.Bytes()); err != nil {
		return fmt.Errorf("forward buffered batch: %w", err)
	}
	s.resetPending()

	return nil
}

// resetPending clears the buffer, dropping an oversized backing array so a
// connection that saw one large batch does not hold that memory for its life.
func (s *session) resetPending() {
	if s.pending.Len() > maxPending {
		s.pending = bytes.Buffer{}

		return
	}
	s.pending.Reset()
}

// respond enqueues a synthesized answer and writes it, and any answers ahead of
// it that are now unblocked, when nothing forwarded is still pending.
func (s *session) respond(sl slot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enqueueLocked(sl)

	emitted := false
	for len(s.queue) > 0 && !s.queue[0].forwarded {
		if err := s.emit(s.queue[0]); err != nil {
			return err
		}
		s.queue = s.queue[1:]
		emitted = true
	}
	if emitted {
		s.drained.Broadcast()

		return flush(s.cw)
	}

	return nil
}

func (s *session) enqueue(sl slot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enqueueLocked(sl)
}

// enqueueLocked appends a slot, blocking while the queue is full so the client
// is backpressured instead of dropped. Callers hold mu.
func (s *session) enqueueLocked(sl slot) {
	for len(s.queue) >= maxQueue {
		s.drained.Wait()
	}
	s.queue = append(s.queue, sl)
}

// emit writes a synthesized answer. Callers hold mu.
func (s *session) emit(sl slot) error {
	if sl.code != "" {
		if err := writeMessage(s.cw, typeErrorResponse, errorResponse(sl.code, sl.message, sl.hint)); err != nil {
			return err
		}
	}
	if sl.ready {
		if err := writeMessage(s.cw, typeReadyForQuery, []byte{s.tx}); err != nil {
			return err
		}
	}

	return nil
}

// emitError writes a denial straight to the client, best effort, for the
// teardown path where the queue is about to be abandoned.
func (s *session) emitError(sl slot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = writeMessage(s.cw, typeErrorResponse, errorResponse(sl.code, sl.message, sl.hint))
	_ = flush(s.cw)
}

func (s *session) readyForQuery(n uint32) error {
	if n != 1 {
		return fmt.Errorf("%w: ReadyForQuery with %d byte body", errMalformed, n)
	}

	var status [1]byte
	if _, err := io.ReadFull(s.ur, status[:]); err != nil {
		return fmt.Errorf("read ReadyForQuery: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.queue) > 0 && !s.queue[0].forwarded {
		if err := s.emit(s.queue[0]); err != nil {
			return err
		}
		s.queue = s.queue[1:]
	}
	if len(s.queue) == 0 || !s.queue[0].forwarded {
		return fmt.Errorf("%w: ReadyForQuery without a pending request", errMalformed)
	}

	s.queue = s.queue[1:]
	s.tx = status[0]
	if err := writeMessage(s.cw, typeReadyForQuery, status[:]); err != nil {
		return err
	}

	for len(s.queue) > 0 && !s.queue[0].forwarded {
		if err := s.emit(s.queue[0]); err != nil {
			return err
		}
		s.queue = s.queue[1:]
	}

	s.drained.Broadcast()

	return flush(s.cw)
}

// copyInStarted drops the extended-protocol Sync slot for a COPY, whose Sync the
// server ignores while reading copy data. A simple query keeps its slot, since
// its ReadyForQuery still arrives when the copy completes.
func (s *session) copyInStarted() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.queue) > 0 && s.queue[0].forwarded && !s.queue[0].simple {
		s.queue = s.queue[1:]
		s.drained.Broadcast()
	}
}

func (s *session) forwardToClient(typ byte, n uint32) error {
	if n > smallBody {
		s.mu.Lock()
		defer s.mu.Unlock()

		return forward(s.cw, typ, n, s.ur)
	}

	body := s.small[:n]
	if _, err := io.ReadFull(s.ur, body); err != nil {
		return fmt.Errorf("read %q body: %w", typ, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return writeMessage(s.cw, typ, body)
}

func (s *session) flushClient() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return flush(s.cw)
}

func (s *session) setTx(status byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tx = status
}

func (s *session) writeClient(typ byte, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := writeMessage(s.cw, typ, body); err != nil {
		return err
	}

	return flush(s.cw)
}

func (s *session) writeClientRaw(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.cw.Write(b); err != nil {
		return fmt.Errorf("write client: %w", err)
	}

	return flush(s.cw)
}

func (s *session) writeUpstreamRaw(b []byte) error {
	if _, err := s.uw.Write(b); err != nil {
		return fmt.Errorf("write upstream: %w", err)
	}

	return flush(s.uw)
}

func expectsResponse(authCode uint32) bool {
	switch authCode {
	case authOK, authSASLFinal:
		return false
	default:
		return true
	}
}

func denial(v wire.Verdict) slot {
	return slot{code: sqlStateInsufficientPrivilege, message: v.Message, hint: v.Hint}
}

func (s *session) tooLarge(n uint32) slot {
	return slot{
		code:    sqlStateProgramLimitExceeded,
		message: fmt.Sprintf("statement of %d bytes exceeds the %d byte limit", n, s.maxStatement),
	}
}

func readySlot(sl slot) slot {
	sl.ready = true

	return sl
}

// parseSQL returns the query text from a Parse message body, which is the
// statement name followed by the SQL, both null-terminated.
func parseSQL(body []byte) (string, error) {
	_, rest, err := cstring(body)
	if err != nil {
		return "", fmt.Errorf("parse message: %w", err)
	}

	sql, _, err := cstring(rest)
	if err != nil {
		return "", fmt.Errorf("parse message: %w", err)
	}

	return sql, nil
}

func parseStartup(body []byte) (wire.Startup, error) {
	params := make(map[string]string)
	for len(body) > 0 {
		key, rest, err := cstring(body)
		if err != nil {
			return wire.Startup{}, fmt.Errorf("startup packet: %w", err)
		}
		if key == "" {
			break
		}

		value, rest, err := cstring(rest)
		if err != nil {
			return wire.Startup{}, fmt.Errorf("startup packet: %w", err)
		}

		params[key] = value
		body = rest
	}

	user := params["user"]
	if user == "" {
		return wire.Startup{}, fmt.Errorf("%w: startup packet without user", errMalformed)
	}

	database := params["database"]
	if database == "" {
		database = user
	}

	return wire.Startup{
		User:        user,
		Database:    database,
		Application: params["application_name"],
		Params:      params,
	}, nil
}
