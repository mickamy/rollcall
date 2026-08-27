// Package wire holds the dialect-neutral types that the proxy, policy, and
// ledger share. Database-specific packages implement Dialect and Session and
// never leak their own message types through this boundary.
package wire

import (
	"errors"
	"net"
)

var (
	// ErrNoSession reports a connection that carried an out-of-band request
	// (such as a cancel request) and is finished without starting a session.
	ErrNoSession = errors.New("connection did not start a session")
	// ErrRejected reports that the upstream refused the connection during the handshake.
	ErrRejected = errors.New("upstream rejected the connection")
)

// Startup is what the client declared about itself when it connected.
type Startup struct {
	User        string
	Database    string
	Application string
	Params      map[string]string
}

type Statement struct {
	SQL string
}

// Verdict is the zero value to let a statement through.
type Verdict struct {
	Deny    bool
	Message string
	Hint    string
}

type Handler interface {
	Statement(stmt Statement) Verdict
}

type HandlerFunc func(stmt Statement) Verdict

func (f HandlerFunc) Statement(stmt Statement) Verdict {
	return f(stmt)
}

// Principal is who a session's statements are attributed to.
type Principal struct {
	Agent       string
	Purpose     string
	User        string
	Database    string
	Application string
}

// Decision is what the proxy did with a statement.
type Decision string

const (
	Allowed Decision = "allowed"
	Denied  Decision = "denied"
)

// Recorder records the statements of one session for the access ledger. A nil
// Recorder records nothing.
type Recorder interface {
	// Begin starts a record for a statement and its decision, returning a
	// Result to receive the statement's result, or nil to record no result.
	Begin(sql string, decision Decision) Result
}

// Result receives one statement's result from the session's backend goroutine,
// in order: Columns for each result set (returning which columns to capture),
// Row for each row (with the captured columns only), Complete for each result
// set's command tag, and Done once when the statement finishes.
type Result interface {
	Columns(names []string) (capture []int)
	Row(captured [][]byte)
	Complete(tag string)
	Done()
}

// Enforcement is how a session is guarded: who it is attributed to, statements
// to run on the upstream before the relay starts, the handler that judges each
// client statement, and an optional recorder for the ledger.
type Enforcement struct {
	Principal Principal
	Prime     []string
	Handler   Handler
	Recorder  Recorder
}

// Guard resolves the enforcement for a session from the client's identity.
// Resolve runs once, after the handshake.
type Guard interface {
	Resolve(startup Startup) Enforcement
}

type GuardFunc func(startup Startup) Enforcement

func (f GuardFunc) Resolve(startup Startup) Enforcement {
	return f(startup)
}

// AllowAll is a Guard whose sessions permit every statement and record nothing.
var AllowAll Guard = GuardFunc(func(s Startup) Enforcement {
	return Enforcement{
		Principal: Principal{User: s.User, Database: s.Database, Application: s.Application},
		Handler:   HandlerFunc(func(Statement) Verdict { return Verdict{} }),
	}
})

type Dialect interface {
	NewSession(client, upstream net.Conn) Session
}

// Session drives one client connection and its upstream connection.
// Handshake runs first and alone; Frontend and Backend then run concurrently
// until their side of the conversation ends.
type Session interface {
	Handshake() (Startup, error)
	// Prime runs one statement on the upstream and consumes its result before
	// the relay starts, for session setup such as enabling read-only mode. It
	// runs after Handshake and before Frontend and Backend.
	Prime(sql string) error
	Frontend(h Handler, rec Recorder) error
	Backend() error
}
