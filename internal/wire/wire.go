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

type Dialect interface {
	NewSession(client, upstream net.Conn) Session
}

// Session drives one client connection and its upstream connection.
// Handshake runs first and alone; Frontend and Backend then run concurrently
// until their side of the conversation ends.
type Session interface {
	Handshake() (Startup, error)
	Frontend(h Handler) error
	Backend() error
}
