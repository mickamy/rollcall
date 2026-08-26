package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mickamy/rollcall/internal/wire"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 30 * time.Second
	minAcceptDelay   = 5 * time.Millisecond
	maxAcceptDelay   = time.Second
)

// Server accepts client connections and drives each one through Dialect
// against a connection to Upstream.
type Server struct {
	Upstream string
	Dialect  wire.Dialect
	// Handler decides each statement; nil allows everything.
	Handler wire.Handler
	Logger  *slog.Logger
}

func (s Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Dialect == nil {
		return errors.New("proxy: Dialect is required")
	}
	if s.Handler == nil {
		s.Handler = wire.HandlerFunc(func(wire.Statement) wire.Verdict { return wire.Verdict{} })
	}
	if s.Logger == nil {
		s.Logger = slog.New(slog.DiscardHandler)
	}

	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	context.AfterFunc(ctx, func() { _ = ln.Close() })

	var delay time.Duration
	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("accept: %w", err)
			}

			delay = nextDelay(delay)
			s.Logger.Warn("accept", "error", err, "retry_in", delay)
			if !sleep(ctx, delay) {
				return nil
			}

			continue
		}
		delay = 0

		wg.Go(func() { s.handle(ctx, client) })
	}
}

func (s Server) handle(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	logger := s.Logger.With("client", client.RemoteAddr().String())

	dialer := net.Dialer{Timeout: dialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", s.Upstream)
	if err != nil {
		if ctx.Err() == nil {
			logger.Error("dial upstream", "upstream", s.Upstream, "error", err)
		}

		return
	}
	defer func() { _ = upstream.Close() }()

	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stop()

	sess := s.Dialect.NewSession(client, upstream)
	startup, err := handshake(sess, client, upstream)
	if err != nil {
		switch {
		case ctx.Err() != nil:
		case errors.Is(err, wire.ErrNoSession):
			logger.Debug("out-of-band request relayed")
		case errors.Is(err, wire.ErrRejected):
			logger.Info("session rejected", "user", startup.User, "database", startup.Database, "error", err)
		default:
			logger.Warn("handshake", "error", err)
		}

		return
	}

	logger = logger.With("user", startup.User, "database", startup.Database, "application", startup.Application)
	logger.Info("session opened")

	var wg sync.WaitGroup
	var toUpstream, toClient error
	wg.Go(func() {
		toUpstream = sess.Frontend(s.Handler)
		closeWrite(upstream)
	})
	wg.Go(func() {
		toClient = sess.Backend()
		closeWrite(client)
	})
	wg.Wait()

	for _, err := range []error{toUpstream, toClient} {
		if abnormal(err) {
			logger.Warn("relay", "error", err)
		}
	}

	logger.Info("session closed")
}

// handshake bounds the handshake with a deadline on both connections and lifts
// it again once the session is established.
func handshake(sess wire.Session, conns ...net.Conn) (wire.Startup, error) {
	deadline := time.Now().Add(handshakeTimeout)
	for _, c := range conns {
		_ = c.SetDeadline(deadline)
	}

	startup, err := sess.Handshake()

	for _, c := range conns {
		_ = c.SetDeadline(time.Time{})
	}

	if err != nil {
		return startup, fmt.Errorf("handshake: %w", err)
	}

	return startup, nil
}

type closeWriter interface {
	CloseWrite() error
}

// closeWrite passes the end of one direction on as a half-close so that the
// peer can still drain the other direction.
func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()

		return
	}

	_ = c.Close()
}

func abnormal(err error) bool {
	return err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF)
}

func nextDelay(d time.Duration) time.Duration {
	if d == 0 {
		return minAcceptDelay
	}

	return min(d*2, maxAcceptDelay)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
