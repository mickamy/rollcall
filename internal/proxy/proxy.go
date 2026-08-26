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
)

const (
	dialTimeout    = 10 * time.Second
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second
)

// Server relays every accepted connection to Upstream byte for byte.
type Server struct {
	Upstream string
	Logger   *slog.Logger
}

func (s Server) Serve(ctx context.Context, ln net.Listener) error {
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

	logger.Debug("session opened")

	var wg sync.WaitGroup
	var toUpstream, toClient error
	wg.Go(func() { toUpstream = relay(upstream, client) })
	wg.Go(func() { toClient = relay(client, upstream) })
	wg.Wait()

	for _, err := range []error{toUpstream, toClient} {
		if abnormal(err) {
			logger.Warn("relay", "error", err)
		}
	}

	logger.Debug("session closed")
}

type closeWriter interface {
	CloseWrite() error
}

// relay copies src to dst until src is done, then passes the end of stream on
// to dst as a half-close so that dst's owner can still drain the other direction.
func relay(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)

	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}

	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return nil
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
