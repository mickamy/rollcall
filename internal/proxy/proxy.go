package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// Server relays every accepted connection to Upstream byte for byte.
type Server struct {
	Upstream string
	Logger   *slog.Logger
}

func (s Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return fmt.Errorf("accept: %w", err)
		}

		wg.Go(func() { s.handle(ctx, client) })
	}
}

func (s Server) handle(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	var dialer net.Dialer
	upstream, err := dialer.DialContext(ctx, "tcp", s.Upstream)
	if err != nil {
		s.logger().Error("dial upstream", "upstream", s.Upstream, "client", client.RemoteAddr().String(), "error", err)

		return
	}
	defer func() { _ = upstream.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = upstream.Close()
	}()

	done := make(chan struct{}, 2)
	go relay(upstream, client, done)
	go relay(client, upstream, done)

	<-done
	cancel()
	<-done
}

func (s Server) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}

	return s.Logger
}

func relay(dst io.Writer, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	done <- struct{}{}
}
