package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mickamy/rollcall/internal/proxy"
	"github.com/mickamy/rollcall/internal/wire"
)

const (
	timeout = 5 * time.Second

	// Nothing listens on port 0, so dials fail immediately without reserving a port
	// that a parallel test could pick up.
	unreachable = "127.0.0.1:0"
)

func TestServeRelaysBothDirections(t *testing.T) {
	t.Parallel()

	upstream := startEcho(t)
	addr, cancel, wait := startProxy(t, upstream)

	client := dial(t, addr)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := make([]byte, 5)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("echo: got %q, want %q", got, "hello")
	}

	cancel()
	if err := wait(); err != nil {
		t.Errorf("Serve: got %v, want nil after cancel", err)
	}

	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("client connection still open after shutdown")
	}
}

func TestServePropagatesHalfClose(t *testing.T) {
	t.Parallel()

	upstream := startEcho(t)
	addr, cancel, wait := startProxy(t, upstream)
	defer func() {
		cancel()
		_ = wait()
	}()

	client := dial(t, addr)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("echo after half-close: got %q, want %q", got, "hello")
	}
}

func TestServeClosesClientWhenUpstreamIsUnreachable(t *testing.T) {
	t.Parallel()

	addr, cancel, wait := startProxy(t, unreachable)
	defer func() {
		cancel()
		_ = wait()
	}()

	client := dial(t, addr)

	_, err := client.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Errorf("read: got %v, want %v", err, io.EOF)
	}
}

func TestServeReturnsAcceptError(t *testing.T) {
	t.Parallel()

	ln := listen(t)
	errc := make(chan error, 1)
	go func() {
		errc <- proxy.Server{Upstream: unreachable, Dialect: rawDialect{}}.Serve(t.Context(), ln)
	}()

	_ = ln.Close()

	select {
	case err := <-errc:
		if err == nil || !strings.HasPrefix(err.Error(), "accept: ") {
			t.Errorf("Serve: got %v, want an accept error", err)
		}
	case <-time.After(timeout):
		t.Fatal("Serve did not return after the listener was closed")
	}
}

func TestServeRequiresDialect(t *testing.T) {
	t.Parallel()

	ln := listen(t)
	defer func() { _ = ln.Close() }()

	err := proxy.Server{Upstream: unreachable}.Serve(t.Context(), ln)
	if err == nil || !strings.Contains(err.Error(), "Dialect is required") {
		t.Errorf("Serve: got %v, want a missing Dialect error", err)
	}
}

// rawDialect relays bytes without interpreting them, so the proxy's lifecycle
// can be tested against a plain echo server.
type rawDialect struct{}

func (rawDialect) NewSession(client, upstream net.Conn) wire.Session {
	return rawSession{client: client, upstream: upstream}
}

type rawSession struct {
	client   net.Conn
	upstream net.Conn
}

func (rawSession) Handshake() (wire.Startup, error) {
	return wire.Startup{User: "raw"}, nil
}

func (rawSession) Prime(string) error {
	return nil
}

func (s rawSession) Frontend(wire.Handler, wire.Recorder) error {
	if _, err := io.Copy(s.upstream, s.client); err != nil {
		return fmt.Errorf("frontend: %w", err)
	}

	return nil
}

func (s rawSession) Backend() error {
	if _, err := io.Copy(s.client, s.upstream); err != nil {
		return fmt.Errorf("backend: %w", err)
	}

	return nil
}

func startProxy(t *testing.T, upstream string) (addr string, cancel context.CancelFunc, wait func() error) {
	t.Helper()

	ln := listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errc := make(chan error, 1)
	go func() {
		errc <- proxy.Server{Upstream: upstream, Dialect: rawDialect{}}.Serve(ctx, ln)
	}()

	wait = func() error {
		select {
		case err := <-errc:
			return err
		case <-time.After(timeout):
			t.Fatal("Serve did not return")

			return nil
		}
	}

	return ln.Addr().String(), cancel, wait
}

func startEcho(t *testing.T) string {
	t.Helper()

	ln := listen(t)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().String()
}

func listen(t *testing.T) net.Listener {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	return ln
}

func dial(t *testing.T, addr string) *net.TCPConn {
	t.Helper()

	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("dial %s: got %T, want *net.TCPConn", addr, conn)
	}

	return tcp
}
