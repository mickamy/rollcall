package cli_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mickamy/rollcall/internal/cli"
	"github.com/mickamy/rollcall/internal/exit"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args     []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		"no arguments prints usage to stderr": {
			args:     nil,
			wantCode: exit.Usage,
			wantErr:  "Usage: " + cli.Name,
		},
		"help": {
			args:     []string{"help"},
			wantCode: exit.OK,
			wantOut:  "Commands:",
		},
		"version": {
			args:     []string{"--version"},
			wantCode: exit.OK,
			wantOut:  cli.Name + " ",
		},
		"unknown command": {
			args:     []string{"bogus"},
			wantCode: exit.Usage,
			wantErr:  `unknown command "bogus"`,
		},
		"proxy help": {
			args:     []string{"proxy", "-h"},
			wantCode: exit.OK,
			wantOut:  "Usage: " + cli.Name + " proxy",
		},
		"proxy help after flags": {
			args:     []string{"proxy", "-upstream", "127.0.0.1:5432", "-h"},
			wantCode: exit.OK,
			wantErr:  "Usage: " + cli.Name + " proxy",
		},
		"proxy with unknown flag": {
			args:     []string{"proxy", "-bogus"},
			wantCode: exit.Usage,
			wantErr:  "flag provided but not defined: -bogus",
		},
		"proxy with unexpected argument": {
			args:     []string{"proxy", "-upstream", "127.0.0.1:5432", "extra"},
			wantCode: exit.Usage,
			wantErr:  `unexpected argument "extra"`,
		},
		"proxy without upstream": {
			args:     []string{"proxy"},
			wantCode: exit.Error,
			wantErr:  cli.Name + ": -upstream is required\n",
		},
		"proxy with upstream lacking a port": {
			args:     []string{"proxy", "-upstream", "127.0.0.1"},
			wantCode: exit.Error,
			wantErr:  cli.Name + ": -upstream: address 127.0.0.1: missing port in address\n",
		},
		"proxy with empty listen": {
			args:     []string{"proxy", "-upstream", "127.0.0.1:5432", "-listen", ""},
			wantCode: exit.Error,
			wantErr:  cli.Name + ": -listen is required\n",
		},
		"proxy with unlistenable address": {
			args:     []string{"proxy", "-upstream", "127.0.0.1:5432", "-listen", "127.0.0.1:port"},
			wantCode: exit.Error,
			wantErr:  cli.Name + ": listen tcp",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out, errOut bytes.Buffer
			std := cli.IO{In: strings.NewReader(""), Out: &out, Err: &errOut}

			code := cli.Run(t.Context(), tt.args, std)

			if code != tt.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout: got %q, want it to contain %q", out.String(), tt.wantOut)
			}
			if !strings.Contains(errOut.String(), tt.wantErr) {
				t.Errorf("stderr: got %q, want it to contain %q", errOut.String(), tt.wantErr)
			}
		})
	}
}

func TestRunProxyStopsOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errOut := newNotifyWriter("msg=listening")
	code := make(chan int, 1)
	go func() {
		args := []string{"proxy", "-upstream", "127.0.0.1:0", "-listen", "127.0.0.1:0"}
		code <- cli.Run(ctx, args, cli.IO{In: strings.NewReader(""), Out: io.Discard, Err: errOut})
	}()

	select {
	case <-errOut.seen:
	case c := <-code:
		t.Fatalf("proxy exited with %d before listening (stderr: %q)", c, errOut.String())
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not start listening")
	}

	cancel()

	select {
	case c := <-code:
		if c != exit.OK {
			t.Errorf("exit code: got %d, want %d (stderr: %q)", c, exit.OK, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not stop after cancel")
	}
}

// notifyWriter closes seen once the accumulated output contains want.
type notifyWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	want string
	seen chan struct{}
	once sync.Once
}

func newNotifyWriter(want string) *notifyWriter {
	return &notifyWriter{want: want, seen: make(chan struct{})}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf.Write(p)
	if strings.Contains(w.buf.String(), w.want) {
		w.once.Do(func() { close(w.seen) })
	}

	return len(p), nil
}

func (w *notifyWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.buf.String()
}
