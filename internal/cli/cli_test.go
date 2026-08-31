package cli_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mickamy/rollcall/internal/cli"
	"github.com/mickamy/rollcall/internal/exit"
	"github.com/mickamy/rollcall/internal/ledger"
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
		"proxy with a missing policy file": {
			args:     []string{"proxy", "-upstream", "127.0.0.1:5432", "-policy", "/no/such/policy.yaml"},
			wantCode: exit.Error,
			wantErr:  cli.Name + ": read policy:",
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

func TestIsLoopback(t *testing.T) {
	t.Parallel()

	tests := map[string]bool{
		"127.0.0.1:6432":   true,
		"[::1]:6432":       true,
		"localhost:6432":   true,
		"0.0.0.0:6432":     false,
		"[::]:6432":        false,
		":6432":            false,
		"10.0.0.5:6432":    false,
		"db.internal:6432": false,
		"garbage":          false,
	}

	for addr, want := range tests {
		if got := cli.IsLoopback(addr); got != want {
			t.Errorf("isLoopback(%q): got %v, want %v", addr, got, want)
		}
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

func TestRunProxyServesPostgreSQL(t *testing.T) {
	t.Parallel()

	upstream := startFakePostgres(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errOut := newNotifyWriter("msg=listening")
	code := make(chan int, 1)
	go func() {
		args := []string{"proxy", "-upstream", upstream, "-listen", "127.0.0.1:0"}
		code <- cli.Run(ctx, args, cli.IO{In: strings.NewReader(""), Out: io.Discard, Err: errOut})
	}()

	select {
	case <-errOut.seen:
	case c := <-code:
		t.Fatalf("proxy exited with %d before listening (stderr: %q)", c, errOut.String())
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not start listening")
	}

	addr := regexp.MustCompile(`addr=(\S+)`).FindStringSubmatch(errOut.String())
	if addr == nil {
		t.Fatalf("stderr: got %q, want the listening address", errOut.String())
	}

	var dialer net.Dialer
	client, err := dialer.DialContext(ctx, "tcp", addr[1])
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	writeAll(t, client, startupPacket("user", "alice", "database", "app"))
	expectMessage(t, client, pgMessage('R', be32(0)))
	expectMessage(t, client, pgMessage('Z', []byte("I")))

	writeAll(t, client, pgMessage('Q', cstring("select 1")))
	expectMessage(t, client, pgMessage('C', cstring("SELECT 1")))
	expectMessage(t, client, pgMessage('Z', []byte("I")))

	writeAll(t, client, pgMessage('X'))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after Terminate")
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

	for _, want := range []string{"msg=\"session opened\"", "user=alice", "database=app", "msg=\"session closed\""} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr: got %q, want it to contain %q", errOut.String(), want)
		}
	}
}

func TestRunProxyLedgerRecordsPreparedExecutions(t *testing.T) {
	t.Parallel()

	upstream := startFakePostgres(t)
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errOut := newNotifyWriter("msg=listening")
	code := make(chan int, 1)
	go func() {
		args := []string{"proxy", "-upstream", upstream, "-listen", "127.0.0.1:0", "-ledger", ledgerPath}
		code <- cli.Run(ctx, args, cli.IO{In: strings.NewReader(""), Out: io.Discard, Err: errOut})
	}()

	select {
	case <-errOut.seen:
	case c := <-code:
		t.Fatalf("proxy exited with %d before listening", c)
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not start listening")
	}
	addr := regexp.MustCompile(`addr=(\S+)`).FindStringSubmatch(errOut.String())[1]

	var dialer net.Dialer
	client, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	writeAll(t, client, startupPacket("user", "agent", "database", "app"))
	expectMessage(t, client, pgMessage('R', be32(0)))
	expectMessage(t, client, pgMessage('Z', []byte("I")))

	// Prepare once, then re-execute in a second batch that carries no Parse.
	parse := pgMessage('P', cstring("ps1"), cstring("select id from t where id > $1"), be16(0))
	bind := pgMessage('B', cstring(""), cstring("ps1"), be16(0), be16(0), be16(0))
	exec := pgMessage('E', cstring(""), be32(0))
	sync := pgMessage('S')
	writeAll(t, client, bytes.Join([][]byte{parse, bind, exec, sync}, nil))
	readUntilReadyForQuery(t, client)
	writeAll(t, client, bytes.Join([][]byte{bind, exec, sync}, nil))
	readUntilReadyForQuery(t, client)

	writeAll(t, client, pgMessage('X'))
	_, _ = client.Read(make([]byte, 1))
	cancel()
	<-code

	records := readLedger(t, ledgerPath)
	if len(records) != 2 {
		t.Fatalf("ledger records: got %d, want 2 (prepare + reuse)", len(records))
	}
	for i, r := range records {
		if r.Kind != "SELECT" || r.Decision != "allowed" || r.Rows != 1 {
			t.Errorf("record %d: got %+v, want an allowed SELECT with 1 row", i, r)
		}
		if strings.Contains(r.Fingerprint, "1") {
			t.Errorf("record %d fingerprint kept a literal: %q", i, r.Fingerprint)
		}
	}
	if records[1].PrevHash != records[0].Hash {
		t.Error("ledger records are not chained")
	}
}

func readUntilReadyForQuery(t *testing.T, r io.Reader) {
	t.Helper()

	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			t.Fatalf("read: %v", err)
		}
		if _, err := io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint32(header[1:]))-4); err != nil {
			t.Fatalf("read body: %v", err)
		}
		if header[0] == 'Z' {
			return
		}
	}
}

func readLedger(t *testing.T, path string) []ledger.Record {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	var out []ledger.Record
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec ledger.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		out = append(out, rec)
	}

	return out
}

// startFakePostgres serves trust authentication and answers every simple
// query with "SELECT 1" until the client terminates.
func startFakePostgres(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			go serveFakePostgres(conn)
		}
	}()

	return ln.Addr().String()
}

func serveFakePostgres(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	length := make([]byte, 4)
	if _, err := io.ReadFull(conn, length); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint32(length))-4); err != nil {
		return
	}
	if _, err := conn.Write(bytes.Join([][]byte{pgMessage('R', be32(0)), pgMessage('Z', []byte("I"))}, nil)); err != nil {
		return
	}

	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint32(header[1:]))-4); err != nil {
			return
		}

		switch header[0] {
		case 'Q':
			reply := bytes.Join([][]byte{pgMessage('C', cstring("SELECT 1")), pgMessage('Z', []byte("I"))}, nil)
			if _, err := conn.Write(reply); err != nil {
				return
			}
		case 'S': // Sync: answer the batch with a one-row result set
			reply := bytes.Join([][]byte{
				pgMessage('T', be16(1), cstring("id"), be32(0), be16(0), be32(23), be16(4), be32(0xffffffff), be16(0)),
				pgMessage('D', be16(1), be32(1), []byte("7")),
				pgMessage('C', cstring("SELECT 1")),
				pgMessage('Z', []byte("I")),
			}, nil)
			if _, err := conn.Write(reply); err != nil {
				return
			}
		case 'X':
			return
		}
	}
}

func be32(v uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, v)
}

func be16(v uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, v)
}

func cstring(s string) []byte {
	return append([]byte(s), 0)
}

func pgMessage(typ byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	out := []byte{typ}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // test payloads are tiny

	return append(out, body...)
}

func startupPacket(params ...string) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint32(body, 196608)
	for _, p := range params {
		body = append(body, cstring(p)...)
	}
	body = append(body, 0)

	out := binary.BigEndian.AppendUint32(nil, uint32(len(body)+4)) //nolint:gosec // test payloads are tiny

	return append(out, body...)
}

func writeAll(t *testing.T, w io.Writer, b []byte) {
	t.Helper()

	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func expectMessage(t *testing.T, r io.Reader, want []byte) {
	t.Helper()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("message: got %q, want %q", got, want)
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
