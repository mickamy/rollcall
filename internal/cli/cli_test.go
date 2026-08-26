package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

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

func TestRunProxyStopsWhenCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var out, errOut bytes.Buffer
	args := []string{"proxy", "-upstream", "127.0.0.1:5432", "-listen", "127.0.0.1:0"}
	code := cli.Run(ctx, args, cli.IO{In: strings.NewReader(""), Out: &out, Err: &errOut})

	if code != exit.OK {
		t.Errorf("exit code: got %d, want %d (stderr: %q)", code, exit.OK, errOut.String())
	}
	if !strings.Contains(errOut.String(), "msg=listening") {
		t.Errorf("stderr: got %q, want it to log that it listened", errOut.String())
	}
}
