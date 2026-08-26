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
		"hello with default name": {
			args:     []string{"hello"},
			wantCode: exit.OK,
			wantOut:  "Hello, world!\n",
		},
		"hello with name": {
			args:     []string{"hello", "-name", "Go"},
			wantCode: exit.OK,
			wantOut:  "Hello, Go!\n",
		},
		"hello help": {
			args:     []string{"hello", "-h"},
			wantCode: exit.OK,
			wantOut:  "Usage: " + cli.Name + " hello",
		},
		"hello with unknown flag": {
			args:     []string{"hello", "-bogus"},
			wantCode: exit.Usage,
			wantErr:  "flag provided but not defined: -bogus",
		},
		"hello with unexpected argument": {
			args:     []string{"hello", "extra"},
			wantCode: exit.Usage,
			wantErr:  `unexpected argument "extra"`,
		},
		"hello with empty name": {
			args:     []string{"hello", "-name", ""},
			wantCode: exit.Error,
			wantErr:  cli.Name + ": name must not be empty\n",
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

func TestRunCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var out, errOut bytes.Buffer
	code := cli.Run(ctx, []string{"hello"}, cli.IO{In: strings.NewReader(""), Out: &out, Err: &errOut})

	if code != exit.Error {
		t.Errorf("exit code: got %d, want %d", code, exit.Error)
	}
	if !strings.Contains(errOut.String(), context.Canceled.Error()) {
		t.Errorf("stderr: got %q, want it to mention %q", errOut.String(), context.Canceled)
	}
}
