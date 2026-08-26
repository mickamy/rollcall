package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/mickamy/rollcall/internal/exit"
)

func runHello(ctx context.Context, args []string, std IO) int {
	fs := newFlagSet("hello", std.Err, printHelloUsage)
	name := fs.String("name", "world", "who to greet")
	if err := fs.Parse(args); err != nil {
		return exit.Usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(std.Err, "%s hello: unexpected argument %q\n", Name, fs.Arg(0))

		return exit.Usage
	}

	if *name == "" {
		return fail(std, errors.New("name must not be empty"))
	}

	select {
	case <-ctx.Done():
		return fail(std, ctx.Err())
	default:
	}

	fmt.Fprintf(std.Out, "Hello, %s!\n", *name)

	return exit.OK
}

func printHelloUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s hello [-name NAME]\n\n", Name)
	fmt.Fprint(w, "Print a greeting.\n\n")
	fmt.Fprint(w, "Flags:\n")
	fmt.Fprint(w, "  -name NAME  who to greet (default \"world\")\n")
}
