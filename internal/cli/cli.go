package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/mickamy/rollcall/internal/exit"
	"github.com/mickamy/rollcall/internal/version"
)

const Name = "rollcall"

type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, std IO) int
	usage   func(w io.Writer)
}

var commands = []command{
	{
		name:    "hello",
		summary: "Print a greeting",
		run:     runHello,
		usage:   printHelloUsage,
	},
}

func Run(ctx context.Context, args []string, std IO) int {
	if len(args) == 0 {
		PrintUsage(std.Err)

		return exit.Usage
	}

	switch args[0] {
	case "help", "-h", "--help":
		PrintUsage(std.Out)

		return exit.OK
	case "version", "-v", "--version":
		fmt.Fprintf(std.Out, "%s %s\n", Name, version.String())

		return exit.OK
	}

	cmd, ok := lookup(args[0])
	if !ok {
		fmt.Fprintf(std.Err, "%s: unknown command %q\n\n", Name, args[0])
		PrintUsage(std.Err)

		return exit.Usage
	}

	rest := args[1:]
	if wantsHelp(rest) {
		cmd.usage(std.Out)

		return exit.OK
	}

	return cmd.run(ctx, rest, std)
}

func PrintUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s <command> [flags]\n\nCommands:\n", Name)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
	}
	fmt.Fprintf(tw, "  %s\t%s\n", "help", "Show this help")
	fmt.Fprintf(tw, "  %s\t%s\n", "version", "Show the version")
	_ = tw.Flush() // usage output: nothing useful to do with a write error

	fmt.Fprintf(w, "\nRun '%s <command> -h' for help on a command.\n", Name)
}

func lookup(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}

	return command{}, false
}

func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			return true
		}
	}

	return false
}

func newFlagSet(name string, w io.Writer, usage func(io.Writer)) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	fs.Usage = func() { usage(w) }

	return fs
}

func fail(std IO, err error) int {
	fmt.Fprintf(std.Err, "%s: %v\n", Name, err)

	return exit.Error
}
