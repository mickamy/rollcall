package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mickamy/rollcall/internal/exit"
	"github.com/mickamy/rollcall/internal/proxy"
)

func runProxy(ctx context.Context, args []string, std IO) int {
	fs := newFlagSet("proxy", std.Err, printProxyUsage)
	listen := fs.String("listen", "127.0.0.1:6432", "address to accept client connections on")
	upstream := fs.String("upstream", "", "address of the upstream database")
	if err := fs.Parse(args); err != nil {
		return exit.Usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(std.Err, "%s proxy: unexpected argument %q\n", Name, fs.Arg(0))

		return exit.Usage
	}

	if *upstream == "" {
		return fail(std, errors.New("-upstream is required"))
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		return fail(std, err)
	}
	defer func() { _ = ln.Close() }()

	logger := slog.New(slog.NewTextHandler(std.Err, nil))
	logger.Info("listening", "addr", ln.Addr().String(), "upstream", *upstream)

	srv := proxy.Server{Upstream: *upstream, Logger: logger}
	if err := srv.Serve(ctx, ln); err != nil {
		return fail(std, err)
	}

	return exit.OK
}

func printProxyUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s proxy -upstream ADDR [-listen ADDR]\n\n", Name)
	fmt.Fprint(w, "Accept database connections and relay them to the upstream database.\n")
	fmt.Fprint(w, "Stops when interrupted.\n\n")
	fmt.Fprint(w, "Flags:\n")
	fmt.Fprint(w, "  -upstream ADDR  address of the upstream database (required)\n")
	fmt.Fprint(w, "  -listen ADDR    address to accept client connections on (default \"127.0.0.1:6432\")\n")
}
