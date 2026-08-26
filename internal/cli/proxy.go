package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/mickamy/rollcall/internal/exit"
	"github.com/mickamy/rollcall/internal/proxy"
)

const (
	defaultListen = "127.0.0.1:6432"
	listenUsage   = "address to accept client connections on"
	upstreamUsage = "address of the upstream database"
)

func runProxy(ctx context.Context, args []string, std IO) int {
	fs := newFlagSet("proxy", std.Err, printProxyUsage)
	listen := fs.String("listen", defaultListen, listenUsage)
	upstream := fs.String("upstream", "", upstreamUsage)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exit.OK
		}

		return exit.Usage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(std.Err, "%s proxy: unexpected argument %q\n", Name, fs.Arg(0))

		return exit.Usage
	}

	if err := validateAddr("-upstream", *upstream); err != nil {
		return fail(std, err)
	}
	if err := validateAddr("-listen", *listen); err != nil {
		return fail(std, err)
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

func validateAddr(flagName, addr string) error {
	if addr == "" {
		return fmt.Errorf("%s is required", flagName)
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s: %w", flagName, err)
	}
	if port == "" {
		return fmt.Errorf("%s: %q has no port", flagName, addr)
	}

	return nil
}

func printProxyUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s proxy -upstream ADDR [-listen ADDR]\n\n", Name)
	fmt.Fprint(w, "Accept database connections and relay them to the upstream database.\n")
	fmt.Fprint(w, "Stops when interrupted.\n\n")
	fmt.Fprint(w, "Flags:\n")
	fmt.Fprintf(w, "  -upstream ADDR  %s (required)\n", upstreamUsage)
	fmt.Fprintf(w, "  -listen ADDR    %s (default %q)\n", listenUsage, defaultListen)
}
