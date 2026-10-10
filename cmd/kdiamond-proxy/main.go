// Command kdiamond-proxy carries Kerberos messages over TLS for
// clients that cannot do it themselves.
//
// Diamond's KDC has no cleartext listener: it is an HTTPS server
// speaking MS-KKDCP. A client reaches it directly only if it was
// built with a TLS module — Kerberos 5 needs its k5tls plugin,
// which in turn needs OpenSSL at build time. Clients built without
// one point at this proxy instead, which listens for plain Kerberos
// TCP and forwards each message to the KDC inside TLS.
//
// The listener is loopback-only and the hop to it is cleartext, so
// this moves the TLS boundary rather than removing it. It belongs on
// the client's own host.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/transport"
)

// version is set at link time; see the Makefile's LDFLAGS.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kdiamond-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("kdiamond-proxy", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8088",
		"host:port to accept plain Kerberos TCP on")
	kdc := fs.String("kdc", "",
		"KDC URL, e.g. https://kdc.example:8088/KdcProxy")
	realm := fs.String("realm", "",
		"realm to send as target-domain")
	showVersion := fs.Bool("version", false,
		"print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *kdc == "" {
		fs.Usage()
		return errors.New("-kdc is required")
	}
	return forward(*listen, *kdc, *realm)
}

// forward runs the shim until a signal arrives.
//
// The listener is bound before anything else so that a port already
// in use fails immediately rather than after the first client
// connects.
func forward(listen, kdc, realm string) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	l, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer l.Close()
	go func() {
		<-ctx.Done()
		l.Close()
	}()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	log.Info("kdiamond-proxy listening",
		"addr", l.Addr().String(), "kdc", kdc)
	s := &transport.Shim{
		Client: &transport.Client{
			URL:   kdc,
			Realm: realm,
		},
		Timeout: 60 * time.Second,
		Log:     log,
	}
	return s.Serve(ctx, l)
}
