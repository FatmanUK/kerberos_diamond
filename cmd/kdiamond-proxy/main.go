// Command kdiamond-proxy carries Kerberos messages over TLS for
// clients that cannot do it themselves.
//
// Kerberos Diamond's KDC has no cleartext listener: it is an HTTPS
// server speaking MS-KKDCP. A client reaches it directly only if it
// was built with a TLS module — Kerberos 5 needs its k5tls plugin,
// which in turn needs OpenSSL at build time. Clients built without
// one point at this proxy instead, which listens for plain Kerberos
// TCP and forwards each message to the KDC inside TLS.
//
// The listener is loopback-only and the hop to it is cleartext, so
// this moves the TLS boundary rather than removing it. It belongs on
// the client's own host.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
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
	_ = *listen
	return errors.New("not implemented yet")
}
