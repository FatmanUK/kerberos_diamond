// Command kdiamond is the Kerberos Diamond key distribution centre.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/FatmanUK/kerberos_diamond/internal/config"
)

// version is set at link time; see the Makefile's LDFLAGS.
var version = "dev"

// errNotImplemented is what every subcommand returns until the KDC
// exists. It is deliberately not a silent success: a container that
// starts and does nothing is worse than one that refuses to.
var errNotImplemented = errors.New("not implemented yet")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kdiamond: %v\n", err)
		os.Exit(1)
	}
}

// usage names the subcommands, on stderr, for a bad invocation.
func usage() {
	fmt.Fprintf(os.Stderr, `kdiamond %s

usage:
  kdiamond serve        run the KDC
  kdiamond version      print the version and exit
`, version)
}

func run(args []string) error {
	fs := flag.NewFlagSet("kdiamond", flag.ContinueOnError)
	fs.Usage = usage
	showVersion := fs.Bool("version", false,
		"print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	switch cmd := fs.Arg(0); cmd {
	case "serve":
		return serve()
	case "version":
		fmt.Println(version)
		return nil
	case "":
		usage()
		return errors.New("no subcommand given")
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", cmd)
	}
}

// serve loads the configuration and starts the KDC.
//
// Loading the configuration first is deliberate even while the rest
// is unwritten: a misconfigured deployment should fail on its
// environment, which is the error it can actually act on.
func serve() error {
	if _, err := config.Load(); err != nil {
		return err
	}
	return errNotImplemented
}
