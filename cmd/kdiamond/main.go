// Command kdiamond is the Kerberos Diamond key distribution centre.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/config"
	"github.com/FatmanUK/kerberos_diamond/internal/kdc"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/transport"
)

// version is set at link time; see the Makefile's LDFLAGS.
var version = "dev"

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
// Loading the configuration first is deliberate: a misconfigured
// deployment should fail on its environment, which is the error it
// can actually act on, rather than after binding a port.
func serve() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	mkey, err := store.DeriveMasterKey(c.Realm,
		c.MasterPassword, store.DefaultMasterKeyType)
	if err != nil {
		return err
	}
	s, err := store.Open(c.DatabaseURL, mkey)
	if err != nil {
		return err
	}
	defer s.Close()
	return listen(c, s)
}

// listen runs the HTTPS listener until a signal arrives.
//
// There is no cleartext listener and no raw-TCP listener, so "TLS
// only" holds literally: a client either speaks KKDCP over HTTPS or
// goes through kdiamond-proxy.
func listen(c *config.Config, s *store.Store) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	k := &kdc.KDC{
		Store:     s,
		Realm:     c.Realm,
		ClockSkew: c.ClockSkew,
	}
	mux := http.NewServeMux()
	mux.Handle("/", &transport.Handler{
		Path:   c.ProxyPath,
		Handle: k.Handle,
		Log:    log,
	})
	srv := &http.Server{
		Addr:              c.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Info("kdiamond listening", "addr", c.ListenAddr,
		"realm", c.Realm, "path", c.ProxyPath)
	err := srv.ListenAndServeTLS(c.TLSCertFile, c.TLSKeyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
