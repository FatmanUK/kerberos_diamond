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
  kdiamond serve                  run the KDC
  kdiamond version                print the version and exit

principal administration, standing in for kadmin:
  kdiamond addprinc -pw PW [-kvno N] [-maxlife D]
                    [-maxrenewlife D] [-attr SPEC] PRINC
  kdiamond modprinc [-maxlife D] [-maxrenewlife D]
                    [-attr SPEC] PRINC
  kdiamond cpw -pw PW PRINC       change a password, bumping the kvno
  kdiamond delprinc PRINC         remove a principal
  kdiamond getprinc PRINC         print what the KDC knows
  kdiamond listprincs             print every principal's name
  kdiamond ktadd -k FILE [-norandkey] PRINC
                                  write keys into a keytab

ktadd re-keys the principal unless -norandkey is given, because a
keytab is a copy of a secret and handing one out without changing the
key would leave every previous copy working. That is kadmin's
behaviour too.

An attribute SPEC is kadmin's, sign included: +requires_preauth,
-allow_tix, +forwardable and so on. Most are inverted -- +forwardable
*clears* DISALLOW_FORWARDABLE -- so read them as what the principal is
permitted, not as which bit is set.
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

	rest := fs.Args()
	switch cmd := fs.Arg(0); cmd {
	case "serve":
		return serve()
	case "version":
		fmt.Println(version)
		return nil
	case "addprinc":
		return addprinc(rest[1:])
	case "modprinc":
		return modprinc(rest[1:])
	case "cpw":
		return cpw(rest[1:])
	case "delprinc":
		return delprinc(rest[1:])
	case "getprinc":
		return getprinc(rest[1:])
	case "listprincs":
		return listprincs(rest[1:])
	case "ktadd", "xst":
		return ktadd(rest[1:])
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
	c, err := config.Load(config.Serve)
	if err != nil {
		return err
	}
	mkey, err := store.DeriveMasterKeyWith(c.MasterKDF,
		c.Realm, c.MasterPassword,
		store.DefaultMasterKeyType)
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
//
// The process holds nothing that a restart would have to rebuild.
// Every principal and key is in Postgres; the master key is derived
// from the environment; an exchange carries no state past its reply.
// So several of these can serve one realm behind one address, and any
// of them can be killed at any moment -- which is the whole of this
// project's crash-only claim and what the HA tests in internal/golden
// check.
func listen(c *config.Config, s *store.Store) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv := &http.Server{
		Addr:              c.ListenAddr,
		Handler:           routes(c, s, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Close, not Shutdown: a signal ends the process abruptly and
	// that is the only stopping path there is.
	//
	// Nothing needs draining. An AS or TGS exchange is a single
	// request with no state carried past the reply -- no replay
	// cache, no session table, nothing written to the database --
	// so a connection cut mid-flight costs the client one retry
	// and costs this KDC nothing. Draining would make stopping
	// slower without making it safer, and it would create a
	// second stopping path that a crash does not exercise.
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Info("kdiamond listening", "addr", c.ListenAddr,
		"realm", c.Realm, "path", c.ProxyPath,
		"master-kdf", string(s.MasterKey().KDF))
	err := srv.ListenAndServeTLS(c.TLSCertFile, c.TLSKeyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// routes are the two the KDC serves: the readiness probe a load
// balancer needs, and everything else to the KKDCP handler.
func routes(
	c *config.Config,
	s *store.Store,
	log *slog.Logger,
) http.Handler {
	k := &kdc.KDC{
		Store:     s,
		Realm:     c.Realm,
		ClockSkew: c.ClockSkew,
		Paths:     c.Paths,

		Hosts:             c.Hosts,
		HostBasedServices: c.HostBasedServices,
		NoHostReferral:    c.NoHostReferral,
	}
	mux := http.NewServeMux()
	mux.Handle(transport.HealthPath, &transport.Health{
		Check: s.Ping,
		Log:   log,
	})
	mux.Handle("/", &transport.Handler{
		Path:   c.ProxyPath,
		Handle: k.Handle,
		Log:    log,
	})
	return mux
}
