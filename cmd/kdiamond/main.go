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
	"github.com/FatmanUK/kerberos_diamond/internal/kadm5"
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
                    [-attr SPEC] [-policy NAME] [-unlock] PRINC
  kdiamond renprinc OLD NEW       rename a principal
  kdiamond alias ALIAS TARGET     name a principal twice
  kdiamond unalias ALIAS          remove an alias, keeping its target
  kdiamond cpw -pw PW PRINC       change a password, bumping the kvno
  kdiamond delprinc PRINC         remove a principal
  kdiamond getprinc PRINC         print what the KDC knows
  kdiamond listprincs             print every principal's name
  kdiamond ktadd -k FILE [-norandkey] [-keepold] PRINC
                                  write keys into a keytab
  kdiamond purgekeys PRINC        drop every key below the current
`, version)
	usagePolicies()
}

// usagePolicies is the second half, split off only to keep one
// function under this project's forty-line rule.
func usagePolicies() {
	fmt.Fprint(os.Stderr, `
ktadd re-keys the principal unless -norandkey is given, because a
keytab is a copy of a secret and handing one out without changing the
key would leave every previous copy working. That is kadmin's
behaviour too. -keepold on it or on cpw keeps the previous version as
well, so that tickets already issued under it go on verifying until
they expire; purgekeys removes it afterwards.

password policies, also kadmin's:
  kdiamond addpol [-minlife D] [-maxlife D] [-minlength N]
                  [-minclasses N] [-history N] POLICY
  kdiamond modpol [same flags] POLICY
  kdiamond delpol POLICY          remove a policy nothing names
  kdiamond getpol POLICY          print one
  kdiamond getpols                name every policy

A principal names a policy with modprinc -policy, and the policy
constrains the passwords set for it. A principal naming no policy is
unconstrained, which is not the same as naming one whose values are
all defaults.

An attribute SPEC is kadmin's, sign included: +requires_preauth,
-allow_tix, +forwardable and so on. Most are inverted -- +forwardable
*clears* DISALLOW_FORWARDABLE -- so read them as what the principal is
permitted, not as which bit is set.
`)
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
	cmd := fs.Arg(0)
	switch cmd {
	case "serve":
		return serve()
	case "version":
		fmt.Println(version)
		return nil
	case "":
		usage()
		return errors.New("no subcommand given")
	}
	if fn := adminCommand(cmd); fn != nil {
		return fn(rest[1:])
	}
	usage()
	return fmt.Errorf("unknown subcommand %q", cmd)
}

// adminCommand maps a subcommand name to its handler, or nil.
//
// A table rather than a switch because the aliases are part of the
// vocabulary: kadmin's own ktadd is also xst and its getpols is also
// listpols, and an operator who types either should be answered.
func adminCommand(cmd string) func([]string) error {
	return map[string]func([]string) error{
		"addprinc":        addprinc,
		"ank":             addprinc,
		"modprinc":        modprinc,
		"renprinc":        renprinc,
		"alias":           alias,
		"add_alias":       alias,
		"unalias":         unalias,
		"cpw":             cpw,
		"change_password": cpw,
		"delprinc":        delprinc,
		"getprinc":        getprinc,
		"listprincs":      listprincs,
		"ktadd":           ktadd,
		"purgekeys":       purgekeys,
		"xst":             ktadd,
		"addpol":          addpol,
		"modpol":          modpol,
		"delpol":          delpol,
		"getpol":          getpol,
		"getpols":         getpols,
		"listpols":        getpols,
	}[cmd]
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
	s.SetEnctypes(c.Enctypes)
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
		"admin", kadm5.Prefix,
		"master-kdf", string(s.MasterKey().KDF))
	err := srv.ListenAndServeTLS(c.TLSCertFile, c.TLSKeyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// routes are the three the KDC serves: the readiness probe a load
// balancer needs, the administrative surface, and everything else to
// the KKDCP handler.
//
// /kadm5/ goes first because "/" catches everything, and it needs no
// listener and no port of its own -- which is most of the argument
// for an HTTPS administrative surface rather than a port of kadmin's
// RPC. The same certificate, the same address, the same process.
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
		AdminACL:  c.AdminACL,

		SPAKEGroups:     c.SPAKEGroups,
		SPAKEIndicators: c.SPAKEIndicators,
		DisablePAC:      c.DisablePAC,

		Hosts:             c.Hosts,
		HostBasedServices: c.HostBasedServices,
		NoHostReferral:    c.NoHostReferral,
	}
	mux := http.NewServeMux()
	mux.Handle(transport.HealthPath, &transport.Health{
		Check: s.Ping,
		Log:   log,
	})
	mux.Handle(kadm5.Prefix, &kadm5.Server{
		KDC:   k,
		Store: s,
		ACL:   c.AdminACL,
		Realm: c.Realm,
	})
	mux.Handle("/", &transport.Handler{
		Path:   c.ProxyPath,
		Handle: k.Handle,
		Log:    log,
	})
	return mux
}
