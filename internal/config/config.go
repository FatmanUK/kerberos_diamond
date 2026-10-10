// Package config reads the process's configuration from the
// environment, and nowhere else.
//
// Everything is a KD_-prefixed environment variable: there is no
// configuration file, no flag that sets a persistent value, and
// nothing read from the database at startup. A container gets its
// whole configuration from its environment, and two processes given
// the same environment behave identically.
//
// This package depends on internal/store for one type, the master key
// derivation's name. That is the right way round -- the store does
// not know about configuration -- and it keeps the rule this package
// exists for: a bad environment is reported in full, every fault at
// once, rather than one per run.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/hostrealm"
	"github.com/FatmanUK/kerberos_diamond/internal/spake"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/transit"
)

// Config is the whole of a process's configuration.
type Config struct {
	// DatabaseURL is the Postgres connection string holding the
	// principal database.
	DatabaseURL string

	// Realm is the Kerberos realm this KDC serves.
	Realm string

	// ListenAddr is the host:port the KDC's HTTPS listener binds.
	ListenAddr string

	// ProxyPath is the URL path the KDC answers KKDCP requests
	// on. A client's profile names it as "kdc =
	// https://host:port/<path>".
	ProxyPath string

	// TLSCertFile and TLSKeyFile are the PEM certificate and
	// private key. There is no cleartext listener, so a process
	// that is going to serve will not start without both -- and a
	// process that is only going to edit the database does not
	// need them at all, which is what Role is for.
	TLSCertFile string
	TLSKeyFile  string

	// MasterPassword is what the database master key is derived
	// from. There is no stash file: realm plus password determine
	// the key, so a replacement container derives the same one
	// from the same environment. It is the only secret the KDC
	// holds and the whole database is readable to anyone who
	// learns it.
	MasterPassword string

	// MasterKDF is how that password becomes a key: Argon2id,
	// which is what this project writes, or upstream's
	// string-to-key, which exists only so a database created by
	// MIT Kerberos can be opened.
	//
	// It is configuration rather than something stored because
	// nothing persists that could carry it -- the key is derived
	// afresh at every start. Pointing a KDC at a database with
	// the wrong value here does not corrupt anything; it simply
	// cannot decrypt a key, and says so.
	MasterKDF store.MasterKDF

	// ClockSkew is how far a timestamp may be from this host's
	// clock and still be accepted.
	ClockSkew time.Duration

	// Paths are the cross-realm authentication paths, krb5.conf's
	// [capaths] in one line. Empty means none, and then every
	// path is decided by the realm-naming hierarchy -- which is
	// the common case, because realms in one organisation are
	// usually named as a hierarchy on purpose.
	//
	// It is configuration rather than something stored for the
	// same reason MasterKDF is: nothing persists that could carry
	// it, and a KDC derives its whole view of the world from the
	// environment at startup.
	Paths transit.Paths

	// Enctypes is kadmin's supported_enctypes: which key/salt
	// pairs addprinc and cpw *create*, as distinct from what a
	// session may use and from what a client asks for. Unset
	// means upstream's default, which is the two RFC 3962 types
	// and **not** the aes-sha2 pair.
	//
	// The order is load-bearing: a ticket is sealed with the
	// first key of a principal's highest key version, so the
	// first entry is the enctype every service ticket is
	// encrypted with.
	Enctypes store.SupportedEnctypes

	// SPAKEGroups are the SPAKE groups this realm offers, empty
	// meaning the mechanism is not offered at all -- which is
	// upstream's default for a KDC and not for a client
	// (DEFAULT_GROUPS_KDC against DEFAULT_GROUPS_CLIENT,
	// plugins/preauth/spake/groups.c:59-60).
	SPAKEGroups []int32

	// SPAKEIndicators are the authentication indicators a
	// successful SPAKE exchange asserts, which is upstream's
	// per-realm spake_preauth_indicator. Without one SPAKE still
	// strengthens the reply key and still says nothing about it
	// in the ticket, so a realm that wants services to be able to
	// *insist* on SPAKE needs both this and require_auth on those
	// services.
	SPAKEIndicators []string

	// Hosts maps a host name to the realm that serves it,
	// krb5.conf's [domain_realm] in one line. It exists for the
	// host-based referral and has no other reader: a client
	// asking this realm for a service on a host elsewhere is told
	// which realm to ask instead.
	//
	// Nil means none, and then no referral is ever offered --
	// which is what this KDC did before the map existed.
	Hosts hostrealm.Map

	// HostBasedServices and NoHostReferral gate that lookup, and
	// are kdc.conf's keys of the same names. The first lets an
	// NT-UNKNOWN server name be treated as host-based, because an
	// unknown type says nothing about whether the second
	// component is a host; the second excludes a service from
	// referral whatever its type, and overrides the first.
	//
	// Upstream combines a realm's value with [kdcdefaults]' by
	// space-joining them (combine, kdc/main.c:173-189), so realm
	// values supplement the defaults rather than replacing them.
	// One realm per process means one list, so that asymmetry has
	// nowhere to show.
	HostBasedServices hostrealm.Services
	NoHostReferral    hostrealm.Services

	// AdminACL is who may administer what, kadmin's kadm5.acl
	// folded onto one line. Nil permits nothing but the
	// self-service operations -- a user changing its own password
	// and reading its own entry -- which is the right default for
	// a surface that provisions principals.
	AdminACL acl.ACL
}

// Defaults for everything that can sensibly have one. The database
// URL, the realm and the TLS material cannot.
const (
	defaultListen    = ":8088"
	defaultProxyPath = "KdcProxy"
	defaultClockSkew = 5 * time.Minute
)

// Role is what a process intends to do with its configuration, which
// is what decides the variables it cannot start without.
//
// It exists because there is one environment and more than one
// program reading it. A KDC that is about to listen must have TLS
// material or it would serve in the clear; a subcommand that edits
// the database opens no socket and has no use for a certificate, and
// demanding one of it meant every administrative test had to invent a
// path that was never opened.
type Role int

const (
	// Serve is the KDC daemon.
	Serve Role = iota

	// Admin is a subcommand that reads or edits the database and
	// listens for nothing.
	Admin
)

// ErrMissing reports a variable that has no value and no default.
var ErrMissing = errors.New("required but unset")

// Load reads the configuration from the environment.
//
// It returns every problem it finds rather than only the first, so
// that a misconfigured deployment needs one restart to diagnose
// instead of one per missing variable.
func Load(role Role) (*Config, error) {
	c := &Config{
		DatabaseURL: os.Getenv("KD_DATABASE_URL"),
		Realm:       os.Getenv("KD_REALM"),
		ListenAddr:  envOr("KD_LISTEN_ADDR", defaultListen),
		ProxyPath:   envOr("KD_PROXY_PATH", defaultProxyPath),
		TLSCertFile: os.Getenv("KD_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("KD_TLS_KEY_FILE"),
		ClockSkew:   defaultClockSkew,

		MasterPassword: os.Getenv("KD_MASTER_PASSWORD"),

		HostBasedServices: hostrealm.Services(
			os.Getenv("KD_HOST_BASED_SERVICES")),
		NoHostReferral: hostrealm.Services(
			os.Getenv("KD_NO_HOST_REFERRAL")),
	}

	errs := c.parse()
	errs = append(errs, c.validate(role)...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// parse fills in the fields that need more than reading a string, and
// collects their faults rather than returning at the first.
func (c *Config) parse() []error {
	var errs []error
	errs = append(errs, c.parseSkew()...)
	kdf, err := store.ParseMasterKDF(
		os.Getenv("KD_MASTER_KDF"))
	if err != nil {
		errs = append(errs, err)
	} else {
		c.MasterKDF = kdf
	}
	return append(errs, c.parseTables()...)
}

// parseSkew reads the one duration.
func (c *Config) parseSkew() []error {
	d := os.Getenv("KD_CLOCK_SKEW")
	if d == "" {
		return nil
	}
	parsed, err := time.ParseDuration(d)
	if err != nil {
		return []error{fmt.Errorf("KD_CLOCK_SKEW: %w", err)}
	}
	c.ClockSkew = parsed
	return nil
}

// parseTables reads the structured variables -- the ones whose syntax
// is a krb5.conf section folded onto one line. Each parser lives in
// the package that owns the type, and this only names the variable in
// the error.
func (c *Config) parseTables() []error {
	var errs []error
	paths, err := transit.ParsePaths(os.Getenv("KD_CAPATHS"))
	if err != nil {
		errs = append(errs, fmt.Errorf("KD_CAPATHS: %w", err))
	} else {
		c.Paths = paths
	}
	hosts, err := hostrealm.Parse(
		os.Getenv("KD_DOMAIN_REALM"))
	if err != nil {
		errs = append(errs, fmt.Errorf(
			"KD_DOMAIN_REALM: %w", err))
	} else {
		c.Hosts = hosts
	}
	// The attribute specifiers in a restriction are
	// internal/store's table, which internal/acl deliberately
	// does not import -- so it is handed over here, once, before
	// anything is parsed.
	acl.SetAttrFunc(store.AttrMask)
	list, err := acl.Parse(os.Getenv("KD_ADMIN_ACL"))
	if err != nil {
		errs = append(errs, fmt.Errorf(
			"KD_ADMIN_ACL: %w", err))
	} else {
		c.AdminACL = list
	}
	return append(errs, c.parseCrypto()...)
}

// parseCrypto reads the two structured variables that say what
// cryptography a realm creates and offers.
func (c *Config) parseCrypto() []error {
	var errs []error
	types, err := store.ParseEnctypes(
		os.Getenv("KD_SUPPORTED_ENCTYPES"))
	if err != nil {
		errs = append(errs, fmt.Errorf(
			"KD_SUPPORTED_ENCTYPES: %w", err))
	} else {
		c.Enctypes = types
	}
	groups, err := spake.ParseGroups(
		os.Getenv("KD_SPAKE_GROUPS"))
	if err != nil {
		errs = append(errs, fmt.Errorf(
			"KD_SPAKE_GROUPS: %w", err))
	} else {
		c.SPAKEGroups = groups
	}
	// Indicators are free text and cannot be malformed: they are
	// compared against a service's require_auth as strings.
	c.SPAKEIndicators = strings.Fields(
		os.Getenv("KD_SPAKE_INDICATORS"))
	return errs
}

// required names the variables this role cannot start without, paired
// with the field each fills.
//
// The first three are everything: without a database there is nothing
// to read, without a realm nothing can be named, and without the
// master password nothing stored can be decrypted. The TLS material
// is the listener's alone.
func (c *Config) required(role Role) map[string]string {
	need := map[string]string{
		"KD_DATABASE_URL":    c.DatabaseURL,
		"KD_REALM":           c.Realm,
		"KD_MASTER_PASSWORD": c.MasterPassword,
	}
	if role == Serve {
		need["KD_TLS_CERT_FILE"] = c.TLSCertFile
		need["KD_TLS_KEY_FILE"] = c.TLSKeyFile
	}
	return need
}

// validate collects every problem with a loaded Config.
func (c *Config) validate(role Role) []error {
	var errs []error
	for name, value := range c.required(role) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf(
				"%s: %w", name, ErrMissing))
		}
	}
	if c.ClockSkew <= 0 {
		errs = append(errs, errors.New(
			"KD_CLOCK_SKEW: must be positive"))
	}
	return errs
}

// envOr returns the variable's value, or def when it is unset or
// empty. An empty value is treated as unset so that a container
// passing an empty string gets the default rather than nothing.
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
