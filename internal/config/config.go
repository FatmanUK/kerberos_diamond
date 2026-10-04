// Package config reads the process's configuration from the
// environment, and nowhere else.
//
// Everything is a KD_-prefixed environment variable: there is no
// configuration file, no flag that sets a persistent value, and
// nothing read from the database at startup. A container gets its
// whole configuration from its environment, and two processes given
// the same environment behave identically.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
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
	// private key. There is no cleartext listener, so the KDC
	// will not start without both.
	TLSCertFile string
	TLSKeyFile  string

	// MasterPassword is what the database master key is derived
	// from. There is no stash file: the key is string-to-key over
	// the salt for K/M@REALM, so realm plus password determine it
	// and a replacement container derives the same key from the
	// same environment. It is the only secret the KDC holds and
	// the whole database is readable to anyone who learns it.
	MasterPassword string

	// ClockSkew is how far a timestamp may be from this host's
	// clock and still be accepted.
	ClockSkew time.Duration
}

// Defaults for everything that can sensibly have one. The database
// URL, the realm and the TLS material cannot.
const (
	defaultListen    = ":8088"
	defaultProxyPath = "KdcProxy"
	defaultClockSkew = 5 * time.Minute
)

// ErrMissing reports a variable that has no value and no default.
var ErrMissing = errors.New("required but unset")

// Load reads the configuration from the environment.
//
// It returns every problem it finds rather than only the first, so
// that a misconfigured deployment needs one restart to diagnose
// instead of one per missing variable.
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL: os.Getenv("KD_DATABASE_URL"),
		Realm:       os.Getenv("KD_REALM"),
		ListenAddr:  envOr("KD_LISTEN_ADDR", defaultListen),
		ProxyPath:   envOr("KD_PROXY_PATH", defaultProxyPath),
		TLSCertFile: os.Getenv("KD_TLS_CERT_FILE"),
		TLSKeyFile:  os.Getenv("KD_TLS_KEY_FILE"),
		ClockSkew:   defaultClockSkew,

		MasterPassword: os.Getenv("KD_MASTER_PASSWORD"),
	}

	var errs []error
	if d := os.Getenv("KD_CLOCK_SKEW"); d != "" {
		parsed, err := time.ParseDuration(d)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"KD_CLOCK_SKEW: %w", err))
		} else {
			c.ClockSkew = parsed
		}
	}
	errs = append(errs, c.validate()...)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// required names the variables a KDC cannot start without, paired
// with the field each fills.
func (c *Config) required() map[string]string {
	return map[string]string{
		"KD_DATABASE_URL":  c.DatabaseURL,
		"KD_REALM":         c.Realm,
		"KD_TLS_CERT_FILE": c.TLSCertFile,
		"KD_TLS_KEY_FILE":  c.TLSKeyFile,

		"KD_MASTER_PASSWORD": c.MasterPassword,
	}
}

// validate collects every problem with a loaded Config.
func (c *Config) validate() []error {
	var errs []error
	for name, value := range c.required() {
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
