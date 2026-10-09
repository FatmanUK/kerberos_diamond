package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/acl"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
)

// setMinimal puts the variables that have no default into the
// environment, so a test can vary one thing at a time.
func setMinimal(t *testing.T) {
	t.Helper()
	t.Setenv("KD_DATABASE_URL", "postgres://localhost/kd")
	t.Setenv("KD_REALM", "KDIAMOND.TEST")
	t.Setenv("KD_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("KD_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("KD_MASTER_PASSWORD", "masterpassword")
}

func TestLoadDefaults(t *testing.T) {
	setMinimal(t)

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAddr != defaultListen {
		t.Errorf("ListenAddr = %q, want %q",
			c.ListenAddr, defaultListen)
	}
	if c.ProxyPath != defaultProxyPath {
		t.Errorf("ProxyPath = %q, want %q",
			c.ProxyPath, defaultProxyPath)
	}
	if c.ClockSkew != defaultClockSkew {
		t.Errorf("ClockSkew = %v, want %v",
			c.ClockSkew, defaultClockSkew)
	}
}

// An empty value must be treated as unset, or a container passing an
// empty string silently loses the default.
func TestEmptyValueTakesDefault(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_LISTEN_ADDR", "")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ListenAddr != defaultListen {
		t.Errorf("ListenAddr = %q, want the default %q",
			c.ListenAddr, defaultListen)
	}
}

// Load must report every missing variable at once. Reporting only the
// first costs one restart per mistake.
func TestLoadReportsEveryMissingVariable(t *testing.T) {
	t.Setenv("KD_DATABASE_URL", "")
	t.Setenv("KD_REALM", "")
	t.Setenv("KD_TLS_CERT_FILE", "")
	t.Setenv("KD_TLS_KEY_FILE", "")
	t.Setenv("KD_MASTER_PASSWORD", "")

	_, err := Load(Serve)
	if err == nil {
		t.Fatal("Load succeeded with nothing set")
	}
	if !errors.Is(err, ErrMissing) {
		t.Errorf("error does not wrap ErrMissing: %v", err)
	}
	for _, name := range []string{
		"KD_DATABASE_URL", "KD_REALM",
		"KD_TLS_CERT_FILE", "KD_TLS_KEY_FILE",
		"KD_MASTER_PASSWORD",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not mention %s: %v",
				name, err)
		}
	}
}

// Whitespace is not a value. A realm of " " would otherwise pass and
// fail much later, in key derivation.
func TestWhitespaceIsMissing(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_REALM", "   ")

	if _, err := Load(Serve); !errors.Is(err, ErrMissing) {
		t.Errorf("whitespace realm accepted: %v", err)
	}
}

func TestClockSkew(t *testing.T) {
	cases := []struct {
		name string
		set  string
		want time.Duration
		ok   bool
	}{
		{"parsed", "30s", 30 * time.Second, true},
		{"unparseable", "soon", 0, false},
		{"zero", "0s", 0, false},
		{"negative", "-1m", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setMinimal(t)
			t.Setenv("KD_CLOCK_SKEW", tc.set)

			c, err := Load(Serve)
			if !tc.ok && err == nil {
				t.Fatalf("accepted %q", tc.set)
			}
			if !tc.ok {
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.ClockSkew != tc.want {
				t.Errorf("ClockSkew = %v, want %v",
					c.ClockSkew, tc.want)
			}
		})
	}
}

// KD_CAPATHS is read into a usable Paths, and a malformed one is a
// configuration error rather than something discovered much later
// when a cross-realm ticket is refused for no visible reason.
func TestCapaths(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_CAPATHS",
		"ANL.GOV>NERSC.GOV=ES.NET;ANL.GOV>ES.NET=.")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tree, err := c.Paths.Tree("ANL.GOV", "NERSC.GOV")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 3 || tree[1].Service != "ES.NET" {
		t.Errorf("the path is %v, want a hop via ES.NET",
			tree)
	}
}

// Unset means no configuration, and then every path comes from the
// realm hierarchy. That is the common case, so it must not be an
// error.
func TestCapathsUnsetIsNotAnError(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_CAPATHS", "")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Paths != nil {
		t.Errorf("unset gave %v", c.Paths)
	}
}

func TestCapathsMalformed(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_CAPATHS", "ANL.GOV>NERSC.GOV")

	_, err := Load(Serve)
	if err == nil {
		t.Fatal("a malformed KD_CAPATHS was accepted")
	}
	if !strings.Contains(err.Error(), "KD_CAPATHS") {
		t.Errorf("the error does not name it: %v", err)
	}
}

// KD_DOMAIN_REALM is read into a usable map, and a malformed one is a
// configuration error rather than a referral that silently never
// happens.
func TestDomainRealm(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_DOMAIN_REALM",
		".elsewhere.test=ELSEWHERE.TEST;d=REFREALM")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Hosts.Realm("www.elsewhere.test"); got !=
		"ELSEWHERE.TEST" {
		t.Errorf("got %q, want ELSEWHERE.TEST", got)
	}
	if got := c.Hosts.Realm("x.d"); got != "REFREALM" {
		t.Errorf("got %q, want REFREALM", got)
	}
}

// Unset means no map, and then no host-based referral is ever
// offered. That is the common case for a realm whose services are all
// its own, so it must not be an error.
func TestDomainRealmUnsetIsNotAnError(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_DOMAIN_REALM", "")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Hosts != nil {
		t.Errorf("unset gave %v", c.Hosts)
	}
}

func TestDomainRealmMalformed(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_DOMAIN_REALM", "elsewhere.test")

	_, err := Load(Serve)
	if err == nil {
		t.Fatal("a malformed KD_DOMAIN_REALM was accepted")
	}
	if !strings.Contains(err.Error(), "KD_DOMAIN_REALM") {
		t.Errorf("the error does not name it: %v", err)
	}
}

// An administrative subcommand opens no socket, so it must load
// without TLS material rather than being made to invent a certificate
// path that is never read.
//
// The gap this closes was visible in the tests that found it: every
// case in internal/golden/admin_test.go used to hand the binary
// /unused/cert.pem and /unused/key.pem, which existed only to get
// past a requirement the command had no use for.
func TestAdminNeedsNoTLSMaterial(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_TLS_CERT_FILE", "")
	t.Setenv("KD_TLS_KEY_FILE", "")

	c, err := Load(Admin)
	if err != nil {
		t.Fatalf("Load(Admin): %v", err)
	}
	if c.Realm != "KDIAMOND.TEST" {
		t.Errorf("Realm = %q", c.Realm)
	}
	// And the serving role still refuses the same environment,
	// because a KDC that started without them would listen in the
	// clear.
	if _, err := Load(Serve); err == nil {
		t.Fatal("Load(Serve) accepted no TLS material")
	}
}

// What every role needs is the database, the realm and the master
// password: without them there is nothing to read, nothing to name
// and nothing that can be decrypted. Each is reported by name, and
// all of them at once.
func TestAdminStillNeedsTheRest(t *testing.T) {
	t.Setenv("KD_DATABASE_URL", "")
	t.Setenv("KD_REALM", "")
	t.Setenv("KD_MASTER_PASSWORD", "")

	_, err := Load(Admin)
	if err == nil {
		t.Fatal("an empty environment was accepted")
	}
	for _, name := range []string{
		"KD_DATABASE_URL", "KD_REALM", "KD_MASTER_PASSWORD",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the error does not name %s: %v",
				name, err)
		}
	}
}

// KD_ADMIN_ACL is read into a usable list, and a malformed entry is a
// configuration error rather than a privilege nobody intended.
func TestAdminACL(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_ADMIN_ACL",
		"admin@KDIAMOND.TEST x;*/admin@KDIAMOND.TEST i")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.AdminACL) != 2 {
		t.Fatalf("%d entries", len(c.AdminACL))
	}
	if _, ok := c.AdminACL.Check(acl.DelPrinc,
		"admin@KDIAMOND.TEST", "x@KDIAMOND.TEST"); !ok {
		t.Error("the first entry does not permit a delete")
	}
	if _, ok := c.AdminACL.Check(acl.DelPrinc,
		"a/admin@KDIAMOND.TEST", "x@KDIAMOND.TEST"); ok {
		t.Error("an inquire entry permitted a delete")
	}
}

// Unset permits nothing but the self-service operations, which is the
// right default for a surface that provisions principals.
func TestAdminACLUnsetIsNotAnError(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_ADMIN_ACL", "")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AdminACL != nil {
		t.Errorf("unset gave %v", c.AdminACL)
	}
}

func TestAdminACLMalformed(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_ADMIN_ACL", "admin@KDIAMOND.TEST z")

	_, err := Load(Serve)
	if err == nil {
		t.Fatal("a malformed KD_ADMIN_ACL was accepted")
	}
	if !strings.Contains(err.Error(), "KD_ADMIN_ACL") {
		t.Errorf("the error does not name it: %v", err)
	}
}

// An attribute restriction is read through internal/store's own
// specifier table, which internal/acl deliberately does not import --
// so this also checks the handover happens.
func TestAdminACLReadsAttributeRestrictions(t *testing.T) {
	setMinimal(t)
	t.Setenv("KD_ADMIN_ACL",
		"admin@KDIAMOND.TEST a * +requires_preauth")

	c, err := Load(Serve)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	r, ok := c.AdminACL.Check(acl.AddPrinc,
		"admin@KDIAMOND.TEST", "x@KDIAMOND.TEST")
	if !ok || r == nil {
		t.Fatalf("no restriction: %v %v", r, ok)
	}
	if r.Set != store.AttrRequiresPreAuth {
		t.Errorf("set mask is %#x, want %#x",
			r.Set, store.AttrRequiresPreAuth)
	}
}
