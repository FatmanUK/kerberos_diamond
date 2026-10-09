package golden

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The alias verb, and the authorisation that is unlike every other
// operation's: add on the alias name, modify on the target, and the
// add entry must carry **no restrictions at all** (acl_addalias,
// auth_acl.c:723-734).
//
// The restriction rule is the surprising one and the reasoning is
// sound: a restriction says what attributes and lifetimes a created
// principal must have, and an alias creates no principal to apply
// them to. Rather than impose nothing and pretend, upstream refuses.
func TestTheAliasVerbNeedsBothPrivileges(t *testing.T) {
	d := diamond(t, "kd_kadm5_alias", time.Now().UTC)
	for _, c := range []struct {
		why  string
		acl  string
		want int
	}{
		{"add and modify", "*@" + Realm + " am",
			http.StatusOK},
		{"add alone", "*@" + Realm + " a",
			http.StatusForbidden},
		{"modify alone", "*@" + Realm + " m",
			http.StatusForbidden},
		{"add with a restriction",
			"*@" + Realm + " am * -maxlife 1h",
			http.StatusForbidden},
	} {
		t.Run(c.why, func(t *testing.T) {
			s := kadm5Server(t, d, c.acl)
			res, body := call(t, s, "alias",
				adminToken(t, d, UserName),
				map[string]any{
					"alias":  "anAlias",
					"target": PreauthName,
				})
			if res.StatusCode != c.want {
				t.Errorf("status %d, want %d: %v",
					res.StatusCode, c.want, body)
			}
			if res.StatusCode == http.StatusOK {
				cleanAlias(t, d)
			}
		})
	}
}

// cleanAlias removes the alias a subtest created, so the next one
// starts from the same realm.
func cleanAlias(t *testing.T, d *Diamond) {
	t.Helper()
	err := d.Store.DeleteAlias(context.Background(),
		"anAlias@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
}

// Which operations canonicalise is not a judgement call, and this is
// the split asserted one operation at a time.
//
// An ACL granting everything **on the alias name only** lets through
// exactly the operations that do *not* canonicalise, and refuses the
// ones that do -- because those check the name the alias resolves to,
// which this ACL says nothing about. Upstream's own test does the
// same thing from the other side, with entries naming
// `aliastounselected' (t_kadmin_acl.py:70-84).
func TestWhichOperationsCanonicalise(t *testing.T) {
	d := diamond(t, "kd_kadm5_canon", time.Now().UTC)
	ctx := context.Background()
	err := d.Store.CreateAlias(ctx, "theAlias@"+Realm,
		PreauthName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	// Everything, but only for the alias name itself.
	s := kadm5Server(t, d,
		"*@"+Realm+" * theAlias@"+Realm)
	for _, c := range aliasACLCases() {
		t.Run(c.verb, func(t *testing.T) {
			res, body := call(t, s, c.verb,
				adminToken(t, d, UserName), c.arg)
			if res.StatusCode != c.want {
				t.Errorf("status %d, want %d: %v",
					res.StatusCode, c.want, body)
			}
		})
	}
}

// aliasCase is one operation named through an alias, and whether an
// ACL entry naming the *alias* lets it through.
type aliasCase struct {
	verb string
	arg  map[string]any
	want int
}

// aliasACLCases is the split: forbidden means the ACL check used the
// canonical name, which this ACL does not cover.
func aliasACLCases() []aliasCase {
	alias := map[string]any{"principal": "theAlias"}
	return []aliasCase{
		// These canonicalise (t_kadmin_acl.py:199-201,
		// :225-227, :255-257, :271-273, :316-318).
		{"getprinc", alias, http.StatusForbidden},
		{"getstrs", alias, http.StatusForbidden},
		{"modprinc", map[string]any{
			"principal": "theAlias",
			"max_life":  "1h"}, http.StatusForbidden},
		{"purgekeys", alias, http.StatusForbidden},
		{"setstr", map[string]any{
			"principal": "theAlias",
			"key":       "k",
			"value":     "v"}, http.StatusForbidden},
		{"cpw", map[string]any{
			"principal": "theAlias",
			"randkey":   true}, http.StatusForbidden},
		// delprinc does not (t_kadmin_acl.py:172-176), and it
		// deletes the alias rather than its target.
		{"delprinc", alias, http.StatusOK},
	}
}

// The stock-client anchor for the whole step: an unmodified kinit
// logs in through an alias, and an unmodified kvno gets a service
// ticket through one.
//
// It is also the only check that the *salt* is right, which is the
// trap in aliasing a principal that has a password. The default salt
// is the realm followed by the principal's own name components, so a
// KDC that derived it from the name the client typed would hand out a
// key the client disagrees with -- and what a client reports for that
// is "password incorrect", with nothing to say why. Only a real
// client deriving a real key from a real password catches it.
func TestStockKinitThroughAnAlias(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "alias", clientConf)
	d := diamondOf(t)
	err := d.Store.CreateAlias(ctx, "nickname@"+Realm,
		UserName+"@"+Realm)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "nickname@"+Realm)
	if err != nil {
		t.Fatalf("kinit through an alias: %v\n%s", err, out)
	}
	// The ticket names the alias, not the principal behind it,
	// which is upstream's default (t_alias.py:30-31).
	assertTicket(t, ctx, o, env, "nickname")
	assertAliasedService(t, ctx, o, env, d)
}

// assertAliasedService gets a service ticket through an alias of a
// service principal.
func assertAliasedService(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	d *Diamond,
) {
	t.Helper()
	alias := "host/nick.kdiamond.test"
	// storeName already qualifies with the realm.
	err := d.Store.CreateAlias(ctx, alias+"@"+Realm,
		storeName(ServiceName))
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.ExecEnv(ctx, env, "", "kvno", alias)
	if err != nil {
		t.Fatalf("kvno through an alias: %v\n%s", err, out)
	}
	// klist shows the name that was asked for.
	list, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist: %v\n%s", err, list)
	}
	if !strings.Contains(list, alias+"@"+Realm) {
		t.Errorf("klist does not show %s:\n%s", alias,
			list)
	}
}
