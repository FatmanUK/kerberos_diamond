package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// An alias resolves, and what comes back is the **canonical**
// principal: its Name is the target's, not the name that was asked
// for. That is upstream's shape -- resolution happens inside
// krb5_db_get_principal (kdb5.c:823-836) -- and it is what makes
// every consumer alias-aware without asking.
func TestAnAliasResolvesToItsTarget(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	canon := "canon@" + testRealm
	principal(t, s, canon, "canonpassword")
	alias := "alias@" + testRealm
	if err := s.CreateAlias(ctx, alias, canon); err != nil {
		t.Fatal(err)
	}
	p, err := s.Lookup(ctx, alias)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != canon {
		t.Errorf("resolved to %q, want %q", p.Name, canon)
	}
	// And LookupExact does not follow it, which is what the
	// operations acting on a *name* need.
	if _, err := s.LookupExact(ctx, alias); !errors.Is(
		err, ErrNotFound) {
		t.Errorf("LookupExact followed the alias: %v", err)
	}
}

// A chain resolves to ten links and the eleventh is **not found**,
// which is MAX_ALIAS_DEPTH and the exact boundary upstream tests
// (t_alias.py:36-60: kvno a10 works, kvno a11 reports the server is
// not in the database).
func TestAnAliasChainResolvesTenDeep(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	canon := "canon@" + testRealm
	principal(t, s, canon, "canonpassword")
	at := canon
	names := make([]string, 0, MaxAliasDepth+1)
	for i := 1; i <= MaxAliasDepth+1; i++ {
		name := aliasName(i)
		if err := s.CreateAlias(ctx, name, at); err != nil {
			t.Fatalf("a%d: %v", i, err)
		}
		names = append(names, name)
		at = name
	}
	// a1..a10 are one to ten links from canon.
	for i := 0; i < MaxAliasDepth; i++ {
		p, err := s.Lookup(ctx, names[i])
		if err != nil {
			t.Fatalf("%s: %v", names[i], err)
		}
		if p.Name != canon {
			t.Errorf("%s resolved to %q", names[i],
				p.Name)
		}
	}
	// The eleventh is one link too far.
	last := names[MaxAliasDepth]
	if _, err := s.Lookup(ctx, last); !errors.Is(
		err, ErrNotFound) {
		t.Errorf("%s resolved: %v", last, err)
	}
}

// aliasName is a1, a2, ... in the order upstream's test builds them.
func aliasName(i int) string {
	return fmt.Sprintf("a%d@%s", i, testRealm)
}

// A self-referential alias is **not** detected as a cycle. It runs
// out of depth and reports not found, which is all upstream does
// (t_alias.py:60-63 asserts exactly that for `alias selfalias
// selfalias'), because the depth limit is the only loop detection
// there is.
func TestASelfAliasRunsOutOfDepth(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	self := "selfalias@" + testRealm
	if err := s.CreateAlias(ctx, self, self); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, self); !errors.Is(
		err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// The target must be in the same realm, which upstream refuses with a
// code of its own (KADM5_ALIAS_REALM, kadm_err.et:70, from
// svr_principal.c:2060-2061). The reason is structural: an alias is
// resolved by a second lookup in the same database, and a KDC's
// database holds one realm.
func TestAnAliasCannotCrossRealms(t *testing.T) {
	s, _ := testStore(t)
	err := s.CreateAlias(context.Background(),
		"x@"+testRealm, "y@OTHER.TEST")
	if !errors.Is(err, ErrAliasRealm) {
		t.Errorf("got %v, want ErrAliasRealm", err)
	}
}

// A name that resolves blocks a creation; a name whose chain dangles
// does not.
//
// Upstream calls the second half "emergent behavior" and keeps a test
// for it anyway (t_alias.py:65-85), which is the right record to
// copy: a dangling alias can be overwritten by addprinc, by another
// alias, or by a rename, because every one of those asks whether the
// name *resolves* and a dangling one does not.
func TestOnlyAResolvingNameBlocksCreation(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	canon := "canon@" + testRealm
	principal(t, s, canon, "canonpassword")
	good := "good@" + testRealm
	if err := s.CreateAlias(ctx, good, canon); err != nil {
		t.Fatal(err)
	}
	// A second alias of the same name is a duplicate.
	if err := s.CreateAlias(ctx, good, canon); !errors.Is(
		err, ErrNameInUse) {
		t.Errorf("got %v, want ErrNameInUse", err)
	}
	// A dangling one is not, and can be pointed somewhere real.
	dangling := "dangling@" + testRealm
	missing := "missing@" + testRealm
	if err := s.CreateAlias(
		ctx, dangling, missing); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAlias(
		ctx, dangling, canon); err != nil {
		t.Errorf("a dangling alias blocked a creation: %v",
			err)
	}
}

// Deleting an alias leaves its target alone, which is what upstream
// does because an alias is a database entry there and delprinc
// removes that entry (t_alias.py:12-16).
func TestDeletingAnAliasKeepsItsTarget(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	canon := "canon@" + testRealm
	principal(t, s, canon, "canonpassword")
	alias := "alias@" + testRealm
	if err := s.CreateAlias(ctx, alias, canon); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, alias); !errors.Is(
		err, ErrNotFound) {
		t.Errorf("the alias survived: %v", err)
	}
	if _, err := s.Lookup(ctx, canon); err != nil {
		t.Errorf("the target went with it: %v", err)
	}
}

// Renaming refuses an alias at either end, with an error of its own
// rather than "already exists" -- which would be misleading about
// what is wrong (kdb5.c:1076-1083 for the source; t_alias.py:88-90
// and t_kadmin_acl.py:296-298 for both).
func TestRenamingAnAliasIsRefused(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	for _, name := range []string{"from", "to"} {
		principal(t, s, name+"@"+testRealm, name+"password")
	}
	for _, c := range []struct{ from, to string }{
		{"aliastofrom", "other"},
		{"from", "aliastoto"},
	} {
		if err := s.CreateAlias(ctx,
			"aliastofrom@"+testRealm,
			"from@"+testRealm); err != nil &&
			!errors.Is(err, ErrNameInUse) {
			t.Fatal(err)
		}
		if err := s.CreateAlias(ctx,
			"aliastoto@"+testRealm,
			"to@"+testRealm); err != nil &&
			!errors.Is(err, ErrNameInUse) {
			t.Fatal(err)
		}
		err := s.Rename(ctx, c.from+"@"+testRealm,
			c.to+"@"+testRealm)
		if !errors.Is(err, ErrAliasUnsupported) {
			t.Errorf("%s -> %s gave %v", c.from, c.to,
				err)
		}
	}
}

// listprincs includes alias names, which upstream gets for free
// because an alias is an ordinary entry there (t_alias.py:108-109).
func TestListIncludesAliases(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	canon := "canon@" + testRealm
	principal(t, s, canon, "canonpassword")
	alias := "alias@" + testRealm
	if err := s.CreateAlias(ctx, alias, canon); err != nil {
		t.Fatal(err)
	}
	names, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sawAlias, sawCanon bool
	for _, n := range names {
		switch n {
		case alias:
			sawAlias = true
		case canon:
			sawCanon = true
		}
	}
	if !sawAlias || !sawCanon {
		t.Errorf("listed %v", names)
	}
}
