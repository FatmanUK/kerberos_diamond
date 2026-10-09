package store

import (
	"context"
	"errors"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
)

// A history of one means the current password alone, which is
// upstream's own comment: "A history of 1 means just check the
// current password" (svr_principal.c:1102-1104). So nothing is stored
// and the live keys are the whole of the check.
func TestHistoryOfOneChecksOnlyTheCurrent(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := withPolicy(t, s, "one", 1)

	if err := s.CheckPasswordReuse(ctx, p,
		"userpassword"); !errors.Is(err, ErrPasswordReuse) {
		t.Errorf("the current password was allowed: %v", err)
	}
	if err := s.CheckPasswordReuse(ctx, p,
		"something-else"); err != nil {
		t.Errorf("a fresh password was refused: %v", err)
	}
	// And nothing is stored, so there is nothing to remember.
	if err := s.RecordPasswordHistory(ctx, p); err != nil {
		t.Fatal(err)
	}
	if n := countHistory(t, s, p.Name); n != 0 {
		t.Errorf("%d history rows at a history of one", n)
	}
}

// A longer history remembers that many passwords *including* the
// current one, so three means the current and the two before it.
func TestHistoryRemembersAndThenForgets(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := withPolicy(t, s, "three", 3)

	// Walk through four passwords, recording history as a change
	// would.
	used := []string{"userpassword", "second-one",
		"third-one", "fourth-one"}
	for i := 1; i < len(used); i++ {
		err := s.RecordPasswordHistory(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		err = s.SetPassword(p, used[i],
			int32(i)+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Save(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	// The two before the current one are refused, and the one
	// before those has been forgotten.
	for _, pw := range []string{"fourth-one", "third-one",
		"second-one"} {
		if err := s.CheckPasswordReuse(ctx, p,
			pw); !errors.Is(err, ErrPasswordReuse) {
			t.Errorf("%q was allowed: %v", pw, err)
		}
	}
	if err := s.CheckPasswordReuse(ctx, p,
		"userpassword"); err != nil {
		t.Errorf("the forgotten password was refused: %v",
			err)
	}
}

// With no policy there is no history at all, which is the same rule
// the quality check follows: have_pol gates both
// (svr_principal.c:1264-1283).
func TestNoPolicyMeansNoHistory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "user@" + testRealm
	principal(t, s, name, "userpassword")
	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPasswordReuse(ctx, p,
		"userpassword"); err != nil {
		t.Errorf("reuse was refused with no policy: %v", err)
	}
	if err := s.RecordPasswordHistory(ctx, p); err != nil {
		t.Fatal(err)
	}
	if n := countHistory(t, s, name); n != 0 {
		t.Errorf("%d history rows with no policy", n)
	}
}

// Deleting a principal takes its history with it. A principal
// recreated under the same name must not inherit the old one -- which
// would be both a surprise and a way to learn that a password was
// once used.
func TestDeleteForgetsHistory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := withPolicy(t, s, "three", 3)
	if err := s.RecordPasswordHistory(ctx, p); err != nil {
		t.Fatal(err)
	}
	if countHistory(t, s, p.Name) == 0 {
		t.Fatal("nothing was recorded")
	}
	if err := s.Delete(ctx, p.Name); err != nil {
		t.Fatal(err)
	}
	if n := countHistory(t, s, p.Name); n != 0 {
		t.Errorf("%d history rows survived the principal", n)
	}
}

// withPolicy makes a principal under a policy with the given history
// depth.
func withPolicy(
	t *testing.T,
	s *Store,
	policy string,
	history int32,
) *Principal {
	t.Helper()
	ctx := context.Background()
	pol := NewPolicy(policy)
	pol.PWHistoryNum = history
	if err := s.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	name := "user@" + testRealm
	principal(t, s, name, "userpassword")
	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = policy
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return again
}

func countHistory(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	var n int64
	err := s.db.Model(&HistoryKey{}).
		Where("principal_name = ?", name).Count(&n).Error
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// keepold keeps the previous key version, and the new keys come first
// -- which SelectKey requires, because it breaks out of its scan on
// the first row below the version it wants.
func TestKeepOldKeepsThePreviousVersion(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "host/a.test@" + testRealm
	principal(t, s, name, "first-password")
	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	err = s.SetPasswordKeepOld(p,
		"second-password", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	assertBothVersions(t, s, again)

	assertPurged(t, s, again)
}

// assertPurged checks purgekeys leaves only the current version,
// which is the other half of keepold: the old key is kept so that
// tickets issued under it keep verifying, and removed once none can
// still be in use.
func assertPurged(t *testing.T, s *Store, p *Principal) {
	t.Helper()
	ctx := context.Background()
	if n := p.PurgeOldKeys(); n == 0 {
		t.Error("purge removed nothing")
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	purged, err := s.Lookup(ctx, p.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range purged.Keys {
		if k.KVNO != 2 {
			t.Errorf("version %d survived the purge",
				k.KVNO)
		}
	}
}

// assertBothVersions checks the old keys are still selectable and
// that the list is in the descending order SelectKey needs.
func assertBothVersions(
	t *testing.T, s *Store, p *Principal,
) {
	t.Helper()
	if p.HighestKVNO() != 2 {
		t.Fatalf("highest version is %d", p.HighestKVNO())
	}
	if p.Keys[0].KVNO != 2 {
		t.Errorf("the list does not lead with the newest")
	}
	seen := map[int32]bool{}
	for _, k := range p.Keys {
		seen[k.KVNO] = true
	}
	if !seen[1] || !seen[2] {
		t.Errorf("versions present: %v", seen)
	}
	// The old key still opens, which is the whole point: a ticket
	// issued under it has to keep verifying.
	start := 0
	row, _, err := s.Key(p, &start, AnyEType, AnySaltType, 1)
	if err != nil {
		t.Fatalf("the old version is unreadable: %v", err)
	}
	if row.KVNO != 1 {
		t.Errorf("asked for version 1, got %d", row.KVNO)
	}
}

// A rename carries everything that hangs off the principal, and --
// the part that matters -- leaves the keys usable with the same
// password. Upstream's own test is exactly that: rename, then kinit
// with the password unchanged (tests/t_renprinc.py:31-38).
//
// What makes it work is pinning the salt first. The default salt is
// the realm followed by the name components, so it changes when the
// name does; a rename without pinning it would leave every
// password-derived key unusable, reported to the user as "password
// incorrect".
func TestRenameKeepsThePasswordUsable(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	from := "before@" + testRealm
	to := "after@" + testRealm
	principal(t, s, from, "the-password")

	if err := s.Rename(ctx, from, to); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, from); !errors.Is(
		err, ErrNotFound) {
		t.Errorf("the old name survives: %v", err)
	}
	p, err := s.Lookup(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	if p.Realm != testRealm {
		t.Errorf("realm is %q", p.Realm)
	}
	assertSaltPinned(t, s, p, "before", "the-password")
}

// assertSaltPinned checks every key carries an explicit salt, that it
// is the one the *old* name produced, and that the stored key is
// still what the password derives under it.
func assertSaltPinned(
	t *testing.T,
	s *Store,
	p *Principal,
	oldName, password string,
) {
	t.Helper()
	want := crypto.Salt(testRealm, []string{oldName})
	start := 0
	for {
		row, key, err := s.Key(p, &start, AnyEType,
			AnySaltType, HighestKVNO)
		if errors.Is(err, ErrNoMatchingKey) {
			break
		}
		if err != nil {
			t.Fatalf("Key: %v", err)
		}
		if row.SaltType != SaltSpecial {
			t.Errorf("enctype %d salt type is %d",
				row.EType, row.SaltType)
		}
		if string(row.Salt) != string(want) {
			t.Errorf("enctype %d salt is %q, want %q",
				row.EType, row.Salt, want)
		}
		prof, err := crypto.Profile(crypto.EncType(row.EType))
		if err != nil {
			t.Fatal(err)
		}
		derived, err := prof.StringToKey(password, want, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(key) != string(derived) {
			t.Errorf("enctype %d key no longer matches "+
				"the password", row.EType)
		}
	}
}

// Renaming twice works, because the second rename finds the salt the
// first pinned and leaves it alone. Upstream tests this case
// separately and says why in a comment: the principal "will have" the
// special salt type after the first rename
// (tests/t_renprinc.py:40-43).
func TestRenamingTwiceKeepsTheFirstSalt(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	principal(t, s, "one@"+testRealm, "the-password")
	if err := s.Rename(ctx, "one@"+testRealm,
		"two@"+testRealm); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename(ctx, "two@"+testRealm,
		"three@"+testRealm); err != nil {
		t.Fatal(err)
	}
	p, err := s.Lookup(ctx, "three@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
	// Still the salt of the *first* name, not the second's.
	assertSaltPinned(t, s, p, "one", "the-password")
}

// A rename carries the password history too, which it has to: the
// history is not an association on the principal, so an ordinary Save
// cannot touch it and a rename has to move it by hand.
func TestRenameCarriesTheHistory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	p := withPolicy(t, s, "three", 3)
	if err := s.RecordPasswordHistory(ctx, p); err != nil {
		t.Fatal(err)
	}
	before := countHistory(t, s, p.Name)
	if before == 0 {
		t.Fatal("nothing was recorded")
	}
	to := "renamed@" + testRealm
	if err := s.Rename(ctx, p.Name, to); err != nil {
		t.Fatal(err)
	}
	if n := countHistory(t, s, to); n != before {
		t.Errorf("%d history rows followed, want %d",
			n, before)
	}
	if n := countHistory(t, s, p.Name); n != 0 {
		t.Errorf("%d history rows stayed behind", n)
	}
}

// A rename onto a name that exists is refused, because the
// alternative is merging two principals.
func TestRenameOntoAnExistingNameIsRefused(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	principal(t, s, "a@"+testRealm, "pw-a")
	principal(t, s, "b@"+testRealm, "pw-b")
	if err := s.Rename(ctx, "a@"+testRealm,
		"b@"+testRealm); !errors.Is(err, ErrNameInUse) {
		t.Errorf("%v, want ErrNameInUse", err)
	}
}
