package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The quality rules: a length floor and a count of character classes,
// which are the only two things a policy says about a password
// itself.
func TestPolicyChecksQuality(t *testing.T) {
	pol := &Policy{PWMinLength: 8, PWMinClasses: 3}
	for _, c := range []struct {
		why      string
		password string
		want     error
	}{
		{"long and varied", "Abcdefg1", nil},
		{"too short", "Abc1", ErrPasswordTooShort},
		{"one class", "abcdefghij", ErrPasswordTooSimple},
		{"two classes", "abcdefgH", ErrPasswordTooSimple},
		{"three with punctuation", "abcdefG!", nil},
	} {
		t.Run(c.why, func(t *testing.T) {
			err := pol.Check(c.password)
			if !errors.Is(err, c.want) {
				t.Errorf("%v, want %v", err, c.want)
			}
		})
	}
}

// The class counting is the half that is easy to get wrong, so it is
// asserted on its own.
//
// Five classes, counted the way C's ctype counts them in the C
// locale: lower, upper, digit, punctuation, and anything else. The
// fifth is why a space counts as a class of its own -- ispunct(' ')
// is false because isspace(' ') is true -- and why anything outside
// ASCII lands there rather than counting as a letter. Go's unicode
// predicates would disagree on both, and a password that satisfied
// the policy on one implementation and not the other would be a bad
// surprise.
func TestCharacterClassesAreCountedLikeC(t *testing.T) {
	for _, c := range []struct {
		password string
		want     int32
	}{
		{"", 0},
		{"abc", 1},
		{"abcDEF", 2},
		{"abcDEF123", 3},
		{"abcDEF123!", 4},
		{"abcDEF123! ", 5},
		// A space is not punctuation, so this is two.
		{"abc def", 2},
		// And é is two octets, both outside ASCII, so this
		// is lower plus the fifth class.
		{"abcé", 2},
		// Every ASCII symbol is punctuation to C, including
		// the ones Go classes as symbols rather than
		// punctuation.
		{"a+b=c", 2},
	} {
		t.Run(c.password, func(t *testing.T) {
			if got := classesIn(
				c.password); got != c.want {
				t.Errorf("%q has %d classes, want %d",
					c.password, got, c.want)
			}
		})
	}
}

// A principal naming no policy is unconstrained, which is not the
// same as naming one whose values are all defaults: upstream calls
// passwd_check with a NULL policy in exactly that case
// (svr_principal.c:1264-1267).
func TestANilPolicyAcceptsAnything(t *testing.T) {
	var pol *Policy
	if err := pol.Check(""); err != nil {
		t.Errorf("the empty password was refused: %v", err)
	}
}

// Every way a policy is refused, each with its own error because an
// operator who set the wrong field needs to be told which.
func TestPolicyValidation(t *testing.T) {
	for _, c := range []struct {
		why  string
		pol  Policy
		want error
	}{
		{"no name", Policy{PWMinLength: 1,
			PWMinClasses: 1, PWHistoryNum: 1},
			ErrBadPolicyName},
		{"a name outside printable ASCII",
			Policy{Name: "pol\x01", PWMinLength: 1,
				PWMinClasses: 1, PWHistoryNum: 1},
			ErrBadPolicyName},
		{"a minimum life above the maximum",
			Policy{Name: "p", PWMinLife: 100,
				PWMaxLife: 50, PWMinLength: 1,
				PWMinClasses: 1, PWHistoryNum: 1},
			ErrBadMinPWLife},
		{"a zero length", Policy{Name: "p",
			PWMinClasses: 1, PWHistoryNum: 1},
			ErrBadPWLength},
		{"six classes", Policy{Name: "p",
			PWMinLength: 1, PWMinClasses: 6,
			PWHistoryNum: 1}, ErrBadPWClasses},
		{"no history", Policy{Name: "p",
			PWMinLength: 1, PWMinClasses: 1},
			ErrBadPWHistory},
	} {
		t.Run(c.why, func(t *testing.T) {
			err := c.pol.Validate()
			if !errors.Is(err, c.want) {
				t.Errorf("%v, want %v", err, c.want)
			}
		})
	}
}

// A maximum password life of zero means *no* maximum, so a minimum
// above it is not a contradiction. This is the one validation rule
// that reads backwards (svr_policy.c:107-110).
func TestNoMaximumMeansNoContradiction(t *testing.T) {
	pol := NewPolicy("p")
	pol.PWMinLife = 1000
	if err := pol.Validate(); err != nil {
		t.Errorf("refused with no maximum set: %v", err)
	}
}

// Policies round-trip, and the defaults a new one gets are upstream's
// floors rather than zeroes.
func TestPolicyRoundTrip(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	pol := NewPolicy("standard")
	pol.PWMinLength = 10
	pol.PWMaxLife = 90 * 24 * 3600
	if err := s.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	got, err := s.LookupPolicy(ctx, "standard")
	if err != nil {
		t.Fatal(err)
	}
	if got.PWMinLength != 10 || got.PWMaxLife != 7776000 {
		t.Errorf("got %+v", got)
	}
	// The floors, which an unset field takes rather than zero.
	if got.PWMinClasses != MinPWClasses ||
		got.PWHistoryNum != MinPWHistory {
		t.Errorf("defaults are %d and %d",
			got.PWMinClasses, got.PWHistoryNum)
	}
	names, err := s.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "standard" {
		t.Errorf("listed %v", names)
	}
}

// A principal can outlive the policy it names, and that is upstream's
// behaviour rather than leniency: get_policy reports have_pol false
// for a missing one and the password is then checked against no
// policy at all. Upstream keeps a regression test for it
// (tests/t_policy.py:98-101), because the alternative is a principal
// nobody can change the password of.
func TestAMissingPolicyIsNotAnError(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "user@" + testRealm
	principal(t, s, name, "userpassword")
	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = "gone"
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := s.PolicyFor(ctx, again)
	if err != nil || pol != nil {
		t.Errorf("got %v, %v", pol, err)
	}
	if err := s.CheckPassword(ctx, again, "x"); err != nil {
		t.Errorf("a missing policy constrained a password: "+
			"%v", err)
	}
}

// Deleting a policy a principal names is refused, because the
// alternative is a principal that silently loses its constraints.
func TestDeletingAPolicyInUseIsRefused(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if err := s.SavePolicy(ctx, NewPolicy("p")); err != nil {
		t.Fatal(err)
	}
	name := "user@" + testRealm
	principal(t, s, name, "userpassword")
	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	p.Policy = "p"
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicy(ctx, "p"); !errors.Is(
		err, ErrPolicyInUse) {
		t.Errorf("got %v, want ErrPolicyInUse", err)
	}
	// And once nothing names it, it goes.
	p.Policy = ""
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePolicy(ctx, "p"); err != nil {
		t.Errorf("deleting an unused policy: %v", err)
	}
}

// The minimum password life, and the exemption that has to be there:
// a principal told to change its password is *not* subject to the
// minimum (check_min_life, kadmin/server/misc.c:88-89). Without that
// an administrator who both forced a change and set a minimum life
// would have locked the user out of doing what they were told.
func TestMinimumPasswordLifeAndItsExemption(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	pol := NewPolicy("slow")
	pol.PWMinLife = 24 * 3600
	if err := s.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := NewPrincipal(testRealm, []string{"user"})
	p.Policy = "slow"
	p.LastPWChange = now.Add(-time.Hour)

	err := s.CheckMinPasswordLife(ctx, p, now)
	if !errors.Is(err, ErrPasswordTooSoon) {
		t.Errorf("an hour old was accepted: %v", err)
	}
	// A day later it is fine.
	if err := s.CheckMinPasswordLife(ctx, p,
		now.Add(24*time.Hour)); err != nil {
		t.Errorf("a day later was refused: %v", err)
	}
	// And a principal under orders is exempt whatever the clock
	// says.
	p.Attributes |= AttrRequiresPWChange
	if err := s.CheckMinPasswordLife(ctx, p, now); err != nil {
		t.Errorf("a forced change was refused: %v", err)
	}
}

// A policy's maximum password life is where PWExpiration comes from,
// and clearing the policy clears the deadline rather than leaving a
// principal with one it no longer has a reason for.
func TestPasswordExpiryFollowsThePolicy(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	pol := NewPolicy("ninety")
	pol.PWMaxLife = 90 * 24 * 3600
	if err := s.SavePolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := NewPrincipal(testRealm, []string{"user"})
	p.Policy = "ninety"
	if err := s.SetPasswordExpiry(ctx, p, now); err != nil {
		t.Fatal(err)
	}
	want := now.Add(90 * 24 * time.Hour)
	if !p.PWExpiration.Equal(want) {
		t.Errorf("expiry is %v, want %v",
			p.PWExpiration, want)
	}
	p.Policy = ""
	if err := s.SetPasswordExpiry(ctx, p, now); err != nil {
		t.Fatal(err)
	}
	if !p.PWExpiration.IsZero() {
		t.Errorf("expiry survived the policy: %v",
			p.PWExpiration)
	}
}
