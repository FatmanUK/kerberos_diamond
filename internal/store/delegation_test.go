package store

import (
	"context"
	"errors"
	"testing"
)

const (
	impA = "host/front.example.test@EXAMPLE.TEST"
	impB = "host/other.example.test@EXAMPLE.TEST"
	tgtA = "host/back.example.test@EXAMPLE.TEST"
	tgtB = "host/else.example.test@EXAMPLE.TEST"
)

// The traditional relation: an impersonator's own list of targets.
//
// It is the thing upstream needs LDAP for. DB2 has no
// check_allowed_to_delegate method at all, so every traditional
// S4U2Proxy request against a stock flat-file realm is refused, and
// upstream's own suite reaches the successful cases only through a
// test KDB module reading JSON out of krb5.conf (t_s4u.py:32-34).
func TestTheTraditionalDelegationRelation(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if err := s.GrantDelegation(ctx, impA, tgtA); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowedToDelegate(ctx, impA, tgtA); err != nil {
		t.Errorf("a granted delegation was refused: %v", err)
	}
	// A different target is refused, which is what says the
	// target is compared and not only the impersonator.
	err := s.AllowedToDelegate(ctx, impA, tgtB)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("another target: %v", err)
	}
	// And a different impersonator is refused with the same
	// target, which is the other half of the pair.
	err = s.AllowedToDelegate(ctx, impB, tgtA)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("another impersonator: %v", err)
	}
}

// **An empty target asks whether there are any grants at all**, which
// is upstream's `proxy == NULL' (kdb5.c:2554-2568) and is the
// question s4u2self_forwardable asks: a server with any delegation
// targets does not also get forwardable S4U2Self tickets.
//
// Sharing one method between the two questions is upstream's, and
// sharing one table here follows from it.
func TestAnEmptyTargetAsksAboutAnyGrant(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	err := s.AllowedToDelegate(ctx, impA, "")
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("no grants: %v", err)
	}
	if err := s.GrantDelegation(ctx, impA, tgtA); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowedToDelegate(ctx, impA, ""); err != nil {
		t.Errorf("one grant: %v", err)
	}
}

// The resource-based relation runs the other way round: the resource
// names the impersonators it accepts.
//
// The two are not symmetric and a grant in one does not imply the
// other, which is the whole administrative point -- a traditional
// grant is made by whoever runs the impersonator and a resource-based
// one by whoever runs the resource.
func TestTheResourceBasedRelationIsSeparate(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if err := s.GrantDelegation(ctx, impA, tgtA); err != nil {
		t.Fatal(err)
	}
	err := s.AllowedToDelegateFrom(ctx, tgtA, impA)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("a traditional grant implied RBCD: %v",
			err)
	}
	if err := s.GrantRBCD(ctx, tgtA, impA); err != nil {
		t.Fatal(err)
	}
	if err := s.AllowedToDelegateFrom(ctx, tgtA,
		impA); err != nil {
		t.Errorf("a granted RBCD was refused: %v", err)
	}
	err = s.AllowedToDelegateFrom(ctx, tgtA, impB)
	if !errors.Is(err, ErrNotAllowed) {
		t.Errorf("another impersonator: %v", err)
	}
}

// Granting twice is not an error, because a grant is a statement
// about what is permitted and saying it twice says the same thing --
// and because several KDCs share one database, so two operators can
// race.
func TestGrantingTwiceIsIdempotent(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.GrantDelegation(ctx, impA,
			tgtA); err != nil {
			t.Fatalf("grant %d: %v", i, err)
		}
		if err := s.GrantRBCD(ctx, tgtA, impA); err != nil {
			t.Fatalf("rbcd grant %d: %v", i, err)
		}
	}
	got, err := s.Delegations(ctx, impA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != tgtA {
		t.Errorf("listed %v", got)
	}
}

// Revoking removes one grant and leaves the others, and listing comes
// back in a stable order so an operator's output does not shuffle.
func TestRevokeAndList(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	for _, target := range []string{tgtB, tgtA} {
		if err := s.GrantDelegation(ctx, impA,
			target); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Delegations(ctx, impA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != tgtA || got[1] != tgtB {
		t.Errorf("listed %v, want sorted", got)
	}
	if err := s.RevokeDelegation(ctx, impA, tgtA); err != nil {
		t.Fatal(err)
	}
	got, err = s.Delegations(ctx, impA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != tgtB {
		t.Errorf("after revoking: %v", got)
	}
	// Revoking something that is not there is not an error, for
	// the same reason granting twice is not.
	if err := s.RevokeDelegation(ctx, impA, tgtA); err != nil {
		t.Errorf("revoking twice: %v", err)
	}
}

// And the resource-based listing, which is the one a resource's owner
// reads to see who may reach it.
func TestRBCDList(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	for _, imp := range []string{impB, impA} {
		if err := s.GrantRBCD(ctx, tgtA, imp); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.RBCDGrants(ctx, tgtA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != impA || got[1] != impB {
		t.Errorf("listed %v, want sorted", got)
	}
	if err := s.RevokeRBCD(ctx, tgtA, impA); err != nil {
		t.Fatal(err)
	}
	got, err = s.RBCDGrants(ctx, tgtA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != impB {
		t.Errorf("after revoking: %v", got)
	}
}
