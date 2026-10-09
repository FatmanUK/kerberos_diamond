package kdc

import (
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// enterpriseRequest is an AS-REQ whose client name is a user
// principal name in one component, which is what `kinit -E' sends.
func enterpriseRequest(upn string) wire.ASReq {
	req := asRequest([]string{"unused"})
	req.Body.CName = &wire.PrincipalName{
		Type:       wire.NTEnterprise,
		Components: []string{upn},
	}
	return req
}

// The split is at the **last** at sign, because a realm cannot
// contain one and a user name can.
func TestEnterpriseNamesSplitAtTheLastAt(t *testing.T) {
	for _, c := range []struct {
		in    string
		name  string
		realm string
		ok    bool
	}{
		{"user@KDIAMOND.TEST", "user", "KDIAMOND.TEST",
			true},
		{"first@last@KDIAMOND.TEST", "first@last",
			"KDIAMOND.TEST", true},
		{"nobody", "", "", false},
		{"@KDIAMOND.TEST", "", "", false},
		{"user@", "", "", false},
		{"", "", "", false},
	} {
		t.Run(c.in, func(t *testing.T) {
			n, r, ok := enterpriseName(
				wire.PrincipalName{
					Type:       wire.NTEnterprise,
					Components: []string{c.in},
				})
			if ok != c.ok || n != c.name ||
				r != c.realm {
				t.Errorf("got %q %q %v", n, r, ok)
			}
		})
	}
}

// The name type is a flag and not a hint: the same string sent as an
// ordinary NT-PRINCIPAL is one component containing an at sign and is
// not split at all.
func TestOnlyTheEnterpriseTypeIsSplit(t *testing.T) {
	_, _, ok := enterpriseName(wire.PrincipalName{
		Type:       wire.NTPrincipal,
		Components: []string{"user@KDIAMOND.TEST"},
	})
	if ok {
		t.Error("an NT-PRINCIPAL name was split")
	}
	// And a two-component enterprise name is not one.
	_, _, ok = enterpriseName(wire.PrincipalName{
		Type:       wire.NTEnterprise,
		Components: []string{"host", "a@b"},
	})
	if ok {
		t.Error("a two-component name was split")
	}
}

// An enterprise name naming **this** realm logs in, which is the
// whole point of the type: the name a user types at a Windows
// workstation is their UPN, and it has to resolve.
func TestAnEnterpriseNameInThisRealmLogsIn(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k,
		enterpriseRequest("user@"+testRealm))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	// The reply names the principal, because the enterprise name
	// was rewritten to the ordinary form before anything looked
	// at it.
	if got := rep.CName.Components[0]; got != "user" {
		t.Errorf("the reply names %q", got)
	}
}

// And an enterprise name naming **another** realm is referred there.
//
// Three things have to be right together or a client ignores it, and
// is_referral checks all three (get_in_tkt.c:1659-1667): the code is
// WRONG_REALM, there is a cname, and **its realm differs from the
// client's own**. The third is the one that matters -- upstream keeps
// a regression test for an error that satisfies the first two and not
// the third being treated as a plain refusal
// (tests/t_general.py:56-61).
func TestAnEnterpriseNameElsewhereIsReferred(t *testing.T) {
	k := testKDC(t)
	_, kerr := as(t, k,
		enterpriseRequest("remote@FOREIGN.TEST"))
	if kerr == nil {
		t.Fatal("accepted")
	}
	if kerr.ErrorCode != wire.ErrCodeWrongRealm {
		t.Fatalf("code %d, want WRONG_REALM",
			kerr.ErrorCode)
	}
	if kerr.CRealm != "FOREIGN.TEST" {
		t.Errorf("the referral names realm %q",
			kerr.CRealm)
	}
	if kerr.CName == nil ||
		kerr.CName.Components[0] != "remote" {
		t.Errorf("the referral names %v", kerr.CName)
	}
	// And the realm genuinely differs from this one, which is
	// what makes it a referral rather than a refusal.
	if kerr.CRealm == k.Realm {
		t.Error("the referral points back at this realm")
	}
}

// Every other error keeps the name the request sent, because a client
// has to recognise it. Only WRONG_REALM gets the canonicalised one
// (do_as_req.c:806-807).
func TestOnlyAReferralRenamesTheClient(t *testing.T) {
	k := testKDC(t)
	_, kerr := as(t, k,
		enterpriseRequest("nobody@"+testRealm))
	if kerr == nil {
		t.Fatal("accepted")
	}
	if kerr.ErrorCode != wire.ErrCodeCPrincipalUnknown {
		t.Fatalf("code %d", kerr.ErrorCode)
	}
	if kerr.CRealm != k.Realm {
		t.Errorf("crealm is %q, want this realm",
			kerr.CRealm)
	}
}
