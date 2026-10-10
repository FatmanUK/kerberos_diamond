package kdc

import (
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// An anonymous request is **refused**, not quietly answered with an
// ordinary ticket.
//
// It used to be the latter: KDC_OPT_REQUEST_ANONYMOUS was in the
// flags mask, so it reached the ticket, and TKT_FLG_ANONYMOUS was
// then cleared again -- leaving a client that asked for anonymity
// holding a ticket that names it, with nothing said. That is the
// failure mode section 3.3 refuses three times over already.
func TestAnAnonymousRequestIsRefused(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"WELLKNOWN", "ANONYMOUS"})
	req.Body.Options |= wire.OptRequestAnon
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("an anonymous request was answered")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code %d, want BADOPTION",
			kerr.ErrorCode)
	}
}

// A client asking for anonymity **under its own name** has asked for
// a contradiction, and upstream tells it so with a status of its own
// rather than reporting the feature unavailable
// (VALIDATE_ANONYMOUS_PRINCIPAL, do_as_req.c:720-725). The two are
// different problems and only one of them is this KDC's choice.
func TestAnonymityUnderAnOrdinaryNameIsItsOwnError(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptRequestAnon
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("accepted")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Fatalf("code %d", kerr.ErrorCode)
	}
	if kerr.EText != "VALIDATE_ANONYMOUS_PRINCIPAL" {
		t.Errorf("status %q", kerr.EText)
	}
}

// The realm is not compared, because an anonymous client's realm is
// whatever it came from (krb5_principal_compare_any_realm,
// do_as_req.c:719-721).
func TestTheAnonymousNameIgnoresTheRealm(t *testing.T) {
	for _, c := range []struct {
		components []string
		want       bool
	}{
		{[]string{"WELLKNOWN", "ANONYMOUS"}, true},
		{[]string{"WELLKNOWN", "anonymous"}, false},
		{[]string{"WELLKNOWN"}, false},
		{[]string{"WELLKNOWN", "ANONYMOUS", "x"}, false},
		{nil, false},
	} {
		got := isAnonymousName(wire.PrincipalName{
			Components: c.components,
		})
		if got != c.want {
			t.Errorf("%v: %v", c.components, got)
		}
	}
}

// And an ordinary request still gets no anonymous flag, which is the
// other half: removing the option from the mask must not have changed
// anything for a request that did not ask.
func TestAnOrdinaryTicketIsNotAnonymous(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := decodeTicket(t, k, rep)
	if tkt.Flags.Has(wire.FlagAnonymous) {
		t.Error("an ordinary ticket is anonymous")
	}
}
