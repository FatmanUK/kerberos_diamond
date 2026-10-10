package kdc

import (
	"context"
	"errors"

	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// findAlternateTGS answers a request for a trust this realm does not
// hold with the furthest one along the path that it does
// (find_alternate_tgs, kdc/do_tgs_req.c:371-413).
//
// The case it exists for is a client with no path configuration of
// its own. It asks for krbtgt/<the realm it wants>@<its own>, which
// only works where there is a direct trust; where there is not, the
// KDC knows the path and the client does not, so it hands back an
// intermediate's ticket-granting ticket instead and lets the client
// ask again from there. That is the hop the C KDC took when this
// project's three-realm fixture was first driven by hand.
//
// The search runs from the far end backwards, so the longest hop this
// realm can actually make is the one offered -- a nearer intermediate
// would work too and would cost the client an extra round trip.
//
// The realm to head for is a parameter rather than read from the
// request, because the host-based referral reaches this too: there
// the realm comes from the host-to-realm map and not from any name
// the client sent.
func (k *KDC) findAlternateTGS(
	want string,
) (*store.Principal, wire.PrincipalName, bool) {
	tree, err := k.Paths.Tree(k.Realm, want)
	if err != nil {
		return nil, wire.PrincipalName{}, false
	}
	// Entry zero is this realm's own krbtgt, which is never an
	// answer: handing it back would tell the client to start
	// where it already is.
	for i := len(tree) - 1; i > 0; i-- {
		name := tgsNameFor(tree[i].Service)
		srv, err := k.lookupTGS(name)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, wire.PrincipalName{}, false
		}
		return srv, name, true
	}
	return nil, wire.PrincipalName{}, false
}

// lookupTGS looks a ticket-granting service up in this realm's own
// database, and reports store.ErrNotFound rather than swallowing it.
//
// Both callers need that distinction and upstream makes it in the
// same place: db_get_svc_princ's caller continues the search only on
// KRB5_KDB_NOENTRY and refuses on anything else (search_sprinc,
// do_tgs_req.c:558-570). Not finding the entry is an ordinary answer
// -- for the alternate search it means this realm holds no such
// trust, and for the host-based referral it means the map named a
// realm there is no direct trust with -- but a database that cannot
// be read is not, and must not look like one.
func (k *KDC) lookupTGS(
	name wire.PrincipalName,
) (*store.Principal, error) {
	return k.Store.LookupWire(context.Background(),
		k.Realm, name.Components)
}

// tgsNameFor is the name of the ticket-granting service for another
// realm, as this realm's database holds it. The type is the one the C
// KDC's own entry carries, which the differential comparison checks:
// it renders a name's type as well as its components.
func tgsNameFor(realm string) wire.PrincipalName {
	return wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{tgsName, realm},
	}
}

// isCrossTGSName reports whether a name is *another* realm's
// ticket-granting service (is_cross_tgs_principal, kdc/kdc_util.c).
//
// The realm upstream compares against is the name's own, which for a
// request's server name tgsServer has already confirmed is this
// realm's.
func (k *KDC) isCrossTGSName(p wire.PrincipalName) bool {
	return isTGSName(p) && p.Components[1] != k.Realm
}

// referTo records a referral: the principal whose key will seal the
// ticket, and the name to put in it -- which is not the name that was
// asked for, and that is what a referral is.
func (s *tgsState) referTo(
	srv *store.Principal, name wire.PrincipalName,
) {
	s.server, s.serverName, s.referral = srv, name, true
}

// noReferralOptions is NO_REFERRAL_OPTION (kdc/kdc_util.h:460): the
// non-TGT options plus user-to-user, every one of which is about a
// ticket already in the client's hands. It gates both referrals.
const noReferralOptions = nonTGTOptions | wire.OptEncTktInSKey
