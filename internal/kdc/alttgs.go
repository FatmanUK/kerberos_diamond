package kdc

import (
	"context"
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
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
func (k *KDC) findAlternateTGS(
	s *tgsState,
) (*store.Principal, wire.PrincipalName, bool) {
	want := s.req.Body.SName.Components[1]
	tree, err := k.Paths.Tree(k.Realm, want)
	if err != nil {
		return nil, wire.PrincipalName{}, false
	}
	// Entry zero is this realm's own krbtgt, which is never an
	// answer: handing it back would tell the client to start
	// where it already is.
	for i := len(tree) - 1; i > 0; i-- {
		name := wire.PrincipalName{
			Type: wire.NTSrvInst,
			Components: []string{
				tgsName, tree[i].Service,
			},
		}
		srv, err := k.Store.LookupWire(context.Background(),
			k.Realm, name.Components)
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

// wantsAlternateTGS reports whether a failed server lookup is one the
// alternate search can answer.
//
// Two conditions. The name asked for has to be a cross-realm
// ticket-granting service -- a request for an ordinary service that
// does not exist is simply unknown, and upstream's other referral
// path for those needs a host-to-realm map this implementation does
// not have. And the options must not be any of the ones that forbid a
// referral: those all name a ticket the client already holds
// (NO_REFERRAL_OPTION, kdc/kdc_util.h:460), so answering with a
// different server would answer a different question.
func (k *KDC) wantsAlternateTGS(s *tgsState) bool {
	if s.req.Body.Options&noReferralOptions != 0 {
		return false
	}
	name := s.req.Body.SName
	return isTGSName(*name) && name.Components[1] != k.Realm
}

// noReferralOptions is NO_REFERRAL_OPTION (kdc/kdc_util.h:460): the
// non-TGT options plus user-to-user, every one of which is about a
// ticket already in the client's hands.
const noReferralOptions = nonTGTOptions | wire.OptEncTktInSKey
