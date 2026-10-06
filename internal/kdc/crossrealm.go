package kdc

import "github.com/FatmanUK/kerberos_diamond/internal/wire"

// Cross-realm, and what the shape of it is.
//
// A client in realm A reaching a service in realm B does it in three
// exchanges, and only the third is new. First an ordinary AS exchange
// at A's KDC for krbtgt/A@A. Then an ordinary TGS exchange at A's KDC
// for krbtgt/B@A -- ordinary because that principal is just a
// principal, held in A's own database, whose key A and B share. Then
// a TGS exchange at *B's* KDC presenting that ticket, which is the
// one this file is about: the ticket's realm is A, not B.
//
// So nothing on the issuing side needed changing. What needed
// changing was the assumption that a presented ticket belongs to this
// realm. The key for krbtgt/B@A is looked up under the ticket's own
// realm, so the lookup succeeding *is* the trust check: a KDC holds a
// key for a foreign realm's krbtgt exactly when it has agreed to
// trust it.

// isCrossRealm reports whether the presented ticket came from another
// realm, which upstream decides by comparing the header ticket's
// server realm against the requested server's (gather_tgs_req_info,
// do_tgs_req.c:685-687).
func (s *tgsState) isCrossRealm(local string) bool {
	return s.headerRealm != local
}

// checkLineage is check_tgs_lineage (kdc/tgs_policy.c:249-258).
//
// A foreign KDC may not assert a client of *this* realm. If it could,
// any realm this one trusts for its own users could mint a ticket
// naming a local principal, and every service here would believe it
// -- which is a complete compromise rather than a trust relationship.
func (k *KDC) checkLineage(s *tgsState) (int32, string) {
	if !s.isCrossRealm(k.Realm) {
		return 0, ""
	}
	if s.header.CRealm == k.Realm {
		return wire.ErrCodePolicy, "INVALID LINEAGE"
	}
	return 0, ""
}
