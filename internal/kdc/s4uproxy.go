package kdc

import (
	"context"
	"errors"

	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// checkS4UProxy is check_tgs_s4u2proxy (tgs_policy.c:423-518): the
// constraints on a constrained-delegation request, before the
// question of whether the realm authorises it.
//
// S4U2Proxy is a service presenting **two** tickets: its own TGT as
// the header ticket, and a forwardable service ticket that a user
// obtained *to it* as the evidence. It asks for a ticket to a third
// service, and gets one naming the user. So the service acts for a
// user who really did authenticate to it -- which is the whole
// difference from S4U2Self, where the user never appeared.
//
// Six refusals here and the authorisation after them, which is
// deliberate: a request that is malformed is told so, and only a
// well-formed one reaches the question of policy.
func (k *KDC) checkS4UProxy(s *tgsState) (int32, string) {
	if code, status := s4uProxyShape(s); code != 0 {
		return code, status
	}
	// The header ticket's PAC must be present and must name the
	// impersonator, which is the same requirement S4U2Self has
	// and for the same reason (:452-461).
	if s.headerPAC == nil {
		return wire.ErrCodeTGTRevoked,
			"S4U2PROXY_NO_HEADER_PAC"
	}
	if !k.pacNames(s, clientInfoName(s.header.CName, "")) {
		return wire.ErrCodeBadOption, "S4U2PROXY_HEADER_PAC"
	}
	// **The evidence ticket's PAC is KRB5KRB_AP_ERR_MODIFIED and
	// not TGT_REVOKED** when it is missing (:470-473), which is a
	// different code for what looks like the same fault: the
	// header ticket is the requester's own and a missing PAC
	// there is a revoked credential, where the evidence ticket
	// was issued by this realm and one without a PAC has been
	// tampered with.
	if s.stktPAC == nil {
		return wire.ErrCodeModified, "S4U2PROXY_NO_STKT_PAC"
	}
	return k.s4uProxyEvidence(s)
}

// s4uProxyShape is the first four refusals, all about the request
// rather than about any ticket's contents.
func s4uProxyShape(s *tgsState) (int32, string) {
	if s.stkt == nil {
		return wire.ErrCodeBadOption, "NO_2ND_TKT"
	}
	// **The evidence ticket must be forwardable**, which is how a
	// user consents: a client that does not want to be delegated
	// asks for a non-forwardable ticket and cannot be (:433-436).
	if !s.stkt.Flags.Has(wire.FlagForwardable) {
		return wire.ErrCodeBadOption,
			"EVIDENCE_TKT_NOT_FORWARDABLE"
	}
	if s.req.Body.Options&noReferralOptions != 0 {
		return wire.ErrCodeBadOption,
			"INVALID_S4U2PROXY_OPTIONS"
	}
	// **A ticket-granting service is not a legal target.** A TGT
	// obtained this way would let the impersonator ask for
	// anything at all, which is *un*constrained delegation and is
	// the thing being constrained (:447-450).
	if isTGSName(*s.req.Body.SName) {
		return wire.ErrCodePolicy, "NOT_ALLOWED_TO_DELEGATE"
	}
	return 0, ""
}

// s4uProxyEvidence checks the evidence ticket against the header
// ticket, which is where the local and cross-realm cases part
// (tgs_policy.c:475-515).
//
// **Only the local case is implemented**, and the cross-realm one is
// refused rather than mishandled. A cross-realm RBCD request's
// evidence ticket is a referral TGT whose PAC carries
// KRB5_PAC_DELEGATION_INFO, and reading that needs NDR -- 331 lines
// of it in upstream (kdc/ndr.c), for one buffer, whose own header
// comment admits it does not decode RPC_UNICODE_STRING's
// conformant-varying-array lengths generically. The plan put that
// with the cross-realm case for exactly this reason: local-realm
// S4U2Proxy needs none of it.
func (k *KDC) s4uProxyEvidence(s *tgsState) (int32, string) {
	if s.headerRealm != k.Realm {
		return wire.ErrCodeBadOption,
			"XREALM_EVIDENCE_TICKET_MISMATCH"
	}
	// The evidence ticket was issued *to the impersonator*, so
	// its server and the header ticket's client are the same
	// principal -- compared through the database, so an alias of
	// the service works (:481-487).
	if !k.sameDBPrincipal(s.stktSrv, s.headerRealm,
		s.header.CName, s.header.CRealm) {
		return wire.ErrCodeServerNoMatch,
			"EVIDENCE_TICKET_MISMATCH"
	}
	// And the evidence ticket's own PAC names the subject, which
	// is its client (:489-495).
	want := pacClientInfo(
		clientInfoName(s.stkt.CName, ""), s.stkt.AuthTime)
	if s.stktPAC.VerifyClientInfo(want) != nil {
		return wire.ErrCodeBadOption,
			"S4U2PROXY_LOCAL_STKT_PAC"
	}
	return 0, ""
}

// checkS4UProxyPolicy is check_s4u2proxy_policy
// (tgs_policy.c:519-571): whether the realm authorises this
// delegation, by either of two relations.
//
// **The two relations are tried in order and either suffices**, and
// the order is upstream's: resource-based first when the client said
// it understands RBCD, then traditional. A denial by one is
// remembered so that the error distinguishes "the realm says no" from
// "the realm has no rule either way" -- NOT_ALLOWED_TO_DELEGATE
// against UNSUPPORTED_S4U2PROXY_REQUEST (:567-570). Both are
// KDC_ERR_BADOPTION on the wire; the difference is in the log, which
// is where an operator looks.
//
// Traditional authorisation is skipped for a cross-realm requester
// (:557): a grant made by this realm's administrator is about this
// realm's services.
func (k *KDC) checkS4UProxyPolicy(s *tgsState) (int32, string) {
	denied := false
	if supportsRBCD(s.req.PAData) {
		err := k.rbcdAllows(s)
		if err == nil {
			return 0, ""
		}
		denied = denied || errors.Is(err, store.ErrNotAllowed)
	}
	if s.headerRealm == k.Realm {
		err := k.traditionalAllows(s)
		if err == nil {
			return 0, ""
		}
		denied = denied || errors.Is(err, store.ErrNotAllowed)
	}
	if denied {
		return wire.ErrCodeBadOption,
			"NOT_ALLOWED_TO_DELEGATE"
	}
	return wire.ErrCodeBadOption,
		"UNSUPPORTED_S4U2PROXY_REQUEST"
}

// rbcdAllows asks the resource whether it accepts delegation from
// this impersonator.
func (k *KDC) rbcdAllows(s *tgsState) error {
	resource := store.UnparseName(k.Realm,
		s.serverName.Components)
	imp := store.UnparseName(s.header.CRealm,
		s.header.CName.Components)
	return k.Store.AllowedToDelegateFrom(
		context.Background(), resource, imp)
}

// traditionalAllows asks the impersonator's own grants whether this
// target is among them.
func (k *KDC) traditionalAllows(s *tgsState) error {
	imp := store.UnparseName(s.header.CRealm,
		s.header.CName.Components)
	target := store.UnparseName(k.Realm,
		s.req.Body.SName.Components)
	return k.Store.AllowedToDelegate(
		context.Background(), imp, target)
}

// sameDBPrincipal compares two names through the database, which is
// is_client_db_alias (kdc_util.c:1536-1551): two spellings of one
// principal are the same principal.
func (k *KDC) sameDBPrincipal(
	a wire.PrincipalName,
	aRealm string,
	b wire.PrincipalName,
	bRealm string,
) bool {
	ctx := context.Background()
	pa, err := k.Store.Lookup(ctx,
		store.UnparseName(aRealm, a.Components))
	if err != nil {
		return false
	}
	pb, err := k.Store.Lookup(ctx,
		store.UnparseName(bRealm, b.Components))
	if err != nil {
		return false
	}
	return pa.Name == pb.Name
}
