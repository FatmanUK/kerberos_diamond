package kdc

import (
	"context"

	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// checkS4USelf is the whole of S4U2Self's authorisation
// (check_tgs_s4u2self, tgs_policy.c:261-357).
//
// **The four legal shapes are enumerated in upstream's own comment**
// (:285-296) and are worth repeating, because every refusal below is
// one of the complement:
//
//	(1) local TGT,  local user,     local server
//	(2) cross TGT,  local user,     issuing a referral
//	(3) cross TGT,  non-local user, issuing a referral
//	(4) cross TGT,  non-local user, local server
//
// The first is single-realm S4U2Self. The others are the initial,
// intermediate and final hops of a cross-realm one, which is why the
// combinations look arbitrary until laid out: the realm the subject
// belongs to is where the impersonation is decided, and a server
// elsewhere has to be sent there and the answer brought back.
//
// Three of the refusals are annotated *"match Windows error"* in the
// C, which is a reason to copy the codes rather than pick sensible
// ones: a Windows client acts on them.
func (k *KDC) checkS4USelf(s *tgsState) (int32, string) {
	if code, status := k.s4uShape(s); code != 0 {
		return code, status
	}
	// The header ticket's PAC is required, and this is where E1
	// and E2 stop being preparation: without a PAC there is
	// nothing that says who the impersonator is
	// (tgs_policy.c:328-332).
	if s.headerPAC == nil {
		return wire.ErrCodeTGTRevoked, "S4U2SELF_NO_PAC"
	}
	return k.s4uPACAndClient(s)
}

// s4uShape is the first half: the request is for self, its options
// are ones an AS request could carry, and the
// crossrealm/local/referral combination is one of the four.
func (k *KDC) s4uShape(s *tgsState) (int32, string) {
	cross := s.headerRealm != k.Realm
	if !s.referral && !k.s4uRequestIsForSelf(s) {
		return wire.ErrCodeBadMatch,
			"INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH"
	}
	// An S4U2Self request stands in for an AS request, so the
	// options an AS request may not carry it may not carry either
	// (:276-280).
	if s.req.Body.Options&wire.ASInvalidOptions != 0 {
		return wire.ErrCodeBadOption,
			"INVALID S4U2SELF OPTIONS"
	}
	return s4uCombination(s.s4uClient != nil, cross,
		s.referral, s.s4u)
}

// s4uCombination is the four-way table, as four refusals.
func s4uCombination(
	local, cross, referral bool,
	req *wire.PAS4UX509User,
) (int32, string) {
	switch {
	case !cross && referral:
		// The requesting server no longer exists and a
		// referral was found in its place, which is a server
		// lookup failure dressed up as success (:297-302).
		return wire.ErrCodeSPrincipalUnknown,
			"LOOKING_UP_SERVER"
	case local && cross && !referral:
		// A local server does not need a cross-realm TGT to
		// impersonate a local principal (:303-308).
		return wire.ErrCodeCPrincipalUnknown,
			"NOT_CROSS_REALM_REQUEST"
	case !local && !cross:
		// The server is asking to impersonate somebody from
		// another realm using a local TGT. It should ask that
		// realm and follow referrals back (:309-316).
		return wire.ErrCodePolicy, "S4U2SELF_CLIENT_NOT_OURS"
	case !local && !named(req):
		// Only a KDC in the subject's own realm can answer a
		// certificate-only request; everybody else needs a
		// name and ignores the certificate (:317-324).
		return wire.ErrCodePolicy,
			"INVALID_XREALM_S4U2SELF_REQUEST"
	}
	return 0, ""
}

// named reports an S4U2Self request that names a principal rather
// than only a certificate.
func named(req *wire.PAS4UX509User) bool {
	return req.UserID.UserName != nil &&
		len(req.UserID.UserName.Components) > 0
}

// s4uPACAndClient is the second half: the header ticket's PAC has to
// name the right principal, and for a local subject the AS-request
// policy is applied to them.
func (k *KDC) s4uPACAndClient(s *tgsState) (int32, string) {
	if s.s4uClient == nil {
		// A non-local subject: the header ticket is a
		// cross-realm TGT whose PAC names the **subject, with
		// realm** -- it came from the subject's own realm and
		// is being carried through (:345-352).
		want := clientInfoName(*s.s4u.UserID.UserName,
			s.s4u.UserID.UserRealm)
		if !k.pacNames(s, want) {
			return wire.ErrCodeBadOption,
				"S4U2SELF_FOREIGN_PAC_CLIENT"
		}
		return 0, ""
	}
	// A local subject: the header ticket's PAC names the
	// *impersonator*, realm-less, because it is the server's own
	// TGT (:334-340).
	if !k.pacNames(s, clientInfoName(s.header.CName, "")) {
		return wire.ErrCodeBadOption,
			"S4U2SELF_LOCAL_PAC_CLIENT"
	}
	// And the subject is checked against AS-request policy, with
	// an **empty server** so that none of the server checks
	// apply: the question is whether this user could have logged
	// in, not whether they could reach this service (:342-344).
	return k.validateASRequest(
		wire.ASReq{Body: s.req.Body},
		s.s4uClient, &store.Principal{}, s.now)
}

// pacNames checks the header PAC's CLIENT_INFO against a name and the
// header ticket's authtime.
//
// Both halves have to match, which is what stops a PAC being lifted
// from one ticket into another: the authtime is the one the PAC was
// signed with.
func (k *KDC) pacNames(s *tgsState, name string) bool {
	return s.headerPAC.VerifyClientInfo(pacClientInfo(
		name, s.header.AuthTime)) == nil
}

// s4uRequestIsForSelf is is_client_db_alias (kdc_util.c:1536-1551):
// the server the request names and the client of the ticket presented
// have to be the same principal, **compared through the database** so
// that an alias of a service can ask on behalf of the service it
// aliases.
//
// Comparing the names directly would refuse a request from a service
// whose TGT names it by one of its own aliases, which is exactly the
// case D1's alias support exists for.
func (k *KDC) s4uRequestIsForSelf(s *tgsState) bool {
	name := store.UnparseName(s.header.CRealm,
		s.header.CName.Components)
	p, err := k.Store.Lookup(context.Background(), name)
	if err != nil || p == nil || s.server == nil {
		return false
	}
	return p.Name == s.server.Name
}

// s4uSelfForwardable clears the forwardable flag when the server may
// not obtain forwardable S4U2Self tickets, which is [MS-SFU]
// 3.2.5.1.2 by way of s4u2self_forwardable (kdc_util.c:1623-1644).
//
// Two conditions, and the second is why this is currently a no-op. A
// server with +ok_to_auth_as_delegate keeps the flag outright. Any
// other server keeps it too **unless it has traditional S4U2Proxy
// delegation targets**, and that relation does not exist in this
// project yet -- it is E6's table. Upstream behaves identically with
// db2, where krb5_db_check_allowed_to_delegate answers
// KRB5_PLUGIN_OP_NOTSUPP and the flag is left alone (:1637-1642), so
// this agrees with the oracle rather than merely being unfinished.
//
// It is written now, with the branch named, because the alternative
// is a silent difference: a reader finding no forwardable handling
// here could not tell whether it was considered.
func (k *KDC) s4uSelfForwardable(
	s *tgsState,
	flags wire.Flags,
) wire.Flags {
	if s.s4u == nil || s.referral {
		return flags
	}
	if s.server != nil && s.server.Attributes&
		store.AttrOKToAuthAsDelegate != 0 {
		return flags
	}
	if k.hasDelegationTargets(s.server) {
		return flags &^ wire.FlagForwardable
	}
	return flags
}

// hasDelegationTargets is krb5_db_check_allowed_to_delegate with a
// null proxy: "does this server have any authorised delegation
// targets at all?".
//
// Sharing one method between that question and the per-target one is
// upstream's (kdc_util.c:1634-1636), and so is sharing one table
// here. What it decides is whether a server may hold *forwardable*
// S4U2Self tickets: a server with traditional delegation targets
// already has a way to act for a user, so [MS-SFU] 3.2.5.1.2 denies
// it the forwardable flag as well unless it is explicitly marked
// +ok_to_auth_as_delegate.
func (k *KDC) hasDelegationTargets(p *store.Principal) bool {
	if p == nil {
		return false
	}
	return k.Store.AllowedToDelegate(context.Background(),
		p.Name, "") == nil
}
