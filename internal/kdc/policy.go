package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// validateASRequest is the policy gate, ported from
// validate_as_request (kdc/kdc_util.c:715-803).
//
// The *order* of these checks is upstream's and is load-bearing: a
// client's behaviour depends on which error it gets, so a request
// that trips two of them must trip the same one the C would.
// Reordering them would be invisible to any test that checks only
// that a bad request is refused.
func (k *KDC) validateASRequest(
	req wire.ASReq,
	client, server *store.Principal,
	now uint32,
) (int32, string) {
	if req.Body.Options&wire.ASInvalidOptions != 0 {
		return wire.ErrCodeBadOption, "INVALID AS OPTIONS"
	}
	if code, status := expiries(client, server, now); code != 0 {
		return code, status
	}
	if client.Attributes&store.AttrRequiresPWChange != 0 &&
		server.Attributes&store.AttrPWChangeService == 0 {
		return wire.ErrCodeKeyExpired, "REQUIRED PWCHANGE"
	}
	if postdateRefused(req, client, server) {
		return wire.ErrCodeCannotPostdate,
			"POSTDATE NOT ALLOWED"
	}
	if client.Attributes&store.AttrDisallowAllTix != 0 {
		return wire.ErrCodeClientRevoked, "CLIENT LOCKED OUT"
	}
	// A locked-out *service* is reported as unknown rather than
	// revoked, deliberately: it tells a client nothing about
	// whether the principal exists.
	if server.Attributes&store.AttrDisallowAllTix != 0 {
		return wire.ErrCodeSPrincipalUnknown,
			"SERVICE LOCKED OUT"
	}
	if server.Attributes&store.AttrDisallowSvr != 0 {
		return wire.ErrCodeMustUseUser2User,
			"SERVICE NOT ALLOWED"
	}
	return 0, ""
}

// expiries checks the three expiry conditions in upstream's order.
//
// Note that the client's *password* expiry is excused when the
// service is a password-changing service, which is how a user with an
// expired password can still change it.
func expiries(
	client, server *store.Principal,
	now uint32,
) (int32, string) {
	if exp := stamp(client.Expiration); exp != 0 &&
		tsAfter(now, exp) {
		return wire.ErrCodeNameExp, "CLIENT EXPIRED"
	}
	if exp := stamp(client.PWExpiration); exp != 0 &&
		tsAfter(now, exp) &&
		server.Attributes&store.AttrPWChangeService == 0 {
		return wire.ErrCodeKeyExpired, "CLIENT KEY EXPIRED"
	}
	if exp := stamp(server.Expiration); exp != 0 &&
		tsAfter(now, exp) {
		return wire.ErrCodeServiceExp, "SERVICE EXPIRED"
	}
	return 0, ""
}

// postdateRefused reports whether a postdating request must be
// refused because either principal disallows it.
func postdateRefused(
	req wire.ASReq,
	client, server *store.Principal,
) bool {
	asked := req.Body.Options&
		(wire.OptAllowPostdate|wire.OptPostdated) != 0
	disallowed := client.Attributes&
		store.AttrDisallowPostdated != 0 ||
		server.Attributes&store.AttrDisallowPostdated != 0
	return asked && disallowed
}

// optsCommonFlagsMask is the set of KDC options that request the
// ticket flag of the same bit number (OPTS_COMMON_FLAGS_MASK,
// kdc/kdc_util.h:493-497). Note that renewable is *not* in it: it
// needs ticketRenewTime's decision, not a straight copy.
// OptRequestAnon is in upstream's mask and **not in this one**,
// because this KDC refuses the option outright rather than issuing a
// ticket for it -- see refuseAnonymous. Leaving it in the mask is how
// the flag used to reach a ticket and then be cleared again, which
// told a client nothing.
const optsCommonFlagsMask = wire.OptForwardable |
	wire.OptForwarded | wire.OptProxiable | wire.OptProxy |
	wire.OptAllowPostdate | wire.OptPostdated

// ticketFlags computes a new ticket's flags, ported from
// get_ticket_flags (kdc/kdc_util.c:812-858) for the AS case, where
// there is no header ticket.
//
// Two things an AS ticket always gets: TKT_FLG_INITIAL, because it
// was issued from a password rather than from another ticket, and
// TKT_FLG_ENC_PA_REP, which advertises RFC 6806 encrypted padata
// support unconditionally.
//
// Forwardable and proxiable are cleared if *either* principal
// disallows them -- not only the client -- so a service can refuse to
// accept forwardable tickets for itself.
func ticketFlags(
	opts wire.Flags,
	client, server *store.Principal,
) wire.Flags {
	flags := (opts & optsCommonFlagsMask) |
		wire.FlagEncPARep | wire.FlagInitial
	if opts&wire.OptPostdated != 0 {
		flags |= wire.FlagInvalid
	}
	disallow := client.Attributes | server.Attributes
	if disallow&store.AttrDisallowProxiable != 0 {
		flags &^= wire.FlagProxiable
	}
	if disallow&store.AttrDisallowForwardable != 0 {
		flags &^= wire.FlagForwardable
	}
	return flags
}

// tgsCopiedFlagsMask is TGS_COPIED_FLAGS_MASK
// (kdc/kdc_util.h:523-527): the flags a derived ticket inherits from
// the one it was derived from.
//
// PRE-AUTHENT is in it, which is what lets a service require preauth
// and still be reached with a service ticket: the bit travels from
// the TGT rather than being re-established.
const tgsCopiedFlagsMask = wire.FlagForwarded | wire.FlagProxy |
	wire.FlagPreAuthent | wire.FlagHWAuthent | wire.FlagAnonymous

// tgsTicketFlags computes the flags for a ticket issued from another
// ticket -- get_ticket_flags (kdc/kdc_util.c:812-858) for the TGS
// case.
//
// Three things differ from the AS case. A validation or renewal
// preserves the presented ticket's flags wholesale, minus INVALID
// (:819-821). There is no INITIAL: the ticket was not issued from a
// password. And the flags the presented ticket lacks are *subtracted*
// again afterwards, so a request cannot ask for forwardable from a
// ticket that is not.
func tgsTicketFlags(
	opts wire.Flags,
	server *store.Principal,
	header wire.EncTicketPart,
) wire.Flags {
	if opts&(wire.OptValidate|wire.OptRenew) != 0 {
		return header.Flags &^ wire.FlagInvalid
	}
	flags := (opts & optsCommonFlagsMask) | wire.FlagEncPARep
	if opts&wire.OptPostdated != 0 {
		flags |= wire.FlagInvalid
	}
	flags |= header.Flags & tgsCopiedFlagsMask
	if server.Attributes&store.AttrOKAsDelegate != 0 {
		flags |= wire.FlagOKAsDelegate
	}
	if server.Attributes&store.AttrDisallowProxiable != 0 ||
		!header.Flags.Has(wire.FlagProxiable) {
		flags &^= wire.FlagProxiable
	}
	if server.Attributes&store.AttrDisallowForwardable != 0 ||
		!header.Flags.Has(wire.FlagForwardable) {
		flags &^= wire.FlagForwardable
	}
	if !header.Flags.Has(wire.FlagAnonymous) {
		flags &^= wire.FlagAnonymous
	}
	return flags
}
