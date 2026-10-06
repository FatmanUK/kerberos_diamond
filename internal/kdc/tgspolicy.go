package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// tgsFlagRule is one "this option needs that ticket flag" rule, as
// upstream tabulates them (tgsflagrules, kdc/tgs_policy.c:65-77).
type tgsFlagRule struct {
	opt    wire.Flags
	needs  wire.Flags
	status string
	code   int32
}

// tgsFlagRules is the table verbatim. Keeping it a table rather than
// a chain of ifs is upstream's shape and the reason is the same: the
// rules are data, and a new one should be a row.
var tgsFlagRules = []tgsFlagRule{
	{wire.OptForwarded, wire.FlagForwardable,
		"TGT NOT FORWARDABLE", wire.ErrCodeBadOption},
	{wire.OptProxy, wire.FlagProxiable,
		"TGT NOT PROXIABLE", wire.ErrCodeBadOption},
	{wire.OptAllowPostdate | wire.OptPostdated,
		wire.FlagMayPostdate,
		"TGT NOT POSTDATABLE", wire.ErrCodeBadOption},
	{wire.OptValidate, wire.FlagInvalid,
		"VALIDATE VALID TICKET", wire.ErrCodeBadOption},
	{wire.OptRenew, wire.FlagRenewable,
		"TICKET NOT RENEWABLE", wire.ErrCodeBadOption},
}

// checkTGSOpts is check_tgs_opts (kdc/tgs_policy.c:81-105).
//
// The last rule is the one worth reading twice: an INVALID ticket is
// refused unless the request is a validation, which is how a
// postdated ticket stays unusable until its start time arrives.
func checkTGSOpts(
	opts wire.Flags,
	tkt wire.EncTicketPart,
) (int32, string) {
	for _, r := range tgsFlagRules {
		if opts&r.opt == 0 {
			continue
		}
		if tkt.Flags&r.needs == 0 {
			return r.code, r.status
		}
	}
	if tkt.Flags.Has(wire.FlagInvalid) &&
		opts&wire.OptValidate == 0 {
		return wire.ErrCodeTktNYV, "TICKET NOT VALID"
	}
	return 0, ""
}

// svcDenyRules is svcdenyrules (kdc/tgs_policy.c:107-113): options a
// service principal can forbid. Note the three different error codes
// for what looks like one kind of refusal.
var svcDenyRules = []struct {
	opt    wire.Flags
	attr   uint32
	status string
	code   int32
}{
	{wire.OptRenewable, store.AttrDisallowRenewable,
		"NON-RENEWABLE TICKET", wire.ErrCodePolicy},
	{wire.OptAllowPostdate, store.AttrDisallowPostdated,
		"NON-POSTDATABLE TICKET", wire.ErrCodeCannotPostdate},
	{wire.OptEncTktInSKey, store.AttrDisallowDupSKey,
		"DUP_SKEY DISALLOWED", wire.ErrCodePolicy},
}

// checkTGSService is check_tgs_svc_policy (kdc/tgs_policy.c:200-213),
// which runs four checks in a fixed order.
func checkTGSService(
	opts wire.Flags,
	server *store.Principal,
	tkt wire.EncTicketPart,
	now uint32,
) (int32, string) {
	for _, r := range svcDenyRules {
		if opts&r.opt != 0 && server.Attributes&r.attr != 0 {
			return r.code, r.status
		}
	}
	if code, status := svcDenyAll(opts, server, tkt); code != 0 {
		return code, status
	}
	if code, status := svcReqdFlags(server, tkt); code != 0 {
		return code, status
	}
	if exp := stamp(server.Expiration); exp != 0 &&
		tsAfter(now, exp) {
		return wire.ErrCodeServiceExp, "SERVICE EXPIRED"
	}
	return 0, ""
}

// svcDenyAll is check_tgs_svc_deny_all (kdc/tgs_policy.c:143-164).
func svcDenyAll(
	opts wire.Flags,
	server *store.Principal,
	tkt wire.EncTicketPart,
) (int32, string) {
	if server.Attributes&store.AttrDisallowAllTix != 0 {
		return wire.ErrCodeSPrincipalUnknown,
			"SERVER LOCKED OUT"
	}
	if server.Attributes&store.AttrDisallowSvr != 0 &&
		opts&wire.OptEncTktInSKey == 0 {
		return wire.ErrCodeMustUseUser2User,
			"SERVER NOT ALLOWED"
	}
	// A service can refuse to be reached from a TGT at all, which
	// only applies when the presented ticket *is* a TGT.
	if server.Attributes&store.AttrDisallowTGTBased != 0 &&
		isTGSName(tkt.CName) {
		return wire.ErrCodePolicy, "TGT BASED NOT ALLOWED"
	}
	return 0, ""
}

// svcReqdFlags is check_tgs_svc_reqd_flags
// (kdc/tgs_policy.c:169-187).
//
// Both of these answer with the *generic* error rather than something
// specific, which is upstream's choice: a service's preauth
// requirement is not something to describe to a caller that failed
// it.
func svcReqdFlags(
	server *store.Principal,
	tkt wire.EncTicketPart,
) (int32, string) {
	if server.Attributes&store.AttrRequiresHWAuth != 0 &&
		!tkt.Flags.Has(wire.FlagHWAuthent) {
		return wire.ErrCodeGeneric, "NO HW PREAUTH"
	}
	if server.Attributes&store.AttrRequiresPreAuth != 0 &&
		!tkt.Flags.Has(wire.FlagPreAuthent) {
		return wire.ErrCodeGeneric, "NO PREAUTH"
	}
	return 0, ""
}

// checkTGSTimes is check_tgs_times (kdc/tgs_policy.c:220-247).
//
// The header ticket's end time is *not* checked here: it was already
// checked when the AP-REQ was read. What is left is the two cases
// where a request asks for something the ticket's own times forbid.
func checkTGSTimes(
	opts wire.Flags,
	tkt wire.EncTicketPart,
	now uint32,
) (int32, string) {
	if opts&wire.OptValidate != 0 {
		start := stamp(tkt.EffectiveStartTime())
		if tsAfter(start, now) {
			return wire.ErrCodeTktNYV, "NOT_YET_VALID"
		}
	}
	if opts&wire.OptRenew != 0 &&
		tsAfter(now, stamp(tkt.RenewTill)) {
		return wire.ErrCodeTktExpired, "TKT_EXPIRED"
	}
	return 0, ""
}

// isTGSName reports whether a principal name is a ticket-granting
// service: two components whose first is "krbtgt".
func isTGSName(p wire.PrincipalName) bool {
	return len(p.Components) == 2 &&
		p.Components[0] == tgsName
}

// tgsName is the ticket-granting service's first component
// (KRB5_TGS_NAME, include/krb5/krb5.hin).
const tgsName = "krbtgt"
