package kdc

import (
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// canonNames works out the two names an AS reply carries, which are
// not always the ones the request asked for (do_as_req.c:656-686).
//
// Two separate rules, and the C puts them thirty lines apart:
//
//   - **the server** is canonicalised only when KDC_OPT_CANONICALIZE
//     is set *and* both the requested and the found server are
//     ticket-granting services (:659-663). Upstream explains why in
//     a comment -- canonicalisation is "only effective if we are
//     issuing a TGT (the intention is to allow support for Windows
//     'short' realm aliases, nothing more)".
//   - **the client** is canonicalised whenever CANONICALIZE is set,
//     with no such condition (:680-682). Without it the request's
//     own name is used.
//
// The realm does not come into either: this KDC refuses a request
// naming any other realm, so the realm in the reply is always its own
// -- see ourRealm, which is where upstream's "The realm is always
// canonicalized" is satisfied instead.
//
// None of this can be reached without an alias. The found entry's
// name can only differ from the requested name when the request named
// an alias of it, which is why the whole of this arrived with KDB
// aliases rather than before them.
func (k *KDC) canonNames(s *asState) {
	s.ticketCName = s.cname
	s.ticketSName = *s.req.Body.SName
	if s.req.Body.Options&wire.OptCanonicalize == 0 {
		return
	}
	if n, ok := nameOf(s.client); ok {
		s.ticketCName = n
	}
	if !isTGSName(s.ticketSName) {
		return
	}
	n, ok := nameOf(s.server)
	if ok && isTGSName(n) {
		s.ticketSName = n
	}
}

// nameOf turns a stored principal's canonical name into the form a
// message carries.
//
// The name type is the stored one when there is one. A principal
// created by this project's own tools carries NT-PRINCIPAL, and one
// loaded from a dump carries whatever the dump said -- so a zero here
// means "not recorded" rather than NT-UNKNOWN, and the caller's
// existing type is left in place.
func nameOf(p *store.Principal) (wire.PrincipalName, bool) {
	var zero wire.PrincipalName
	if p == nil {
		return zero, false
	}
	components, _, err := store.ParseName(p.Name)
	if err != nil || len(components) == 0 {
		return zero, false
	}
	t := p.NameType
	if t == 0 {
		t = wire.NTPrincipal
	}
	return wire.PrincipalName{
		Type:       t,
		Components: components,
	}, true
}
