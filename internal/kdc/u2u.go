package kdc

import (
	"context"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// User-to-user authentication, KDC_OPT_ENC_TKT_IN_SKEY.
//
// The shape is worth stating because it is the one TGS case where the
// issued ticket is not sealed with a long-term key at all. Alice
// wants a ticket to Bob, but Bob is a *user* rather than a service
// and has no long-term key in a keytab anywhere. So Bob hands Alice
// his own TGT, Alice sends it as the request's second ticket, and the
// KDC seals the new ticket with the **session key inside Bob's TGT**
// -- which Bob knows and nobody else does.
//
// That is why DISALLOW_SVR does not forbid it
// (check_tgs_svc_deny_all, kdc/tgs_policy.c:152-156): a principal
// that may not be a service may still be reached this way, and
// refusing it would be refusing the only mechanism that works for a
// user.

// readSecondTicket decrypts the request's second ticket, if the
// options call for one.
//
// Upstream reads it for either of two options -- user-to-user and
// S4U2Proxy's cname-in-addl-tkt (STKT_OPTIONS, do_tgs_req.c:250) --
// and only S4U2Proxy is absent here, so this reads it for the one.
//
// A missing second ticket is *not* an error here, deliberately:
// decrypt_2ndtkt returns success with no ticket (:275-277) and leaves
// the complaint to check_tgs_u2u, which runs after the ordinary
// option and policy checks. Refusing here instead would answer
// NO_2ND_TKT to a request that upstream refuses for a different and
// better reason.
func (k *KDC) readSecondTicket(s *tgsState) (int32, string) {
	if s.req.Body.Options&wire.OptEncTktInSKey == 0 {
		return 0, ""
	}
	tickets, err := s.req.Body.Tickets()
	if err != nil {
		return wire.ErrCodeModified, "2ND_TKT_DECODE"
	}
	if len(tickets) == 0 {
		return 0, ""
	}
	second := tickets[0]
	// ticketKey looks a ticket's server up in this realm whatever
	// realm the ticket claims, as it does for the header ticket,
	// so the claim is checked here rather than relied on not to
	// matter.
	if second.Realm != k.Realm {
		return wire.ErrCodeNotUs, "2ND_TKT_FOREIGN"
	}
	key, code, _ := k.ticketKey(second)
	if code != 0 {
		return code, "2ND_TKT_SERVER"
	}
	tkt, code, _ := openTicket(second, key)
	if code != 0 {
		return code, "2ND_TKT_DECRYPT"
	}
	s.stkt = &tkt
	s.stktSrv = second.SName
	return 0, ""
}

// checkU2U is check_tgs_u2u (kdc/tgs_policy.c:583-605).
//
// Three conditions, three different errors, and the third is the one
// that makes the mechanism safe: the second ticket's *client* has to
// be the principal the request asked for a ticket to. Without it
// anyone holding any TGT could have the KDC seal a ticket naming
// someone else under a key they chose.
func (k *KDC) checkU2U(s *tgsState) (int32, string) {
	if s.req.Body.Options&wire.OptEncTktInSKey == 0 {
		return 0, ""
	}
	if s.stkt == nil {
		return wire.ErrCodeBadOption, "NO_2ND_TKT"
	}
	// It has to be this realm's own krbtgt, not any old ticket:
	// the session key in a service ticket is known to that
	// service, which would otherwise get to choose whose key
	// seals what.
	if !isTGSName(s.stktSrv) ||
		s.stktSrv.Components[1] != k.Realm {
		return wire.ErrCodePolicy, "2ND_TKT_NOT_TGS"
	}
	if !k.stktClientIsServer(s) {
		return wire.ErrCodeServerNoMatch, "2ND_TKT_MISMATCH"
	}
	return 0, ""
}

// stktClientIsServer reports whether the second ticket's client is
// the principal the new ticket is for.
//
// Upstream compares through the database rather than by name
// (is_client_db_alias, kdc_util.c:1535-1549): it looks the ticket's
// client up and compares the *canonical* entry to the server's, so an
// alias on either side still matches. This compares the resolved
// server entry's name for the same reason, which is as far as the
// comparison can go until aliases are resolved anywhere else in this
// KDC -- store.Alias exists, and nothing reads it yet.
func (k *KDC) stktClientIsServer(s *tgsState) bool {
	name := store.UnparseName(
		s.stkt.CRealm, s.stkt.CName.Components)
	cl, err := k.Store.Lookup(context.Background(), name)
	if err != nil {
		return false
	}
	return cl.Name == s.server.Name
}

// u2uSessionEType is the enctype preference user-to-user imposes,
// from get_2ndtkt_enctype (do_tgs_req.c:309-328).
//
// The second ticket's session key enctype wins when the request lists
// it, and upstream's comment says why in full: the KDC has no idea
// what the application server supports, but it must support the
// enctype of the session key in its own TGT, or it could not decrypt
// the ticket it is about to be handed (gen_session_key, :330-345).
//
// Note the two different ways this declines. An enctype this KDC does
// not implement is an error, because the ticket could not have been
// issued here; an enctype the *request* did not list is not, and the
// ordinary selection runs instead. So a zero enctype with no error is
// "no preference", not a failure.
func u2uSessionEType(s *tgsState) (crypto.EncType, int32, string) {
	if s.stkt == nil {
		return 0, 0, ""
	}
	want := s.stkt.Key.KeyType
	if _, err := crypto.Profile(
		crypto.EncType(want)); err != nil {
		return 0, wire.ErrCodeETypeNoSupp,
			"BAD_ETYPE_IN_2ND_TKT"
	}
	for _, e := range s.req.Body.EType {
		if e == want {
			return crypto.EncType(want), 0, ""
		}
	}
	return 0, 0, ""
}

// u2uSealingKey is the key the new ticket is sealed with: the session
// key out of the second ticket.
//
// The ticket's key version is *absent* in this case, not the server's
// (do_tgs_req.c:1056-1061). There is no key version to name -- the
// key is a session key, which has none -- and a client that read a
// version here would look for a long-term key that was never
// involved.
func u2uSealingKey(s *tgsState) ([]byte, crypto.EncType, int32) {
	return s.stkt.Key.KeyValue,
		crypto.EncType(s.stkt.Key.KeyType), 0
}
