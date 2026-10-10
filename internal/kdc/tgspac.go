package kdc

import (
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/ndr"
	"github.com/FatmanUK/kerberos_diamond/internal/pac"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// verifyHeaderPAC checks the PAC in the presented ticket, if it has
// one (get_verified_pac, kdc_util.c:583-630).
//
// **An absent PAC is not a refusal**, and that is what lets this KDC
// keep answering requests for tickets it issued before it issued any
// PACs -- and what lets it answer a cross-realm request from a realm
// that issues none.
func (k *KDC) verifyHeaderPAC(s *tgsState) (int32, string) {
	p, err := k.verifiedPAC(s.headerSrv, s.header,
		s.headerKey())
	if err != nil {
		return wire.ErrCodeModified, "HEADER PAC"
	}
	s.headerPAC = p
	return 0, ""
}

// verifiedPAC verifies a ticket's PAC, choosing between the two
// branches upstream has.
//
// **For a local or cross-realm TGT only the server signature is
// checked** (:601-605), privsvr left out entirely. That is the
// ordinary case -- the header ticket of a TGS request is a
// ticket-granting ticket -- and the reason is that a TGT's server
// signature was already made with the krbtgt key, so the privsvr
// signature over it would be the same key twice; for a cross-realm
// TGT the privsvr key is another realm's and this one does not hold
// it.
func (k *KDC) verifiedPAC(
	srv wire.PrincipalName,
	part wire.EncTicketPart,
	key wire.EncryptionKey,
) (*pac.PAC, error) {
	if isTGSName(srv) {
		return pac.VerifyTicket(&part, srv, key,
			wire.EncryptionKey{})
	}
	p, err := k.tryVerifyPAC(srv, part, key, 0)
	if err == nil {
		return p, nil
	}
	return k.retryOlderKVNOs(srv, part, key)
}

// tryVerifyPAC verifies with the privsvr key derived from one krbtgt
// key version, 0 meaning the current one (try_verify_pac,
// kdc_util.c:566-581).
func (k *KDC) tryVerifyPAC(
	srv wire.PrincipalName,
	part wire.EncTicketPart,
	key wire.EncryptionKey,
	kvno int32,
) (*pac.PAC, error) {
	tgt, err := k.tgtKeyAt(kvno)
	if err != nil {
		return nil, err
	}
	return pac.VerifyTicket(&part, srv, key, tgt)
}

// retryOlderKVNOs tries the two previous krbtgt key versions, because
// **a PAC signature carries no kvno** (:613-620).
//
// Nothing in the PAC says which key version signed it, so a KDC that
// has just rolled its krbtgt key cannot tell a forgery from a ticket
// signed a minute earlier except by trying. Two is upstream's number
// and the limit is what stops a rollover history being a search
// space.
//
// Upstream regression-tests a krbtgt rollover in the middle of an
// S4U2Self exchange (t_s4u.py:125-145), which is what this is for.
func (k *KDC) retryOlderKVNOs(
	srv wire.PrincipalName,
	part wire.EncTicketPart,
	key wire.EncryptionKey,
) (*pac.PAC, error) {
	current, err := k.tgtKVNO()
	if err != nil {
		return nil, err
	}
	var last error = errPACUnverified
	for kvno := current - 1; kvno > 0 &&
		kvno > current-3; kvno-- {
		p, err := k.tryVerifyPAC(srv, part, key, kvno)
		if err == nil {
			return p, nil
		}
		last = err
	}
	return nil, last
}

// tgtKeyAt is the privsvr key for a krbtgt key version, 0 meaning the
// current one.
func (k *KDC) tgtKeyAt(kvno int32) (wire.EncryptionKey, error) {
	if kvno == 0 {
		raw, etype, _, err := k.localTGT()
		if err != nil {
			return wire.EncryptionKey{}, err
		}
		return wire.EncryptionKey{
			KeyType: int32(etype), KeyValue: raw,
		}, nil
	}
	p, err := k.localTGTEntry()
	if err != nil {
		return wire.EncryptionKey{}, err
	}
	start := 0
	row, raw, err := k.Store.Key(p, &start, store.AnyEType,
		store.AnySaltType, kvno)
	if err != nil {
		return wire.EncryptionKey{}, err
	}
	return wire.EncryptionKey{
		KeyType: row.EType, KeyValue: raw,
	}, nil
}

// tgsPAC attaches a PAC to a TGS-issued ticket.
//
// A TGS request can neither ask for a PAC nor decline one: what
// decides it is whether the ticket it presented carried one
// (handle_pac's `!is_as_req && subject_pac == NULL', :488-489). So a
// client that declined a PAC at the AS exchange gets no PAC in any
// service ticket it spends that TGT for, which is the property every
// golden case has relied on.
//
// The CLIENT_INFO buffer is **copied from the presented PAC** rather
// than rebuilt, and no client info is added during signing
// (:544-553). Upstream's comment says why: the incoming client info
// was already validated, and rebuilding it would quietly replace the
// name in a ticket being re-issued.
func (k *KDC) tgsPAC(
	s *tgsState,
	part *wire.EncTicketPart,
) error {
	if !k.wantPAC(s.server, part.Flags, false, nil,
		s.headerPAC) {
		return nil
	}
	ci := s4uPACClient(s, part)
	subject := k.subjectPAC(s)
	// The delegation info is *replaced* rather than carried on a
	// local constrained-delegation request, so it is left out of
	// the copy there and written afresh below -- which is
	// upstream's if/else (kdc_authdata.c:519-529).
	fresh, err := copyPACBuffers(subject, copyRules{
		clientInfo: ci == nil,
		delegation: !k.extendsDelegation(s),
	})
	if err != nil {
		return err
	}
	if err := k.addDelegationInfo(s, fresh,
		subject); err != nil {
		return err
	}
	privsvr, err := k.privsvrKey(s.server)
	if err != nil {
		return err
	}
	key, etype, _ := s.sealingKey()
	return pac.SignTicket(part, fresh, s.issuedFor(), ci,
		wire.EncryptionKey{
			KeyType: int32(etype), KeyValue: key,
		}, privsvr)
}

// copyPACBuffers carries the presented PAC's payload buffers into a
// new one: the client info, and the delegation info if it had any
// (copy_pac_buffer, kdc_authdata.c:440-453).
//
// The signatures are deliberately not copied -- they are recomputed
// over the new ticket, which is the whole point of re-signing -- and
// the ticket checksum is not either, because SignTicket makes a fresh
// one over the ticket being issued.
func copyPACBuffers(
	subject *pac.PAC,
	rules copyRules,
) (*pac.PAC, error) {
	out := pac.New()
	for _, typ := range subject.Types() {
		if !copiedPACType(typ) || !rules.allows(typ) {
			continue
		}
		content, err := subject.Get(typ)
		if err != nil {
			return nil, err
		}
		if err := out.Add(typ, content); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// copiedPACType says whether a buffer travels from the presented PAC
// into the re-issued one.
//
// Everything that is not a signature does, which is the honest
// reading of upstream: it copies CLIENT_INFO and DELEGATION_INFO by
// name because those are the two a stock KDC can have, and the
// payload buffers a Windows KDC adds reach a re-issued ticket through
// the KDB module's issue_pac rather than through this path. Copying
// them all keeps a PAC that arrived with LOGON_INFO in it intact
// instead of silently emptying it.
func copiedPACType(typ uint32) bool {
	switch typ {
	case pac.TypeServerChecksum, pac.TypePrivsvrChecksum,
		pac.TypeTicketChecksum, pac.TypeFullChecksum:
		return false
	}
	return true
}

// errPACUnverified is what a retry that ran out of key versions
// reports, which is upstream's KRB5KRB_AP_ERR_MODIFIED.
var errPACUnverified = errors.New(
	"no krbtgt key version verifies the PAC")

// s4uPACClient is the CLIENT_INFO the new PAC should be built with,
// or nil to copy the presented PAC's across (handle_pac's three-way
// branch, kdc_authdata.c:531-553).
//
// **An S4U2Self request must not copy it**, and that is the whole
// reason this function exists: the presented ticket is the
// *impersonator's* TGT, so its PAC names the impersonator, and
// carrying that into a ticket whose client is somebody else would
// produce a PAC that disagrees with the ticket around it. A service
// reading the PAC would see the wrong user.
//
// The realm appears only when this realm is answering an S4U request
// with a **referral** (:533-537): the ticket then crosses a realm
// boundary, so the name in it has to say which realm the subject
// belongs to.
func s4uPACClient(
	s *tgsState,
	part *wire.EncTicketPart,
) *pac.ClientInfo {
	// An S4U2Proxy ticket's PAC names the ticket's own client,
	// which is the user from the evidence ticket -- so the
	// evidence PAC's CLIENT_INFO already says the right thing and
	// could be copied; upstream rebuilds it anyway, because the
	// *authtime* is the new ticket's (:538-543).
	if s.isProxy() {
		ci := pacClientInfo(
			clientInfoName(part.CName, ""), part.AuthTime)
		return &ci
	}
	if s.s4u == nil {
		return nil
	}
	if s.referral {
		ci := pacClientInfo(clientInfoName(
			*s.s4u.UserID.UserName,
			s.s4u.UserID.UserRealm), part.AuthTime)
		return &ci
	}
	ci := pacClientInfo(
		clientInfoName(part.CName, ""), part.AuthTime)
	return &ci
}

// checkNormalPAC is check_normal_tgs_pac (tgs_policy.c:717-740): on
// an ordinary TGS request, if the presented ticket carries a PAC then
// that PAC has to name the ticket's own client.
//
// **A PAC is not required** (:721-723), which is what keeps this KDC
// able to answer for tickets it issued before it issued any and for
// realms that issue none. What is refused is a PAC that names
// somebody *else*, because a ticket whose PAC and whose cname
// disagree is one a service would read two different answers out of.
//
// Upstream has a second arm here for an intermediate RBCD request,
// where the header PAC legitimately names the impersonated client and
// is checked through verify_deleg_pac instead (:729-733). That needs
// KRB5_PAC_DELEGATION_INFO decoded, which is NDR and belongs with
// cross-realm S4U2Proxy; until then an RBCD request cannot arrive,
// because cname-in-addl-tkt is refused outright.
func (k *KDC) checkNormalPAC(s *tgsState) (int32, string) {
	if s.headerPAC == nil {
		return 0, ""
	}
	want := pacClientInfo(
		clientInfoName(s.header.CName, ""), s.header.AuthTime)
	if s.headerPAC.VerifyClientInfo(want) != nil {
		return wire.ErrCodeBadOption, "HEADER_PAC"
	}
	return 0, ""
}

// addDelegationInfo records the delegation chain in the new PAC
// (update_delegation_info, kdc_authdata.c:382-439).
//
// It runs on a **local** constrained-delegation request only
// (handle_pac's gate, :519-523): a cross-realm one carries the chain
// forward rather than extending it, and an ordinary request has no
// chain. So this is the first hop, and what it writes is the target
// being reached now plus the service that asked -- the second
// ticket's *server*, which is the impersonator.
//
// The asymmetry in the two names is upstream's and is visible in the
// captured buffers internal/ndr is anchored against: the target
// carries no realm and the transited service does.
func (k *KDC) addDelegationInfo(
	s *tgsState,
	fresh, subject *pac.PAC,
) error {
	if !k.extendsDelegation(s) {
		return nil
	}
	di := ndr.DelegationInfo{
		ProxyTarget: clientInfoName(*s.req.Body.SName, ""),
	}
	if old, err := subject.Get(
		pac.TypeDelegationInfo); err == nil {
		was, err := ndr.Unmarshal(old)
		if err != nil {
			return err
		}
		di.TransitedServices = was.TransitedServices
	}
	di.TransitedServices = append(di.TransitedServices,
		clientInfoName(s.stktSrv, s.headerRealm))
	der, err := ndr.Marshal(di)
	if err != nil {
		return err
	}
	return fresh.Add(pac.TypeDelegationInfo, der)
}

// copyRules says which of the two buffers a re-signing rebuilds are
// left out of the copy.
//
// Both are named rather than inferred because the reason differs:
// CLIENT_INFO is rebuilt when the new ticket names a different
// client, and the delegation info when this hop extends the chain.
type copyRules struct {
	clientInfo bool
	delegation bool
}

func (r copyRules) allows(typ uint32) bool {
	switch typ {
	case pac.TypeClientInfo:
		return r.clientInfo
	case pac.TypeDelegationInfo:
		return r.delegation
	}
	return true
}

// extendsDelegation reports a request that adds a hop to the
// delegation chain, which is a **local** constrained-delegation
// request (handle_pac's gate, kdc_authdata.c:519-523).
//
// A cross-realm one carries the chain forward instead, and an
// ordinary request has no chain.
func (k *KDC) extendsDelegation(s *tgsState) bool {
	return s.isProxy() && s.headerRealm == k.Realm
}

// subjectPAC is the PAC the new one is built from.
//
// **For S4U2Proxy that is the evidence ticket's and not the header
// ticket's.** The header ticket is the impersonator's own; the
// evidence ticket's PAC is the one describing the user being acted
// for, and upstream passes it down as subject_pac for exactly that
// reason (do_tgs_req.c:972-989).
func (k *KDC) subjectPAC(s *tgsState) *pac.PAC {
	if s.isProxy() && s.stktPAC != nil {
		return s.stktPAC
	}
	return s.headerPAC
}
