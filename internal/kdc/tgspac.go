package kdc

import (
	"errors"

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
	fresh, err := copyPACBuffers(s.headerPAC)
	if err != nil {
		return err
	}
	privsvr, err := k.privsvrKey(s.server)
	if err != nil {
		return err
	}
	key, etype, _ := s.sealingKey()
	return pac.SignTicket(part, fresh, s.issuedFor(), nil,
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
func copyPACBuffers(subject *pac.PAC) (*pac.PAC, error) {
	out := pac.New()
	for _, typ := range subject.Types() {
		if !copiedPACType(typ) {
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
