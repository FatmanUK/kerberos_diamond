package kdc

import (
	"context"
	"errors"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/pac"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// readS4USelf reads an S4U2Self request's padata and verifies its
// checksum (kdc_process_s4u2self_req, kdc_util.c:1556-1620).
//
// S4U2Self is a service asking for a ticket **to itself** on behalf
// of a user it never spoke to: the padata names the user, and the
// reply's ticket has that user as its client. So the only thing
// standing between a service and a ticket naming anybody is the
// checksum, which is keyed with the TGT's session key, and the policy
// in checkS4USelf.
//
// Two padata types do the same job and the newer one wins when both
// are present (:1570-1586). The legacy PA-FOR-USER is normalised into
// the newer structure immediately, as upstream does
// (kdc_process_for_user, :1306-1342), so everything downstream sees
// one shape -- but whether it arrived as the legacy form is
// remembered, because a PA-FOR-USER request gets **no reply padata at
// all**.
func (k *KDC) readS4USelf(s *tgsState) (int32, string) {
	if d := findPAData(s.req.PAData,
		wire.PATypeS4UX509User); d != nil {
		if code, status := k.readX509User(s, d); code != 0 {
			return code, status
		}
	} else if d := findPAData(s.req.PAData,
		wire.PATypeForUser); d != nil {
		if code, status := k.readForUser(s, d); code != 0 {
			return code, status
		}
	} else {
		return 0, ""
	}
	// For consistency with Active Directory, a server cannot turn
	// authorization data off for an S4U2Self request: it probably
	// needs the PAC for a later S4U2Proxy, even if it wants no
	// authdata in tickets clients bring it
	// (do_tgs_req.c:706-716).
	//
	// Upstream clears the flag on the loaded entry rather than
	// carrying a waiver down, and so does this -- the entry is
	// this request's copy and nothing writes it back.
	if noAuthData(s.server) {
		s.s4uNoAuthDataWaived = true
		s.server.Attributes &^= store.AttrNoAuthDataRequired
	}
	return k.lookupS4USubject(s)
}

// readForUser handles the legacy PA-FOR-USER (kdc_process_for_user,
// kdc_util.c:1306-1342).
//
// Its checksum is keyed with the header ticket's **session key**, not
// the authenticator's subkey -- the newer form uses the subkey when
// there is one and this form never does (:1327 against :1428-1431).
func (k *KDC) readForUser(
	s *tgsState,
	d *wire.PAData,
) (int32, string) {
	fu, err := wire.UnmarshalPAForUser(d.Value)
	if err != nil {
		return wire.ErrCodeModified, "DECODE_PA_FOR_USER"
	}
	p, err := crypto.ProfileForCksum(
		crypto.CksumType(fu.Cksum.Type))
	if err != nil {
		return wire.ErrCodeInappCksum,
			"INVALID_S4U2SELF_CHECKSUM"
	}
	if err := p.VerifyChecksum(s.header.Key.KeyValue,
		wire.S4UForUserChecksumData(fu), fu.Cksum.Checksum,
		pac.UsageAppDataCksum); err != nil {
		return wire.ErrCodeModified,
			"INVALID_S4U2SELF_CHECKSUM"
	}
	s.s4uLegacy = true
	s.s4u = &wire.PAS4UX509User{UserID: wire.S4UUserID{
		UserName:  &fu.UserName,
		UserRealm: fu.UserRealm,
	}}
	return 0, ""
}

// readX509User handles PA-S4U-X509-USER (kdc_process_s4u_x509_user,
// kdc_util.c:1405-1450).
func (k *KDC) readX509User(
	s *tgsState,
	d *wire.PAData,
) (int32, string) {
	req, err := wire.UnmarshalPAS4UX509User(d.Value)
	if err != nil {
		return wire.ErrCodeModified,
			"DECODE_PA_S4U_X509_USER"
	}
	if req.UserID.Nonce != s.req.Body.Nonce {
		return wire.ErrCodeModified,
			"INVALID_S4U2SELF_CHECKSUM"
	}
	if err := k.verifyX509UserCksum(s, d.Value,
		req); err != nil {
		return wire.ErrCodeModified,
			"INVALID_S4U2SELF_CHECKSUM"
	}
	// A request naming neither a principal nor a certificate
	// names nobody (:1442-1448).
	named := req.UserID.UserName != nil &&
		len(req.UserID.UserName.Components) > 0
	if !named && len(req.UserID.SubjectCert) == 0 {
		return wire.ErrCodeCPrincipalUnknown,
			"INVALID_S4U2SELF_REQUEST"
	}
	s.s4u = &req
	return 0, ""
}

// verifyX509UserCksum checks the checksum over the user-id field, as
// received and then as re-encoded (verify_s4u_x509_user_checksum,
// kdc_util.c:1345-1401).
//
// The key is the authenticator's **subkey when there is one** and the
// ticket's session key otherwise (:1428-1431), which is the same
// choice the reply key makes and has to agree with it.
//
// The re-encode retry is the same tolerance the TGS body checksum
// has: a peer whose encoder differs from this one's checksummed its
// own octets, so the received bytes are tried first and a re-encoding
// only if those fail.
func (k *KDC) verifyX509UserCksum(
	s *tgsState,
	der []byte,
	req wire.PAS4UX509User,
) error {
	p, err := crypto.ProfileForCksum(
		crypto.CksumType(req.Cksum.Type))
	if err != nil {
		return err
	}
	key := s.s4uCksumKey()
	raw, err := wire.S4UUserIDBytes(der)
	if err == nil {
		if p.VerifyChecksum(key, raw, req.Cksum.Checksum,
			crypto.UsageS4UX509UserRequest) == nil {
			return nil
		}
	}
	again, err := wire.MarshalS4UUserID(req.UserID)
	if err != nil {
		return err
	}
	return p.VerifyChecksum(key, again, req.Cksum.Checksum,
		crypto.UsageS4UX509UserRequest)
}

// s4uCksumKey is the key a PA-S4U-X509-USER checksum is made with:
// the authenticator's subkey when it sent one, the header ticket's
// session key otherwise.
func (s *tgsState) s4uCksumKey() []byte {
	if s.auth.SubKey != nil {
		return s.auth.SubKey.KeyValue
	}
	return s.header.Key.KeyValue
}

// lookupS4USubject loads the impersonated principal when it belongs
// to this realm, and leaves it nil when it does not
// (kdc_util.c:1589-1619).
//
// **Password expiry and REQUIRES_PWCHANGE are cleared on the entry**,
// which upstream does "as Windows does, since S4U2Self is not
// password authentication" (:1611-1615). A user whose password has
// expired can still be impersonated, because nothing about this
// exchange involves their password.
func (k *KDC) lookupS4USubject(s *tgsState) (int32, string) {
	id := s.s4u.UserID
	if id.UserRealm != k.Realm {
		return 0, ""
	}
	if len(id.SubjectCert) > 0 && id.UserName == nil {
		// A certificate-only request needs the database to
		// say which principal a certificate belongs to, which
		// is krb5_db_get_s4u_x509_principal -- a KDB method
		// with no implementation outside upstream's test
		// module. Refused rather than guessed.
		return wire.ErrCodeCPrincipalUnknown,
			"UNKNOWN_S4U2SELF_PRINCIPAL"
	}
	name := store.UnparseName(k.Realm, id.UserName.Components)
	p, err := k.Store.Lookup(context.Background(), name)
	if errors.Is(err, store.ErrNotFound) {
		return wire.ErrCodeCPrincipalUnknown,
			"UNKNOWN_S4U2SELF_PRINCIPAL"
	}
	if err != nil {
		return wire.ErrCodeGeneric,
			"LOOKING_UP_S4U2SELF_PRINCIPAL"
	}
	p.PWExpiration = time.Time{}
	p.Attributes &^= store.AttrRequiresPWChange
	s.s4uClient = p
	return 0, ""
}

// s4uSelfRep is the PA-S4U-X509-USER a successful S4U2Self reply
// carries (kdc_make_s4u2self_rep, kdc_util.c:1452-1530).
//
// **It goes in the reply's cleartext padata, not the encrypted
// padata** (:1489-1491 adds it to reply->padata). That reads wrong
// for something carrying a checksum and is not: the checksum is keyed
// with the TGT's session key or the authenticator's subkey, so it is
// already proof the reply came from a KDC that holds one, and the
// client needs the nonce and the subject name echoed back whether or
// not it can decrypt yet.
//
// **A legacy PA-FOR-USER request gets none at all** (do_tgs_req.c:
// 1064-1067 tests for the newer padata specifically), which is why
// the arriving shape is remembered.
//
// Three things in it are masked or chosen rather than copied:
//
//   - the options are masked to USE-REPLY-KEY-USAGE alone
//     (:1470-1472), the same way PA-PAC-OPTIONS is masked, so the
//     reply says what the KDC honoured;
//   - that one bit decides whether the reply's checksum is at usage
//     **27** instead of 26 (:1479-1482);
//   - the checksum *type* is the client's own, copied from the
//     request (:1484), not the enctype's mandatory one -- so a client
//     that asked for a particular checksum type gets its answer in
//     that type.
func (k *KDC) s4uSelfRep(s *tgsState) (*wire.PAData, error) {
	if s.s4u == nil || s.s4uLegacy {
		return nil, nil
	}
	rep := wire.PAS4UX509User{UserID: wire.S4UUserID{
		Nonce:     s.s4u.UserID.Nonce,
		UserName:  s.s4u.UserID.UserName,
		UserRealm: s.s4u.UserID.UserRealm,
		Options: s.s4u.UserID.Options &
			wire.S4UOptUseReplyKeyUsage,
	}}
	der, err := wire.MarshalS4UUserID(rep.UserID)
	if err != nil {
		return nil, err
	}
	p, err := crypto.ProfileForCksum(
		crypto.CksumType(s.s4u.Cksum.Type))
	if err != nil {
		return nil, err
	}
	sum, err := p.Checksum(s.s4uCksumKey(), der,
		s4uReplyUsage(rep.UserID.Options))
	if err != nil {
		return nil, err
	}
	rep.Cksum = wire.Checksum{
		Type: s.s4u.Cksum.Type, Checksum: sum,
	}
	return s4uRepPAData(rep)
}

// s4uReplyUsage is 27 when the client asked for it and 26 otherwise.
func s4uReplyUsage(opts wire.Flags) crypto.Usage {
	if opts&wire.S4UOptUseReplyKeyUsage != 0 {
		return crypto.UsageS4UX509UserReply
	}
	return crypto.UsageS4UX509UserRequest
}

// s4uRepPAData encodes the reply structure as a padata element.
func s4uRepPAData(
	rep wire.PAS4UX509User,
) (*wire.PAData, error) {
	der, err := wire.MarshalPAS4UX509User(rep)
	if err != nil {
		return nil, err
	}
	return &wire.PAData{
		Type: wire.PATypeS4UX509User, Value: der,
	}, nil
}
