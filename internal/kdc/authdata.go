package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// ticketAuthData works out the authorization data a TGS-issued ticket
// carries (handle_authdata, kdc_authdata.c:520-566).
//
// **This KDC carried none at all before.** Neither reply path so much
// as named the field, so the [10] element was always omitted and a
// presented ticket's authorization data was silently dropped on every
// renewal, forward and service-ticket request -- which is a
// correctness bug rather than a missing feature, because a client
// that put something in a ticket expects it to still be there.
//
// And the AD-MANDATORY-FOR-KDC element is worse than dropped: it is
// an element whose entire meaning is "understand this or refuse the
// request", and a KDC that never looks at authorization data cannot
// do either. Upstream answers KDC_ERR_POLICY from both copy paths
// (:277-280 and :291-292) and t_authdata.py:30-32 asserts the exit
// code and the message.
//
// The order is upstream's and visible in the issued ticket: the
// request's own authorization data comes first, then anything a
// module added, then the header ticket's. Nothing here adds anything,
// so it is the two copies.
//
// **Only a TGS request copies anything.** The AS exchange has no
// header ticket and upstream ignores an AS-REQ's
// enc-authorization-data entirely (:536 and :556 both gate on
// KRB5_TGS_REQ), so an AS-issued ticket carries no authorization data
// whatever the client sent.
func (k *KDC) ticketAuthData(
	s *tgsState,
) (wire.AuthorizationData, int32, string) {
	var out wire.AuthorizationData
	req, code, status := k.requestAuthData(s)
	if code != 0 {
		return nil, code, status
	}
	out = append(out, req...)
	tgt, code, status := tgtAuthData(s)
	if code != 0 {
		return nil, code, status
	}
	out = append(out, tgt...)
	return k.addTGSIndicators(s, out)
}

// addTGSIndicators carries verified authentication indicators across
// and checks them against the server's require_auth.
//
// The order is upstream's and both halves matter: the indicators are
// read out of the presented ticket, **checked** against what the
// server demands (check_indicators from do_tgs_req.c:896-903), and
// only then written into the new ticket. Checking after writing would
// issue the ticket and then refuse it.
func (k *KDC) addTGSIndicators(
	s *tgsState,
	ad wire.AuthorizationData,
) (wire.AuthorizationData, int32, string) {
	tgtKey, tgtEType, tgtKVNO, err := k.localTGT()
	if err != nil {
		return nil, wire.ErrCodeGeneric, "LOCAL TGT KEY"
	}
	ind := k.authIndicators(s.header, tgtKey, tgtEType,
		tgtKVNO)
	if code, status := checkIndicators(
		s.server, ind); code != 0 {
		return nil, code, status
	}
	part := s.encTicketPart()
	out, err := k.addIndicators(ad, ind, s.server, part,
		s.serverKey, s.serverEType)
	if err != nil {
		return nil, wire.ErrCodeGeneric, "ADD INDICATORS"
	}
	return out, 0, ""
}

// requestAuthData decrypts and filters the request's own
// enc-authorization-data (copy_request_authdata,
// kdc_authdata.c:234-284).
//
// **The decryption is tried the wrong way round first, on purpose.**
// RFC 4120 says the field is encrypted in the subkey at usage 5 when
// there is a subkey and in the session key at usage 4 when there is
// not -- but krb5 before 1.7 always used the session key and usage 4,
// so upstream tries that first and only then tries the correct way
// (:252-266, with a comment calling it conservatism). A
// reimplementation that tried the right way first would still
// interoperate; one that tried *only* the right way would refuse
// requests a stock KDC accepts.
func (k *KDC) requestAuthData(
	s *tgsState,
) (wire.AuthorizationData, int32, string) {
	ed, ok, err := wire.EncAuthDataOf(
		s.req.Body.EncAuthorizationData)
	if err != nil {
		return nil, wire.ErrCodeModified, "DECODE AUTHDATA"
	}
	if !ok {
		return nil, 0, ""
	}
	plain, code, status := k.openAuthData(s, ed)
	if code != 0 {
		return nil, code, status
	}
	ad, err := wire.UnmarshalAuthorizationData(plain)
	if err != nil {
		return nil, wire.ErrCodeModified, "DECODE AUTHDATA"
	}
	if ad.HasMandatoryForKDC() {
		return nil, wire.ErrCodePolicy,
			"AD-MANDATORY-FOR-KDC IN REQUEST"
	}
	return ad.Filtered(), 0, ""
}

// openAuthData tries the session key at usage 4 and then the
// authenticator's subkey at usage 5, in that order.
func (k *KDC) openAuthData(
	s *tgsState,
	ed wire.EncryptedData,
) ([]byte, int32, string) {
	p, err := crypto.Profile(crypto.EncType(ed.EType))
	if err != nil {
		return nil, wire.ErrCodeETypeNoSupp,
			"AUTHDATA ENCTYPE"
	}
	plain, err := p.Decrypt(s.header.Key.KeyValue, ed.Cipher,
		crypto.UsageTGSReqAuthDataSession)
	if err == nil {
		return plain, 0, ""
	}
	if s.auth.SubKey == nil {
		return nil, wire.ErrCodeBadIntegrity,
			"DECRYPT REQUEST AUTHDATA"
	}
	plain, err = p.Decrypt(s.auth.SubKey.KeyValue, ed.Cipher,
		crypto.UsageTGSReqAuthDataSubkey)
	if err != nil {
		return nil, wire.ErrCodeBadIntegrity,
			"DECRYPT REQUEST AUTHDATA"
	}
	return plain, 0, ""
}

// tgtAuthData carries the presented ticket's authorization data
// across (copy_tgt_authdata, kdc_authdata.c:286-296).
func tgtAuthData(
	s *tgsState,
) (wire.AuthorizationData, int32, string) {
	ad, err := wire.AuthDataOf(s.header.AuthorizationData)
	if err != nil {
		return nil, wire.ErrCodeModified,
			"DECODE TICKET AUTHDATA"
	}
	if len(ad) == 0 {
		return nil, 0, ""
	}
	if ad.HasMandatoryForKDC() {
		return nil, wire.ErrCodePolicy,
			"AD-MANDATORY-FOR-KDC IN TICKET"
	}
	return ad.Filtered(), 0, ""
}

// setAuthData works the authorization data out and encodes it onto
// the state, or refuses the request.
//
// Encoded here rather than at assembly time because the ticket's
// field is opaque DER and because the refusal has to happen before
// anything is built: AD-MANDATORY-FOR-KDC means "refuse the request",
// not "issue a ticket without it".
func (k *KDC) setAuthData(s *tgsState) (int32, string) {
	ad, code, status := k.ticketAuthData(s)
	if code != 0 {
		return code, status
	}
	field, err := wire.AuthDataField(ad)
	if err != nil {
		return wire.ErrCodeGeneric, "ENCODE AUTHDATA"
	}
	s.authData = field
	return 0, ""
}
