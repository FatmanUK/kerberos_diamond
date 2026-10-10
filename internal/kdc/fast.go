package kdc

import (
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// FAST, RFC 6113, the server half of kdc/fast_util.c.
//
// FAST puts the real request inside a tunnel encrypted under an
// *armor key* that neither party chose alone, so that a
// pre-authentication exchange cannot be taken away and attacked
// offline. The KDC's work is three things: unwrap the request before
// the ordinary path sees it, wrap the reply after that path has
// produced it, and -- between those two -- replace the reply key with
// one strengthened by a key of its own choosing.
//
// The state here is upstream's struct kdc_request_state
// (kdc/reqstate.h:40-48), and it hangs off the per-request state for
// the same reason: the strengthened reply key is chosen between the
// reply being assembled and its enc-part being sealed, so nothing
// wrapped around the outside could reach the place it is needed.
//
// A nil *fastState means this was not a FAST request, and that is the
// first test every hook makes -- the shape of upstream's `if
// (!state->armor_key) return 0;` at fast_util.c:291 and :382.
type fastState struct {
	// armor is the key the tunnel is encrypted under, and p its
	// profile. Both halves are kept because every use needs the
	// profile and the enctype is not recoverable from the bytes.
	armor []byte
	p     *crypto.EncProfile

	// options are the client's fast-options, kept only so that a
	// critical bit this KDC does not implement can be refused.
	options wire.Flags

	// strengthen is the key the KDC contributes to the reply key.
	// It is chosen when the reply is assembled, not when the
	// request is read.
	strengthen []byte

	// innerBody is the inner KDC-REQ-BODY's encoded octets, which
	// is what a pre-authentication mechanism hashes -- *not* the
	// outer body in the request's raw message. See
	// wire.KrbFastReq.BodyDER.
	innerBody []byte
}

// findFastTGS unwraps a FAST-armored TGS request, if this is one.
//
// It must run after readAPReq and before tgsServer: the armor key
// comes from the request's own AP-REQ, and the inner body is what
// names the server. That is upstream's order too --
// kdc_process_tgs_req at do_tgs_req.c:617 precedes kdc_find_fast at
// :634, which precedes search_sprinc at :673.
//
// A request with no PA-FX-FAST is not an error and not a FAST
// request; it returns with s.fast still nil.
func (k *KDC) findFastTGS(s *tgsState) (int32, string) {
	pa := findPAData(s.req.PAData, wire.PAFXFast)
	if pa == nil {
		return 0, ""
	}
	ar, err := wire.UnmarshalPAFXFastRequest(pa.Value)
	if err != nil {
		return wire.ErrCodeModified, "DECODE FAST REQUEST"
	}
	// An AP-REQ armor field is refused outright on this path.
	// Upstream says so in as many words -- "Ap-request armor not
	// permitted with TGS" (fast_util.c:158-164) -- because a TGS
	// request already carries an AP-REQ of its own, and taking
	// the armor from a second one would let a client armor with a
	// ticket it had not presented.
	if ar.Armor.Type != 0 {
		return wire.ErrCodePreauthFailed,
			"AP-REQUEST ARMOR WITH TGS"
	}
	f, code, status := k.tgsArmorKey(s)
	if code != 0 {
		return code, status
	}
	return k.openFast(s, f, ar)
}

// tgsArmorKey derives the armor key from the request's own AP-REQ
// (fast_util.c:175-180).
//
// The two inputs are the authenticator's subkey and the presented
// ticket's session key, and the subkey is what makes the key fresh:
// the session key alone is as old as the ticket, and anyone who
// recorded the exchange that issued it would know it.
func (k *KDC) tgsArmorKey(
	s *tgsState,
) (*fastState, int32, string) {
	if s.auth.SubKey == nil {
		// Upstream's wording, and its reasoning: there is no
		// other source of an armor key on this path.
		return nil, wire.ErrCodePreauthFailed,
			"NO ARMOR KEY BUT FAST ARMORED REQUEST"
	}
	sub := s.auth.SubKey
	sp, err := crypto.Profile(crypto.EncType(sub.KeyType))
	if err != nil {
		return nil, wire.ErrCodeETypeNoSupp, "SUBKEY ENCTYPE"
	}
	tp, err := crypto.Profile(
		crypto.EncType(s.header.Key.KeyType))
	if err != nil {
		return nil, wire.ErrCodeETypeNoSupp, "SESSION ENCTYPE"
	}
	armor, err := sp.CF2(sub.KeyValue, "subkeyarmor",
		tp, s.header.Key.KeyValue, "ticketarmor")
	if err != nil {
		return nil, wire.ErrCodeGeneric, "ARMOR KEY"
	}
	return &fastState{armor: armor, p: sp}, 0, ""
}

// openFast decrypts the TGS tunnel and substitutes the inner request
// for the outer one.
func (k *KDC) openFast(
	s *tgsState,
	f *fastState,
	ar wire.KrbFastArmoredReq,
) (int32, string) {
	// The checksummed data is the PA-TGS-REQ value, not the
	// req-body: upstream's own comment names both cases --
	// "either the pa-tgs-req or the kdc-req-body"
	// (fast_util.c:120-124) -- and this path passes the AP-REQ
	// bytes (do_tgs_req.c:633-634).
	ap := findPAData(s.req.PAData, wire.PATGSReq)
	if ap == nil {
		return wire.ErrCodePADataTypeNoSupp, "NO AP-REQ"
	}
	fr, code, status := f.openInner(ar, ap.Value)
	if code != 0 {
		return code, status
	}
	s.fast = f
	// The inner request replaces the outer one entirely, padata
	// included (fast_util.c:229-234). That is the whole point:
	// the outer padata holds only PA-TGS-REQ and PA-FX-FAST, so a
	// KDC reading it would find no pre-authentication at all.
	s.req.Body = fr.Body
	s.req.PAData = fr.PAData
	return 0, ""
}

// openInner is the part both exchanges share: decrypt the tunnel,
// decode what is inside, check it is bound to the outer request, and
// refuse a critical option this KDC does not implement
// (fast_util.c:186-228).
//
// checksummed is what the request checksum covers, and it is the one
// thing the two paths disagree about.
func (f *fastState) openInner(
	ar wire.KrbFastArmoredReq,
	checksummed []byte,
) (wire.KrbFastReq, int32, string) {
	var zero wire.KrbFastReq
	plain, err := f.p.Decrypt(f.armor, ar.EncPart.Cipher,
		crypto.UsageFASTEnc)
	if err != nil {
		return zero, wire.ErrCodeBadIntegrity,
			"DECRYPT FAST REQ"
	}
	fr, err := wire.UnmarshalKrbFastReq(plain)
	if err != nil {
		return zero, wire.ErrCodeModified,
			"DECODE FAST REQUEST"
	}
	code, status := f.checkCksum(ar.ReqChecksum, checksummed)
	if code != 0 {
		return zero, code, status
	}
	if fr.Options&wire.FastCriticalOptions != 0 {
		return zero, wire.ErrCodeUnknownCriticalOpt,
			"UNSUPPORTED CRITICAL FAST OPTION"
	}
	f.options = fr.Options
	return fr, 0, ""
}

// checkCksum verifies the checksum binding the tunnel to the outer
// request (fast_util.c:207-224).
//
// Two checks in upstream's order, which matters because they answer
// differently: the checksum is verified first, and only then is the
// *type* required to be keyed. An unkeyed checksum is a policy
// refusal rather than a verification failure -- it would verify
// perfectly and prove nothing, since anyone could compute it.
//
// The type is narrowed further than upstream, which accepts any keyed
// type that verifies. This accepts only the armor enctype's mandatory
// one, as checkBodyCksum already does for the authenticator. No MIT
// client notices: krb5_c_make_checksum is called with 0 for the type
// (lib/krb5/krb/fast.c), which means "the key's mandatory one".
func (f *fastState) checkCksum(
	sum wire.Checksum,
	data []byte,
) (int32, string) {
	if int32(f.p.RequiredCksum) != sum.Type {
		return wire.ErrCodeSumTypeNoSupp,
			"FAST CHECKSUM TYPE"
	}
	err := f.p.VerifyChecksum(f.armor, data, sum.Checksum,
		crypto.UsageFASTReqCksum)
	if err != nil {
		return wire.ErrCodeModified, "FAST REQ CHECKSUM"
	}
	return 0, ""
}

// fastReply wraps a finished reply in its tunnel and strengthens the
// reply key (kdc_fast_response_handle_padata, fast_util.c:277-350,
// and kdc_fast_handle_reply_key, :427-441).
//
// tktDER is the encoded, already-encrypted ticket, which the finished
// field checksums. Everything the reply was going to say in cleartext
// padata moves inside the tunnel, and the outer reply is left with a
// single PA-FX-FAST element.
//
// The order is forced: the finished field checksums the ticket, so
// the ticket must exist; and the enc-part is sealed with the
// strengthened key, so this must run before it.
func (k *KDC) fastReply(
	f *fastState,
	rep *wire.TGSRep,
	tktDER []byte,
	nonce int32,
	replyKey []byte,
	replyEType crypto.EncType,
) ([]byte, error) {
	fin, err := f.finished(tktDER, rep.CRealm, rep.CName,
		k.now())
	if err != nil {
		return nil, err
	}
	// The strengthen key is minted at the *reply* key's enctype,
	// because CF2 takes its output enctype from its first
	// argument and that argument is this key (do_as_req.c:304).
	rp, err := crypto.Profile(replyEType)
	if err != nil {
		return nil, err
	}
	f.strengthen, err = randomKey(replyEType)
	if err != nil {
		return nil, err
	}
	pa, err := f.seal(wire.KrbFastResponse{
		PAData:        rep.PAData,
		StrengthenKey: f.strengthenKey(replyEType),
		Finished:      fin,
		Nonce:         nonce,
	})
	if err != nil {
		return nil, err
	}
	rep.PAData = []wire.PAData{pa}
	return rp.CF2(f.strengthen, "strengthenkey",
		rp, replyKey, "replykey")
}

// strengthenKey is the key as it goes on the wire.
func (f *fastState) strengthenKey(
	e crypto.EncType,
) wire.EncryptionKey {
	return wire.EncryptionKey{
		KeyType: int32(e), KeyValue: f.strengthen,
	}
}

// seal encrypts a KrbFastResponse and wraps it as the one padata item
// an armored reply carries (encrypt_fast_reply, fast_util.c:92-117).
func (f *fastState) seal(
	r wire.KrbFastResponse,
) (wire.PAData, error) {
	plain, err := wire.MarshalKrbFastResponse(r)
	if err != nil {
		return wire.PAData{}, err
	}
	ct, err := f.p.Encrypt(f.armor, plain, crypto.UsageFASTRep)
	if err != nil {
		return wire.PAData{}, err
	}
	val, err := wire.MarshalPAFXFastReply(wire.EncryptedData{
		EType:  int32(f.p.EncType),
		Cipher: ct,
	})
	if err != nil {
		return wire.PAData{}, err
	}
	return wire.PAData{Type: wire.PAFXFast, Value: val}, nil
}

// finished is the KDC's proof that this reply belongs to this
// exchange (fast_util.c:309-327).
//
// The checksum is over the *encoded, encrypted* ticket, so it covers
// ciphertext -- which is the point: it binds the ticket the client is
// about to cache to the tunnel it arrived through, without the KDC
// needing to show the client anything about the ticket's contents.
func (f *fastState) finished(
	tktDER []byte,
	crealm string,
	cname wire.PrincipalName,
	now time.Time,
) (wire.KrbFastFinished, error) {
	sum, err := f.p.Checksum(f.armor, tktDER,
		crypto.UsageFASTFinished)
	if err != nil {
		return wire.KrbFastFinished{}, err
	}
	return wire.KrbFastFinished{
		Timestamp: now,
		Usec:      int32(now.Nanosecond() / 1000),
		CRealm:    crealm,
		CName:     cname,
		TicketChecksum: wire.Checksum{
			Type:     int32(f.p.RequiredCksum),
			Checksum: sum,
		},
	}, nil
}

// fastError wraps a refusal in its tunnel (kdc_fast_handle_error,
// fast_util.c:364-424).
//
// For an unarmored request this is krbError unchanged. For an armored
// one the shape is doubled: the outer KRB-ERROR is what reaches the
// client in the open, and its e-data carries a PA-DATA sequence
// holding one PA-FX-FAST, inside which a KrbFastResponse carries the
// *real* error as PA-FX-ERROR. A client refuses an armored container
// that does not hold one -- "Expecting FX_ERROR pa-data inside FAST
// container" (lib/krb5/krb/fast.c:459-466).
//
// Neither a strengthen key nor a finished field goes in it
// (:402-407): there is no ticket to checksum and no reply key to
// strengthen.
//
// If the wrapping itself fails there is nothing useful to say, so the
// unwrapped refusal goes out instead -- a client that cannot read it
// will report a protocol error, which is true.
func (k *KDC) fastError(
	s *tgsState,
	code int32,
	status string,
	cname *wire.PrincipalName,
) *wire.KRBError {
	e := k.krbError(code, status, cname)
	return k.wrapErr(s.fast, e, s.req.Body.Nonce)
}

// wrapErr is the part both exchanges share.
func (k *KDC) wrapErr(
	f *fastState,
	e *wire.KRBError,
	nonce int32,
) *wire.KRBError {
	if f == nil {
		return e
	}
	data, err := f.wrapError(e, nonce)
	if err != nil {
		return e
	}
	e.EData = data
	return e
}

// wrapError builds the e-data of an armored refusal.
//
// The refusal's existing e-data is a PA-DATA sequence -- the hint
// list -- and it goes *inside* the tunnel with PA-FX-ERROR appended,
// which is what upstream does: kdc_fast_handle_error is handed the
// caller's padata list and adds to it (fast_util.c:387-401).
//
// Dropping it is a silent dead end, and was one here until a stock
// kinit -T said so. A client sets its retry flag only when the inner
// padata holds more than PA-FX-ERROR *and* a cookie is present
// (lib/krb5/krb/fast.c:481-492), so an armored PREAUTH_REQUIRED
// carrying nothing but the error makes kinit report "Additional
// pre-authentication required" and stop -- with the tunnel itself
// having worked perfectly, which is what made it hard to see.
func (f *fastState) wrapError(
	e *wire.KRBError,
	nonce int32,
) ([]byte, error) {
	hints, err := innerHints(e.EData)
	if err != nil {
		return nil, err
	}
	// The inner error's own e-data is blanked
	// (fast_util.c:384-386), which is what stops the container
	// nesting inside itself.
	inner := *e
	inner.EData = nil
	der, err := wire.MarshalKRBError(inner)
	if err != nil {
		return nil, err
	}
	pa, err := f.seal(wire.KrbFastResponse{
		PAData: append(hints, wire.PAData{
			Type: wire.PAFXError, Value: der,
		}),
		Nonce: nonce,
	})
	if err != nil {
		return nil, err
	}
	return wire.MarshalPADataSeq([]wire.PAData{pa})
}

// innerHints decodes a refusal's e-data into the padata list that
// goes inside the tunnel.
//
// Empty e-data is the common case and not an error: most refusals
// carry no hints, and every refusal on the TGS path carries none --
// upstream adds a cookie only on the AS error path
// (do_as_req.c:786-795, against prepare_error_tgs at
// do_tgs_req.c:190-240, which adds nothing).
func innerHints(edata []byte) ([]wire.PAData, error) {
	if len(edata) == 0 {
		return nil, nil
	}
	return wire.UnmarshalPADataSeq(edata)
}
