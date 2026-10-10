package kdc

import (
	"encoding/binary"
	"errors"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/spake"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// spakeCookieVersion is the version octet-pair in the state this KDC
// stores inside a FAST cookie (make_cookie, spake_kdc.c:62-86).
//
// The layout is upstream's and not negotiable, because a cookie is
// opaque to the client and has to round-trip through it: version,
// stage, group, then the private scalar and the transcript hash each
// as a four-octet length and that many octets. Upstream appends
// second-factor state after those, which neither it nor this
// implements.
const spakeCookieVersion = 1

// errNoSpakeState reports a response with no challenge behind it.
var errNoSpakeState = errors.New("kdc: no SPAKE state")

// spakePreauth handles an incoming PA-SPAKE value, which is the whole
// of the KDC's half of the exchange (spake_verify,
// spake_kdc.c:505-540).
//
// Two of the four message types are live. A support message gets a
// challenge and KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, which is the KDC
// asking for another round trip rather than refusing. A response
// completes the exchange. The other two are refused: an EncData
// message is a second-factor round, which upstream also refuses
// (verify_encdata, :481-498 is a comment and a refusal), and a
// challenge is a message the *KDC* sends.
func (k *KDC) spakePreauth(
	s *asState,
	value []byte,
) *wire.KRBError {
	m, err := spake.UnmarshalMessage(value)
	if err != nil {
		return k.spakeFailed(s, "SPAKE DECODE")
	}
	switch m.Type {
	case spake.MsgSupport:
		return k.spakeChallenge(s, m, value)
	case spake.MsgResponse:
		return k.spakeResponse(s, m)
	}
	return k.spakeFailed(s, "SPAKE MESSAGE TYPE")
}

// spakeFailed is the one refusal this mechanism gives.
//
// Everything that can go wrong is KDC_ERR_PREAUTH_FAILED, including a
// factor field that will not decrypt -- which is what a wrong
// password looks like from here, and upstream translates the
// integrity failure into exactly this code rather than reporting
// corruption (spake_kdc.c:428-431).
func (k *KDC) spakeFailed(
	s *asState,
	status string,
) *wire.KRBError {
	return k.krbError(wire.ErrCodePreauthFailed, status,
		s.nameOrNil())
}

// spakeChallenge picks a group, generates this side's element, and
// asks for another round trip (verify_support and send_challenge,
// spake_kdc.c:211-294 and :326-356).
//
// The transcript hash is seeded with the support message **as it
// arrived** and the challenge **as encoded**, which is why both are
// hashed here rather than re-derived later: the hash binds the
// exchange to the exact bytes, so re-encoding either would produce a
// hash the client disagrees with.
func (k *KDC) spakeChallenge(
	s *asState,
	m spake.Message,
	raw []byte,
) *wire.KRBError {
	group, ok := k.chooseGroup(m.Support.Groups)
	if !ok {
		return k.spakeFailed(s, "SPAKE NO COMMON GROUP")
	}
	w, err := spake.DeriveW(s.clientKey, s.clientEType,
		group)
	if err != nil {
		return k.spakeFailed(s, "SPAKE MULTIPLIER")
	}
	// The KDC masks with M, which is the half of the protocol
	// that is easy to get backwards -- see internal/spake.
	priv, pub, err := spake.Keygen(w, true)
	if err != nil {
		return k.spakeFailed(s, "SPAKE KEYGEN")
	}
	der, err := spake.MarshalMessage(spake.Message{
		Type: spake.MsgChallenge,
		Challenge: &spake.Challenge{
			Group:   group,
			PubKey:  pub,
			Factors: []spake.Factor{{Type: spake.SFNone}},
		},
	})
	if err != nil {
		return k.spakeFailed(s, "SPAKE ENCODE CHALLENGE")
	}
	thash := spake.UpdateThash(nil, raw, der)
	return k.spakeMore(s, group, priv, thash, der)
}

// chooseGroup takes the client's first offer this KDC supports, which
// is upstream's order: the *client's* preference wins
// (verify_support, spake_kdc.c:336-341).
func (k *KDC) chooseGroup(
	offered []int32,
) (int32, bool) {
	for _, g := range offered {
		for _, mine := range k.SPAKEGroups {
			if g == mine {
				return g, true
			}
		}
	}
	return 0, false
}

// spakeMore returns the challenge and the cookie that remembers it.
//
// KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, which is not a failure: it is
// the one error code that means "keep going", and upstream turns the
// successful construction of a challenge into it on purpose
// (send_challenge's vrespond branch, spake_kdc.c:290-292).
func (k *KDC) spakeMore(
	s *asState,
	group int32,
	priv *spake.Private,
	thash, challenge []byte,
) *wire.KRBError {
	cookie, err := k.makeCookie(s.cname, []wire.PAData{{
		Type:  spake.PAType,
		Value: spakeState(group, priv, thash),
	}})
	if err != nil {
		return k.spakeFailed(s, "SPAKE COOKIE")
	}
	e := k.krbError(wire.ErrCodeMorePreauthData,
		"MORE_PREAUTH_DATA_REQUIRED", s.nameOrNil())
	edata, err := wire.MarshalPADataSeq([]wire.PAData{
		{Type: spake.PAType, Value: challenge},
		cookie,
	})
	if err != nil {
		return k.spakeFailed(s, "SPAKE EDATA")
	}
	e.EData = edata
	return e
}

// spakeState marshals what the cookie carries, in upstream's layout
// (make_cookie, spake_kdc.c:62-86).
func spakeState(
	group int32,
	priv *spake.Private,
	thash []byte,
) []byte {
	out := binary.BigEndian.AppendUint16(nil,
		spakeCookieVersion)
	// Stage zero: the only stage there is without second factors,
	// and the value a response is required to have been issued at
	// (:394-398).
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(group))
	out = appendField(out, priv.Bytes())
	return appendField(out, thash)
}

// appendField is upstream's marshal_data: a four-octet big-endian
// length and then the octets.
func appendField(out, b []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
	return append(out, b...)
}

// spakeResponse completes the exchange (verify_response,
// spake_kdc.c:358-475).
//
// The order is upstream's and every step of it is load-bearing. The
// cookie is read first, because without the private scalar and the
// transcript hash from the challenge there is nothing to compute
// against. The transcript hash is then extended with the client's
// element -- and only that, with no second argument, which is an
// empty string rather than a skipped input. The shared element
// follows, then K'[1], then the factor field.
//
// **Decrypting the factor is the authentication.** It is sealed with
// K'[1], which depends on the shared element, which depends on the
// multiplier, which depends on the client's long-term key. A client
// that did not know the password derives a different K'[1] and the
// integrity check fails -- which is why upstream translates that
// failure into KDC_ERR_PREAUTH_FAILED and not into a report of
// corruption.
func (k *KDC) spakeResponse(
	s *asState,
	m spake.Message,
) *wire.KRBError {
	group, priv, thash, kerr := k.spakeStateOf(s)
	if kerr != nil {
		return kerr
	}
	w, err := spake.DeriveW(s.clientKey, s.clientEType, group)
	if err != nil {
		return k.spakeFailed(s, "SPAKE MULTIPLIER")
	}
	thash = spake.UpdateThash(thash, m.Response.PubKey, nil)
	// The KDC unmasks with the client's constant N, which is why
	// the flag is false here and true in the challenge.
	element, err := spake.Result(priv, w, m.Response.PubKey,
		false)
	if err != nil {
		return k.spakeFailed(s, "SPAKE ELEMENT")
	}
	if kerr := k.spakeFactor(s, m, group, w, element,
		thash); kerr != nil {
		return kerr
	}
	return k.spakeAccept(s, group, w, element, thash)
}

// spakeFactor decrypts and checks the response's factor field.
func (k *KDC) spakeFactor(
	s *asState,
	m spake.Message,
	group int32,
	w, element, thash []byte,
) *wire.KRBError {
	k1, err := spake.DeriveKey(s.clientKey, s.clientEType,
		group, w, element, thash, s.reqBody(), 1)
	if err != nil {
		return k.spakeFailed(s, "SPAKE K1")
	}
	p, err := crypto.Profile(s.clientEType)
	if err != nil {
		return k.spakeFailed(s, "SPAKE ENCTYPE")
	}
	plain, err := p.Decrypt(k1, m.Response.Factor.Cipher,
		spake.UsageSPAKE)
	if err != nil {
		return k.spakeFailed(s, "SPAKE FACTOR")
	}
	f, err := spake.UnmarshalFactor(plain)
	if err != nil {
		return k.spakeFailed(s, "SPAKE FACTOR DECODE")
	}
	// SF-NONE is the only type, here and upstream: anything else
	// is a second factor nobody implements (:437-440).
	if f.Type != spake.SFNone {
		return k.spakeFailed(s, "SPAKE FACTOR TYPE")
	}
	return nil
}

// spakeAccept strengthens the reply key and records what happened.
func (k *KDC) spakeAccept(
	s *asState,
	group int32,
	w, element, thash []byte,
) *wire.KRBError {
	k0, err := spake.DeriveKey(s.clientKey, s.clientEType,
		group, w, element, thash, s.reqBody(), 0)
	if err != nil {
		return k.spakeFailed(s, "SPAKE K0")
	}
	// K'[0] already contains the client's long-term key -- the
	// last step of the derivation is a CF2 with it -- so this
	// strengthens the reply key rather than replacing it, which
	// is what upstream's is_strengthen argument asserts
	// (replace_reply_key, kdcpreauth_plugin.h:260-270). The reply
	// still advertises the *client* key's enctype and key
	// version, which is why those are separate fields.
	s.replyKey = k0
	s.preAuthenticated = true
	// The indicator is what makes the exchange visible to a
	// service, through require_auth. Upstream takes the strings
	// from spake_preauth_indicator in the realm's configuration
	// (add_indicators, spake_kdc.c:155-183); here they come from
	// the same place by another name.
	s.indicators = append(s.indicators, k.SPAKEIndicators...)
	return nil
}

// spakeStateOf reads the challenge's state back out of the cookie.
//
// A response with no cookie behind it is refused: the private scalar
// is in there, and without it there is nothing to compute. Upstream
// refuses the same way, and also insists the cookie was issued at
// **stage zero** (:394-398) -- a cookie from some later second-factor
// round is not a cookie a response may answer.
func (k *KDC) spakeStateOf(
	s *asState,
) (int32, *spake.Private, []byte, *wire.KRBError) {
	pas, expired, err := k.readCookie(s)
	if err != nil {
		return 0, nil, nil,
			k.spakeFailed(s, "SPAKE COOKIE")
	}
	if expired {
		// Expired, and its contents were going to be read, so
		// this is the case upstream reports rather than
		// ignores (fast_util.c:592-598).
		return 0, nil, nil, k.krbError(
			wire.ErrCodePreauthExpired,
			"SPAKE COOKIE EXPIRED", s.nameOrNil())
	}
	pa := findPAData(pas, spake.PAType)
	if pa == nil {
		return 0, nil, nil,
			k.spakeFailed(s, "SPAKE NO COOKIE STATE")
	}
	group, priv, thash, err := parseSpakeState(pa.Value)
	if err != nil {
		return 0, nil, nil,
			k.spakeFailed(s, "SPAKE COOKIE STATE")
	}
	return group, priv, thash, nil
}

// parseSpakeState is the reverse of spakeState (parse_cookie,
// spake_kdc.c:44-77).
func parseSpakeState(
	b []byte,
) (int32, *spake.Private, []byte, error) {
	if len(b) < 8 {
		return 0, nil, nil, errNoSpakeState
	}
	if binary.BigEndian.Uint16(b[:2]) !=
		spakeCookieVersion {
		return 0, nil, nil, errNoSpakeState
	}
	if binary.BigEndian.Uint16(b[2:4]) != 0 {
		return 0, nil, nil, errNoSpakeState
	}
	group := int32(binary.BigEndian.Uint32(b[4:8]))
	rest := b[8:]
	privBytes, rest, err := takeField(rest)
	if err != nil {
		return 0, nil, nil, err
	}
	thash, _, err := takeField(rest)
	if err != nil {
		return 0, nil, nil, err
	}
	priv, err := spake.PrivateFromBytes(privBytes)
	if err != nil {
		return 0, nil, nil, err
	}
	return group, priv, thash, nil
}

// takeField reads one length-prefixed field.
func takeField(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, errNoSpakeState
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n < 0 || 4+n > len(b) {
		return nil, nil, errNoSpakeState
	}
	return b[4 : 4+n], b[4+n:], nil
}

// reqBody is the encoded KDC-REQ-BODY the derivations hash.
//
// Taken out of the request's own octets rather than re-encoded, for
// the reason the TGS body checksum has the same rule: DER is
// canonical but a peer that encoded something a shade differently
// still hashes *its* bytes, and a re-encoding would produce a key the
// client disagrees with.
func (s *asState) reqBody() []byte {
	// **Inside FAST it is the inner body**, and the two are not
	// the same: a client encodes the outer body once per restart
	// (krb5int_fast_prep_req_body from restart_init_creds_loop,
	// get_in_tkt.c:805-838) and the inner body once per round
	// trip, after regenerating the nonce and resetting the times
	// (:1272-1286). So on the second round trip the outer body
	// still carries nonce zero and a till of the epoch while the
	// inner one carries the real values -- 139 octets against
	// 142, for this fixture.
	//
	// A stock kinit found it. The exchange ran to the end and
	// then reported "Password incorrect", because the two sides
	// had hashed different bodies and so derived different keys.
	// Upstream hands its modules rock->inner_body for exactly
	// this reason (request_body, kdc_preauth.c:398-401).
	if s.fast != nil {
		return s.fast.innerBody
	}
	body, err := wire.ReqBodyBytes(s.raw)
	if err != nil {
		return nil
	}
	return body
}
