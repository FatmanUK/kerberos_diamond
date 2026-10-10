package kdc

import (
	"errors"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/spake"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// preauth enforces a principal's pre-authentication requirement.
//
// A principal without +requires_preauth gets a ticket in one round
// trip and no padata travels in either direction. That is both the
// easiest case to get right and the most deterministic to diff, which
// is why it is the one with no conditions on it here.
//
// With the requirement set, a request carrying no acceptable
// PA-ENC-TIMESTAMP is refused with KDC_ERR_PREAUTH_REQUIRED and the
// e-data carries the hint list the client needs to try again: the
// salt and enctype to run string-to-key with. Without that hint the
// client would have to guess the salt.
func (k *KDC) preauth(s *asState) *wire.KRBError {
	if !s.client.RequiresPreAuth() {
		return nil
	}
	// SPAKE first, because it is the only mechanism here that
	// spans more than one round trip: a request carrying one is
	// *continuing* an exchange, where the other factors are
	// alternatives to starting one.
	//
	// It is offered armored or not. Upstream's plugin declares no
	// flags function at all (kdcpreauth_spake_initvt,
	// spake_kdc.c:542-562), so it has no armor requirement --
	// worth saying because the value of SPAKE is usually
	// described in terms of FAST, and the two are independent.
	if sp := findPAData(
		s.req.PAData, spake.PAType); sp != nil &&
		len(k.SPAKEGroups) > 0 {
		return k.spakePreauth(s, sp.Value)
	}
	// Inside a tunnel the factor is an encrypted challenge, and a
	// timestamp is not offered. Upstream still *accepts* a
	// timestamp that arrives inside one -- ec_verify has the
	// armor check but enc_ts_verify has none
	// (kdc/kdc_preauth_encts.c:46) -- so this does too, and the
	// asymmetry is upstream's rather than an oversight here.
	if ch := findPAData(
		s.req.PAData, wire.PAEncryptedChallenge); ch != nil {
		code, status := k.checkChallenge(s, ch.Value)
		if code != 0 {
			return k.krbError(code, status, s.nameOrNil())
		}
		return nil
	}
	return k.timestampPreauth(s)
}

// timestampPreauth is the unarmored factor, and the refusal that asks
// for one when nothing acceptable arrived.
func (k *KDC) timestampPreauth(s *asState) *wire.KRBError {
	ts := findPAData(s.req.PAData, wire.PAEncTimestamp)
	if ts == nil {
		return k.preauthRequired(s)
	}
	if err := k.checkEncTimestamp(s, ts.Value); err != nil {
		code := wire.ErrCodePreauthFailed
		status := "PREAUTH_FAILED"
		if errors.Is(err, errClockSkew) {
			code, status = wire.ErrCodeSkew, "CLOCK_SKEW"
		}
		return k.krbError(code, status, s.nameOrNil())
	}
	// The ticket records that the client proved knowledge of its
	// key, which is what lets a service distinguish a
	// preauthorised ticket from one issued on request alone.
	s.preAuthenticated = true
	return nil
}

// preauthRequired builds the KDC_ERR_PREAUTH_REQUIRED refusal with
// its hint list.
//
// The list is a PA-DATA sequence holding an empty PA-ENC-TIMESTAMP --
// which says "send me one" and carries nothing -- followed by
// PA-ETYPE-INFO2 naming each enctype the client has a key for, with
// the salt for it. Ordering matters to clients that take the first
// mechanism they understand.
func (k *KDC) preauthRequired(s *asState) *wire.KRBError {
	e := k.krbError(wire.ErrCodePreauthRequired,
		"NEEDED_PREAUTH", s.nameOrNil())
	hints, err := k.hintList(s)
	if err != nil {
		return k.krbError(wire.ErrCodeGeneric,
			"ETYPE_INFO2", s.nameOrNil())
	}
	edata, err := wire.MarshalPADataSeq(hints)
	if err != nil {
		return k.krbError(wire.ErrCodeGeneric,
			"ETYPE_INFO2", s.nameOrNil())
	}
	e.EData = edata
	return e
}

// hintList is the hint list a PREAUTH_REQUIRED carries
// (get_preauth_hint_list, kdc/kdc_preauth.c:975-1013).
//
// The order is upstream's. The empty PA-FX-FAST comes first and is
// the *advertisement*: it is what tells a client with an armor cache
// that it may upgrade this exchange to FAST (get_in_tkt.c:1702-1708).
// Then PA-ETYPE-INFO2, then whichever factor applies.
//
// Which factor applies is decided by the armor key, not by
// configuration. Inside a tunnel it is an encrypted challenge and a
// timestamp is *not* offered (kdc/kdc_preauth_encts.c:38-43); outside
// one it is the reverse, because an encrypted challenge has no armor
// key to combine with (kdc/kdc_preauth_ec.c:44-48).
func (k *KDC) hintList(s *asState) ([]wire.PAData, error) {
	info, err := k.etypeInfo2(s)
	if err != nil {
		return nil, err
	}
	out := []wire.PAData{
		{Type: wire.PAFXFast},
		{Type: wire.PAETypeInfo2, Value: info},
	}
	out = append(out, k.spakeHint()...)
	if s.fast == nil {
		out = append(out,
			wire.PAData{Type: wire.PAEncTimestamp})
	} else {
		out = append(out,
			wire.PAData{Type: wire.PAEncryptedChallenge})
	}
	// The cookie goes last and goes on *every* AS refusal that
	// carries hints, armored or not: prepare_error_as appends one
	// whenever there is e_data at all, with no condition on FAST
	// (do_as_req.c:785-796). Restricting it to the armored case
	// was this implementation's mistake, and deleting the harness
	// exemption is what found it -- the C's unarmored hint list
	// is "136 19 2 133" and this one was "136 19 2".
	//
	// Inside a tunnel it is load-bearing: without it a client
	// will not retry at all (lib/krb5/krb/fast.c:481-492).
	// Outside one nothing reads it, because a client retries on
	// any non-empty e-data there (fast.c:493-497). It is sent in
	// both cases because upstream sends it in both.
	return append(out, fastCookie()), nil
}

// spakeHint advertises SPAKE, or nothing when the realm offers no
// groups.
//
// **It goes before the timestamp or the challenge**, and that is the
// order the modules are registered in rather than a preference:
// get_preauth_hint_list walks preauth_systems in order, and spake is
// registered ahead of encrypted_challenge and encrypted_timestamp
// (kdc_preauth.c:134-141). It matters because a client takes the
// first mechanism it understands, so the order *is* the KDC's
// preference as far as the client is concerned -- and the
// differential case is what insisted on it: this list had SPAKE last
// and the oracle's had it third.
//
// The value is empty, which says the mechanism is available and
// nothing more. Upstream's spake_edata returns an empty padata
// whenever no optimistic challenge is configured (:316-323), and this
// KDC configures none: an optimistic challenge saves a round trip by
// guessing the group before the client has said what it has, and
// guessing wrong costs two.
func (k *KDC) spakeHint() []wire.PAData {
	if len(k.SPAKEGroups) == 0 {
		return nil
	}
	return []wire.PAData{{Type: spake.PAType}}
}

// etypeInfo2 builds the single ETYPE-INFO2 entry the hint list
// carries.
//
// One entry, not one per enctype the client holds: make_etype_info
// allocates room for exactly one and fills it from rock->client_key
// (kdc/kdc_preauth.c:1046-1069), so the enctype named is the one
// select_client_key already chose. A list of every available enctype
// would be more informative and is not what any MIT KDC sends.
//
// The salt is sent explicitly even though it is the default one the
// client could compute. A client that guessed would be wrong for any
// principal whose salt was ever set by hand, and a wrong salt fails
// as "password incorrect" with nothing to say why. s2kparams is left
// absent, which means the 4096-iteration default
// (_make_etype_info_entry leaves it empty).
func (k *KDC) etypeInfo2(s *asState) ([]byte, error) {
	salt, err := k.clientSalt(s)
	if err != nil {
		return nil, err
	}
	return wire.MarshalETypeInfo2([]wire.ETypeInfo2Entry{{
		EType: int32(s.clientEType),
		Salt:  &salt,
	}})
}

// clientSalt is the salt a client has to use, which is the stored one
// when the key carries an explicit salt and the principal's default
// otherwise.
//
// The explicit case is a renamed principal: the default salt is
// derived from the name, so renaming one would invalidate every
// password-derived key unless the salt computed under the *old* name
// is pinned first (krb5_dbe_specialize_salt, lib/kdb/kdb5.c:2390).
// Upstream's own rename test is exactly this -- rename, then kinit
// with the same password (tests/t_renprinc.py:31-38).
func (k *KDC) clientSalt(s *asState) (string, error) {
	if s.clientSaltType == store.SaltSpecial &&
		len(s.clientSalt) > 0 {
		return string(s.clientSalt), nil
	}
	components, realm, err := store.ParseName(s.client.Name)
	if err != nil {
		return "", err
	}
	return string(crypto.Salt(realm, components)), nil
}

// errClockSkew separates a timestamp that decrypted correctly but
// names the wrong moment from one that did not decrypt at all. They
// are different protocol errors and a client acts on them
// differently: a skew error is worth retrying after resynchronising,
// a preauth failure is not.
var errClockSkew = errors.New("clock skew too great")

// checkEncTimestamp verifies a PA-ENC-TIMESTAMP.
//
// It decrypts under the client's long-term key with key usage 1 and
// checks the timestamp is within the configured skew. Decrypting at
// all is the proof of knowledge; the timestamp is what stops a
// recorded one being replayed forever.
func (k *KDC) checkEncTimestamp(s *asState, value []byte) error {
	ed, err := wire.UnmarshalEncryptedData(value)
	if err != nil {
		return err
	}
	p, err := crypto.Profile(crypto.EncType(ed.EType))
	if err != nil {
		return err
	}
	key, err := k.preauthKey(s, ed)
	if err != nil {
		return err
	}
	plain, err := p.Decrypt(key, ed.Cipher,
		crypto.UsageASReqPAEncTS)
	if err != nil {
		return err
	}
	ts, err := wire.UnmarshalPAEncTSEnc(plain)
	if err != nil {
		return err
	}
	skew := k.ClockSkew
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	if d := unstamp(s.now).Sub(ts.PATimestamp); d > skew ||
		d < -skew {
		return errClockSkew
	}
	return nil
}

// preauthKey finds the client key the timestamp was encrypted under.
//
// It is not necessarily the one the reply will be encrypted under:
// the client chooses which of its keys to prove with, and names the
// enctype in the EncryptedData. The cursor in store.SelectKey exists
// for this -- every matching key is tried, because a kvno the client
// still holds may not be the highest.
func (k *KDC) preauthKey(
	s *asState,
	ed wire.EncryptedData,
) ([]byte, error) {
	start := 0
	_, key, err := k.Store.Key(s.client, &start, ed.EType,
		store.AnySaltType, store.AnyKVNO)
	return key, err
}

// findPAData returns the first padata item of a type, or nil.
func findPAData(ps []wire.PAData, t int32) *wire.PAData {
	for i := range ps {
		if ps[i].Type == t {
			return &ps[i]
		}
	}
	return nil
}
