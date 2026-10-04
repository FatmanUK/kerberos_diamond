package kdc

import (
	"errors"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
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
	info, err := k.etypeInfo2(s)
	if err != nil {
		return k.krbError(wire.ErrCodeGeneric,
			"ETYPE_INFO2", s.nameOrNil())
	}
	edata, err := wire.MarshalPADataSeq([]wire.PAData{
		{Type: wire.PAETypeInfo2, Value: info},
		{Type: wire.PAEncTimestamp},
	})
	if err != nil {
		return k.krbError(wire.ErrCodeGeneric,
			"ETYPE_INFO2", s.nameOrNil())
	}
	e.EData = edata
	return e
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
	components, realm, err := store.ParseName(s.client.Name)
	if err != nil {
		return nil, err
	}
	salt := string(crypto.Salt(realm, components))
	return wire.MarshalETypeInfo2([]wire.ETypeInfo2Entry{{
		EType: int32(s.clientEType),
		Salt:  &salt,
	}})
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
