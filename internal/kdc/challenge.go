package kdc

import (
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// Encrypted challenge, PA-ENCRYPTED-CHALLENGE, the port of
// kdc/kdc_preauth_ec.c.
//
// It is the *only* pre-authentication factor a FAST tunnel offers,
// and that is not a design preference here but upstream's rule: its
// KDC refuses to offer PA-ENC-TIMESTAMP whenever an armor key exists
// -- "Encrypted timestamp must not be used with FAST, and requires a
// key" (kdc/kdc_preauth_encts.c:38-43). A client only runs a
// mechanism whose type appears in the hint list
// (lib/krb5/krb/preauth2.c:648-725, with no unprompted fallback), so
// inside a tunnel there is one factor and this is it.
//
// What it proves is the same thing a timestamp proves -- knowledge of
// the long-term key -- but the key it is encrypted under is combined
// with the armor key, so a recorded challenge is useless to anyone
// who does not also hold the armor. That is the whole of FAST's value
// over a bare timestamp.
//
// The peppers are four, not two, and the pairing matters: a challenge
// and its answer must not be interchangeable, so the two directions
// use "clientchallengearmor" and "kdcchallengearmor" against the
// constant "challengelongterm".

// errNoChallenge reports an encrypted challenge that decrypted under
// no key the client holds.
var errNoChallenge = errors.New("no client key opened the challenge")

// checkChallenge verifies a PA-ENCRYPTED-CHALLENGE and, on success,
// records the key it was proved with so the reply can answer in kind
// (ec_verify, kdc_preauth_ec.c:51-152).
func (k *KDC) checkChallenge(
	s *asState,
	value []byte,
) (int32, string) {
	if s.fast == nil {
		// Upstream's wording. A challenge outside a tunnel
		// has no armor key to combine with, so it would be a
		// bare timestamp wearing the wrong padata type.
		return wire.ErrCodePreauthFailed,
			"ENCRYPTED CHALLENGE OUTSIDE FAST"
	}
	ed, err := wire.UnmarshalEncryptedData(value)
	if err != nil {
		return wire.ErrCodeModified, "DECODE CHALLENGE"
	}
	key, err := k.openChallenge(s, ed)
	if err != nil {
		if errors.Is(err, errClockSkew) {
			return wire.ErrCodeSkew, "CLOCK_SKEW"
		}
		// Upstream's message is "Incorrect password in
		// encrypted challenge", and the code says no more
		// than that on purpose.
		return wire.ErrCodePreauthFailed, "PREAUTH_FAILED"
	}
	s.challengeKey = key
	s.preAuthenticated = true
	return 0, ""
}

// openChallenge tries the client's keys until one opens the challenge
// (kdc_preauth_ec.c:96-125, with client_keys at
// kdc_preauth.c:358-381).
//
// Which keys, and under what enctype, are both easy to get wrong and
// both silent when wrong:
//
// The keys walked are the client's at each enctype the *request*
// listed, highest key version each -- krb5_dbe_find_enctype with kvno
// 0 (kdc_preauth.c:369-371). Not the keys matching the challenge's
// own enctype, which is a different thing entirely, and not every
// kvno.
//
// The challenge is decrypted under the **armor key's** enctype, not
// the long-term key's and not the one named in the EncryptedData. CF2
// takes its output enctype from its first argument and that argument
// is the armor key, so the combined key is an armor-enctype key
// however the long-term key was spelled. Getting this wrong is
// invisible whenever the two enctypes happen to coincide, which in a
// single-enctype realm is always.
//
// Note also what sits outside the loop: a plaintext that will not
// decode, and a timestamp outside the skew, are both final rather
// than a reason to try the next key (kdc_preauth_ec.c:120-126). A key
// that decrypted is the right key; whatever is wrong after that is
// not a wrong password.
func (k *KDC) openChallenge(
	s *asState,
	ed wire.EncryptedData,
) ([]byte, error) {
	for _, e := range s.req.Body.EType {
		start := 0
		_, long, err := k.Store.Key(s.client, &start, e,
			store.AnySaltType, store.HighestKVNO)
		if err != nil {
			continue
		}
		p, err := crypto.Profile(crypto.EncType(e))
		if err != nil {
			continue
		}
		plain, err := s.fast.openChallengeWith(p, long, ed)
		if err != nil {
			continue
		}
		if err := k.checkChallengeTime(s, plain); err != nil {
			return nil, err
		}
		s.challengeEType = crypto.EncType(e)
		return long, nil
	}
	return nil, errNoChallenge
}

// openChallengeWith tries one long-term key and returns the
// plaintext.
func (f *fastState) openChallengeWith(
	p *crypto.EncProfile,
	long []byte,
	ed wire.EncryptedData,
) ([]byte, error) {
	key, err := f.challengeKey(p, long, "clientchallengearmor")
	if err != nil {
		return nil, err
	}
	// f.p, not p: the combined key carries the armor key's
	// enctype.
	return f.p.Decrypt(key, ed.Cipher,
		crypto.UsageEncChallClient)
}

// checkChallengeTime decodes the challenge's plaintext and checks its
// timestamp. Both failures are final, as upstream has them.
func (k *KDC) checkChallengeTime(
	s *asState,
	plain []byte,
) error {
	ts, err := wire.UnmarshalPAEncTSEnc(plain)
	if err != nil {
		return err
	}
	if !withinSkew(stamp(ts.PATimestamp), s.now, k.skew()) {
		return errClockSkew
	}
	return nil
}

// challengeKey combines the armor key with a long-term key
// (kdc_preauth_ec.c:103-106 and :135-137).
//
// The armor key is k1, so the result takes *its* enctype and length
// -- which is why this had to wait for CF2 to run each key under its
// own profile: a client's long-term key is frequently a different
// enctype from the armor key, and this is the call that reaches that
// case.
func (f *fastState) challengeKey(
	p *crypto.EncProfile,
	long []byte,
	pepper string,
) ([]byte, error) {
	return f.p.CF2(f.armor, pepper, p, long,
		"challengelongterm")
}

// answerChallenge is the challenge the reply sends back (ec_return,
// kdc_preauth_ec.c:154-205).
//
// It is the KDC authenticating itself: only something holding the
// client's long-term key could have produced it. The client checks
// nothing but that it decrypts, which upstream's own comment says in
// as many words (lib/krb5/krb/preauth_ec.c:85-89).
func (k *KDC) answerChallenge(
	s *asState,
) (*wire.PAData, error) {
	if s.challengeKey == nil {
		return nil, nil
	}
	// The long-term key's own profile goes into CF2 as the second
	// key's, and the *armor* profile does the encrypting -- the
	// combined key carries the armor key's enctype, not the long
	// term key's (krb5_c_fx_cf2_simple takes its output enctype
	// from k1, and ec_return encrypts with that key directly,
	// kdc_preauth_ec.c:179-182).
	lp, err := crypto.Profile(s.challengeEType)
	if err != nil {
		return nil, err
	}
	key, err := s.fast.challengeKey(lp, s.challengeKey,
		"kdcchallengearmor")
	if err != nil {
		return nil, err
	}
	ct, err := k.sealChallenge(s.fast, key)
	if err != nil {
		return nil, err
	}
	val, err := wire.MarshalEncryptedData(wire.EncryptedData{
		EType: int32(s.fast.p.EncType), Cipher: ct,
	})
	if err != nil {
		return nil, err
	}
	return &wire.PAData{
		Type: wire.PAEncryptedChallenge, Value: val,
	}, nil
}

// sealChallenge encrypts a fresh timestamp under the KDC's half of
// the challenge, at key usage 55.
//
// The client checks nothing but that it decrypts, which upstream's
// own comment says in as many words
// (lib/krb5/krb/preauth_ec.c:85-89). That is enough: only something
// holding the client's long-term key could have produced it.
func (k *KDC) sealChallenge(
	f *fastState,
	key []byte,
) ([]byte, error) {
	now := k.now()
	plain, err := wire.MarshalPAEncTSEnc(wire.PAEncTSEnc{
		PATimestamp: now,
		PAUSec:      int32(now.Nanosecond() / 1000),
	})
	if err != nil {
		return nil, err
	}
	return f.p.Encrypt(key, plain, crypto.UsageEncChallKDC)
}

// fastCookie is the cookie an armored refusal carries.
//
// It is three constant bytes, and that is upstream's own trivial
// form: kdc_fast_make_cookie emits the literal "MIT" whenever no
// pre-authentication mechanism stored any state in it
// (fast_util.c:675-676), and the only mechanisms that ever do are
// SPAKE and its own test module. An encrypted challenge stores none.
//
// The contents are not inspected by anyone. Upstream's reader ignores
// any cookie that does not begin "MIT1" (fast_util.c:563-566), so a
// cookie from a C KDC is dropped here and one from here is dropped
// there -- which is why a constant is enough and why this KDC does
// not read an incoming one at all.
//
// What is skipped by not reading one: an expired MIT1 cookie would
// earn KDC_ERR_PREAUTH_EXPIRED from a C KDC and nothing from this
// one. That matters only to a mechanism spanning more than two round
// trips, which this KDC has none of. Recorded in BOOTSTRAP.md §3.3.
func fastCookie() wire.PAData {
	return wire.PAData{
		Type: wire.PAFXCookie, Value: []byte("MIT"),
	}
}
