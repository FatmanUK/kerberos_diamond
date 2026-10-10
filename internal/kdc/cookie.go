package kdc

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// cookieMagic is the four octets an MIT version 1 cookie starts with
// (kdc_fast_read_cookie, fast_util.c:563-566).
//
// A cookie that does not begin with them is **ignored**, not refused,
// which is how a cookie from a different implementation passes
// harmlessly: upstream's reader drops anything else, and so does
// this. The trivial three-octet "MIT" cookie is exactly such a value.
var cookieMagic = []byte("MIT1")

// cookieLifetime is how long a cookie's contents are believed
// (COOKIE_LIFETIME, fast_util.c:33).
const cookieLifetime = 600 * time.Second

// cookieKey derives the key a cookie is sealed with
// (derive_cookie_key, fast_util.c:508-532).
//
// PRF+ over "COOKIE" followed by the client's fully qualified name,
// from the **local krbtgt key**. Two consequences, both of them the
// point:
//
//   - only a KDC of this realm can read or make one, because only a
//     KDC has that key. So the state inside is as trustworthy as
//     anything the KDC wrote itself.
//   - and the client's name is in the derivation, so a cookie
//     handed to one principal cannot be replayed by another.
//
// This is what lets a multi-round-trip mechanism work on a KDC that
// keeps nothing: the state goes to the client and comes back, and any
// process sharing the database can read it. A cookie survives the KDC
// that issued it being killed, which no in-memory session table
// would.
func (k *KDC) cookieKey(
	client wire.PrincipalName,
) ([]byte, crypto.EncType, uint32, error) {
	tgtKey, etype, kvno, err := k.localTGT()
	if err != nil {
		return nil, 0, 0, err
	}
	p, err := crypto.Profile(etype)
	if err != nil {
		return nil, 0, 0, err
	}
	in := append([]byte("COOKIE"),
		store.UnparseName(k.Realm, client.Components)...)
	derived, err := p.PRFPlus(tgtKey, in, p.KeyLength)
	if err != nil {
		return nil, 0, 0, err
	}
	return derived, etype, kvno, nil
}

// makeCookie seals one mechanism's state into a FAST cookie.
//
// The format is upstream's: "MIT1", the key version as four
// big-endian octets, then the encrypted SecureCookie
// (kdc_fast_make_cookie, fast_util.c:650-712). The key version is
// outside the ciphertext because the reader needs it to pick a key
// before it can decrypt anything.
func (k *KDC) makeCookie(
	client wire.PrincipalName,
	contents []wire.PAData,
) (wire.PAData, error) {
	key, etype, kvno, err := k.cookieKey(client)
	if err != nil {
		return wire.PAData{}, err
	}
	p, err := crypto.Profile(etype)
	if err != nil {
		return wire.PAData{}, err
	}
	plain, err := wire.MarshalSecureCookie(wire.SecureCookie{
		Time: k.now(), Data: contents,
	})
	if err != nil {
		return wire.PAData{}, err
	}
	ct, err := p.Encrypt(key, plain, crypto.UsagePAFXCookie)
	if err != nil {
		return wire.PAData{}, err
	}
	out := append([]byte{}, cookieMagic...)
	out = binary.BigEndian.AppendUint32(out, kvno)
	return wire.PAData{
		Type:  wire.PAFXCookie,
		Value: append(out, ct...),
	}, nil
}

// readCookie finds and opens the request's cookie, returning the
// padata each mechanism stored.
//
// Three outcomes and all three are upstream's. No cookie, or one that
// is not MIT1, yields nothing and no error -- a cookie from another
// implementation is not this KDC's business. One that will not
// decrypt or decode is an error, because it was made here and should
// have worked. And an **expired** one yields nothing: its contents
// are not believed, and whether that is reported as an error depends
// on whether anything was going to read them (fast_util.c:592-598),
// which is the caller's question.
func (k *KDC) readCookie(
	s *asState,
) ([]wire.PAData, bool, error) {
	pa := findPAData(s.req.PAData, wire.PAFXCookie)
	if pa == nil || len(pa.Value) <= 8 ||
		!bytes.Equal(pa.Value[:4], cookieMagic) {
		return nil, false, nil
	}
	// The key version in the cookie is read past rather than
	// used: upstream looks the named version up so that a cookie
	// made under a previous krbtgt key still opens
	// (get_cookie_key, fast_util.c:534-...), and this uses the
	// current one. The cost is a cookie issued within the
	// lifetime of a krbtgt re-key being dropped, which costs the
	// client one restart of the exchange -- against the standing
	// gap that this project loads one master key and not a list.
	key, etype, _, err := k.cookieKey(s.cname)
	if err != nil {
		return nil, false, err
	}
	p, err := crypto.Profile(etype)
	if err != nil {
		return nil, false, err
	}
	plain, err := p.Decrypt(key, pa.Value[8:],
		crypto.UsagePAFXCookie)
	if err != nil {
		return nil, false, err
	}
	c, err := wire.UnmarshalSecureCookie(plain)
	if err != nil {
		return nil, false, err
	}
	if k.now().Sub(c.Time) > cookieLifetime {
		return nil, true, nil
	}
	return c.Data, false, nil
}
