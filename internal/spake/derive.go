package spake

import (
	"encoding/binary"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
)

// UsageSPAKE encrypts the response's factor field
// (KRB5_KEYUSAGE_SPAKE, krb5.hin:1002).
const UsageSPAKE crypto.Usage = 65

// DeriveW is the SPAKE multiplier, derived from the client's
// long-term key (derive_wbytes, util.c:100-141).
//
// PRF+ over the string "SPAKEsecret" followed by the group number as
// four big-endian octets, to the group's multiplier length. The group
// number is in the input on purpose: the same password used with two
// groups yields two unrelated multipliers.
func DeriveW(
	key []byte,
	etype crypto.EncType,
	group int32,
) ([]byte, error) {
	p, err := crypto.Profile(etype)
	if err != nil {
		return nil, err
	}
	in := append([]byte("SPAKEsecret"), be32(group)...)
	return p.PRFPlus(key, in, MultLen)
}

// UpdateThash folds one or two messages into the transcript hash
// (update_thash, util.c:70-96).
//
// A nil thash starts as **the group's hash length of zero octets**
// rather than as nothing (:80-87), so the first update already hashes
// a block of zeroes in front of the first message -- which is the
// detail a reimplementation gets wrong by starting from an empty
// buffer, and which the published vectors catch immediately.
//
// Either message may be nil and is then an empty string, not skipped:
// the hash is over thash || a || b, and an absent b is zero octets of
// b.
func UpdateThash(thash, a, b []byte) []byte {
	if len(thash) == 0 {
		thash = make([]byte, HashLen)
	}
	return Hash(thash, a, b)
}

// DeriveKey is K'[n], the key the response's factor is sealed with
// (n=1) and the strengthened reply key (n=0) (derive_key,
// util.c:143-211).
//
// Nine inputs, hashed in this order and no other: the literal
// "SPAKEkey", the group number, the **initial key's enctype**, the
// multiplier, the shared element, the transcript hash, the encoded
// KDC-REQ-BODY, n, and a one-octet block counter.
//
// Two of those are worth naming. The request body is in there, so a
// key derived for one request cannot be used with another -- which is
// what binds the exchange to what was actually asked for. And the
// block counter is the last input and starts at **one**, so a hash
// function shorter than the key's seed is extended by hashing again
// with the counter bumped; for every enctype in this project one
// block is enough, and the counter is still an input to it.
//
// The result is not the key: it is a seed, turned into a key by the
// enctype's random-to-key, and then combined with the initial key by
// KRB-FX-CF2 under the pepper pair "SPAKE" and "keyderiv". So the
// strengthened key depends on the password as well as on the
// exchange, and an attacker who broke the exchange still needs the
// password.
func DeriveKey(
	key []byte,
	etype crypto.EncType,
	group int32,
	wbytes, element, thash, reqBody []byte,
	n uint32,
) ([]byte, error) {
	p, err := crypto.Profile(etype)
	if err != nil {
		return nil, err
	}
	seed, err := deriveSeed(p, group, key, wbytes, element,
		thash, reqBody, n)
	if err != nil {
		return nil, err
	}
	// Upstream turns the seed into a key with
	// krb5_c_random_to_key before combining (util.c:200-204). For
	// every enctype this project implements that operation is the
	// identity -- RFC 3962 and RFC 8009 both define random-to-key
	// as "use the octets" -- so the seed *is* the key here. It is
	// not the identity for des3, which is why upstream has the
	// call at all.
	return p.CF2(key, "SPAKE", p, seed, "keyderiv")
}

// deriveSeed computes as many hash blocks as the enctype's seed needs
// and trims to that length.
func deriveSeed(
	p *crypto.EncProfile,
	group int32,
	key, wbytes, element, thash, reqBody []byte,
	n uint32,
) ([]byte, error) {
	parts := [][]byte{
		[]byte("SPAKEkey"),
		be32(group),
		be32(int32(p.EncType)),
		wbytes,
		element,
		thash,
		reqBody,
		be32u(n),
		nil,
	}
	seedLen := p.KeyLength
	blocks := (seedLen + HashLen - 1) / HashLen
	out := make([]byte, 0, blocks*HashLen)
	for i := 0; i < blocks; i++ {
		parts[8] = []byte{byte(i + 1)}
		out = append(out, Hash(parts...)...)
	}
	return out[:seedLen], nil
}

// be32 is a signed 32-bit value, big-endian, which is how every
// integer in these derivations travels.
func be32(v int32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	return b[:]
}

// be32u is be32 for the round number.
func be32u(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
