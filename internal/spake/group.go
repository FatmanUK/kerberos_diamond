// Package spake is RFC 8125's password-authenticated key exchange as
// Kerberos uses it: a second pre-authentication factor carried inside
// FAST, which narrows the password-guessing window a
// pre-authentication exchange otherwise leaves open.
//
// # Why this and not PKINIT
//
// PKINIT is the other way to strengthen an AS exchange and it is a
// declared non-goal, for a reason that is about this project's method
// rather than about effort: upstream's only PKINIT backend is
// OpenSSL, so under BOOTSTRAP.md section 3.3's rule there is no
// oracle to compare against and PKINIT would be the one feature
// anchored by nothing but a round trip.
//
// SPAKE is the opposite case. Upstream ships a **built-in**
// edwards25519 (plugins/preauth/spake/edwards25519.c) and reaches
// OpenSSL only for the NIST curves, and it publishes **test vectors
// with every intermediate value** (t_vectors.c) -- the multiplier,
// both private scalars, both masked public points, the shared
// element, the transcript hash and all four derived keys. So it is
// implementable *and* anchorable with the rule unchanged, which is
// the whole reason it is in the plan and PKINIT is not.
//
// # What is here and what is not
//
// The edwards25519 group, the key derivations, and the protocol
// messages. The NIST groups are absent: they are what upstream needs
// OpenSSL for, so implementing them would mean either linking it or
// writing P-256 arithmetic with no oracle -- and edwards25519 is the
// group both ends negotiate by default.
//
// Second factors are absent too, and so are they upstream: the KDC
// plugin hardcodes SF-NONE and says in a comment where the second
// factor would go (spake_kdc.c:240-243). What SPAKE buys without one
// is still the point of it -- an attacker who records an exchange
// cannot test password guesses against it offline.
package spake

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// GroupEdwards25519 is the group number IANA assigned
// (SPAKE_GROUP_EDWARDS25519, plugins/preauth/spake/iana.h).
const GroupEdwards25519 int32 = 1

// The group's fixed parameters (spake_iana_edwards25519,
// iana.c:88-91): a 32-octet multiplier, 32-octet elements, and
// SHA-256 as the hash.
const (
	MultLen = 32
	ElemLen = 32
	HashLen = sha256.Size
)

// ErrNotOnCurve reports a public element that is not a point.
var ErrNotOnCurve = errors.New("spake: element is not a point")

// M and N are the two fixed points SPAKE masks with, one per side
// (iana.c:32-42). They are published constants, derived from nothing.
//
// **The KDC masks with M and the client with N**, which is the way
// round upstream has it and which is easy to get backwards:
// group_keygen passes `use_m = gstate->is_kdc' (groups.c:265-266),
// and group_result inverts it with a comment saying why -- "Invert
// is_kdc here to use the other party's constant" (:316-317). Each
// side masks with its own point and unmasks with the other's.
//
// Getting it backwards is not a silent failure in the end -- the two
// sides compute different shared elements and the exchange fails --
// but it *is* silent in a unit test that computes both sides the same
// wrong way. Upstream's published vectors are what caught it here:
// the shared element agreed and the public elements did not.
var (
	mBytes = [...]byte{
		0xD0, 0x48, 0x03, 0x2C, 0x6E, 0xA0, 0xB6, 0xD6,
		0x97, 0xDD, 0xC2, 0xE8, 0x6B, 0xDA, 0x85, 0xA3,
		0x3A, 0xDA, 0xC9, 0x20, 0xF1, 0xBF, 0x18, 0xE1,
		0xB0, 0xC6, 0xD1, 0x66, 0xA5, 0xCE, 0xCD, 0xAF,
	}
	nBytes = [...]byte{
		0xD3, 0xBF, 0xB5, 0x18, 0xF4, 0x4F, 0x34, 0x30,
		0xF2, 0x9D, 0x0C, 0x92, 0xAF, 0x50, 0x38, 0x65,
		0xA1, 0xED, 0x32, 0x81, 0xDC, 0x69, 0xB3, 0x5D,
		0xD8, 0x68, 0xBA, 0x85, 0xF8, 0x86, 0xC4, 0xAB,
	}
)

// point is M or N, decoded once.
func point(b []byte) *edwards25519.Point {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		panic("spake: " + err.Error())
	}
	return p
}

// maskPoint returns M for the client's side and N for the KDC's.
func maskPoint(useM bool) *edwards25519.Point {
	if useM {
		return point(mBytes[:])
	}
	return point(nBytes[:])
}

// Private is one side's secret scalar.
//
// **It is the scalar before the cofactor multiplication**, and the
// difference from upstream's representation is worth stating because
// it is the one place this implementation is not a transcription.
//
// Upstream picks a scalar uniformly from [0, L), multiplies it by the
// cofactor 8 as a **raw 256-bit integer** (left_shift_3,
// edwards25519.c:1632-1644) and keeps that as the private key. The
// cofactor is the point of it, and its own comment says why: "since
// our private key is a multiple of the cofactor, the shared point
// will be in the generator subgroup even if a rogue peer sends a
// point which is not" (:1696-1700). A raw 8s can exceed the group
// order, and a reduced scalar is not interchangeable with it -- `(8s
// mod L) * Q' differs from `8s * Q' whenever Q has a torsion
// component, which is exactly the case the cofactor exists to handle.
//
// So this keeps s and multiplies the *point* by the cofactor instead:
// `s * MultByCofactor(Q)' is `8s * Q' by definition, needs no
// unreduced scalar, and lands on the same element. The public point
// is `(8s mod L) * G', which equals `8s * G' because G has order L.
type Private struct {
	s *edwards25519.Scalar
}

// eight is the cofactor as a scalar.
func eight() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 8
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		panic("spake: " + err.Error())
	}
	return s
}

// Keygen picks a private scalar and returns it with the masked public
// element the peer receives (builtin_edwards25519_keygen,
// edwards25519.c:1646-1693).
//
// useM selects which fixed point masks the public value, and it is
// **true for the KDC**: see the note on M and N.
func Keygen(
	wbytes []byte,
	useM bool,
) (*Private, []byte, error) {
	var seed [64]byte
	if _, err := rand.Read(seed[:32]); err != nil {
		return nil, nil, err
	}
	return keygenFrom(seed[:], wbytes, useM)
}

// keygenFrom is Keygen with the randomness supplied, which the
// published test vectors need: they pin both private scalars.
func keygenFrom(
	seed64 []byte,
	wbytes []byte,
	useM bool,
) (*Private, []byte, error) {
	s, err := new(edwards25519.Scalar).SetUniformBytes(seed64)
	if err != nil {
		return nil, nil, err
	}
	return publicFor(&Private{s: s}, wbytes, useM)
}

// publicFor computes the masked public element for a private scalar.
func publicFor(
	priv *Private,
	wbytes []byte,
	useM bool,
) (*Private, []byte, error) {
	w, err := multiplier(wbytes)
	if err != nil {
		return nil, nil, err
	}
	// (8s mod L) * G, which is 8s * G because G has order L.
	s8 := new(edwards25519.Scalar).Multiply(priv.s, eight())
	base := new(edwards25519.Point).ScalarBaseMult(s8)
	mask := new(edwards25519.Point).ScalarMult(w,
		maskPoint(useM))
	pub := new(edwards25519.Point).Add(base, mask)
	return priv, pub.Bytes(), nil
}

// Result is the shared element both sides compute
// (builtin_edwards25519_result, edwards25519.c:1695-1738).
//
// The peer's element is checked to be a point and **not** checked to
// be in the generator subgroup, which is upstream's deliberate choice
// and is safe for the reason its comment gives: the private scalar is
// a multiple of the cofactor, so multiplying by it kills any torsion
// component the peer slipped in.
func Result(
	priv *Private,
	wbytes []byte,
	theirPub []byte,
	useM bool,
) ([]byte, error) {
	if len(theirPub) != ElemLen {
		return nil, fmt.Errorf("%w: %d octets",
			ErrNotOnCurve, len(theirPub))
	}
	q, err := new(edwards25519.Point).SetBytes(theirPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotOnCurve, err)
	}
	w, err := multiplier(wbytes)
	if err != nil {
		return nil, err
	}
	// useM here is the *peer's* constant, not this side's: a KDC
	// masks with M and unmasks with N, so a caller inverts the
	// flag between Keygen and Result exactly as group_result does
	// (groups.c:316-317).
	mask := new(edwards25519.Point).ScalarMult(w,
		maskPoint(useM))
	un := new(edwards25519.Point).Subtract(q, mask)
	// 8 * Q first, then the unshifted scalar: together that is
	// the raw 8s * Q upstream computes, without an unreduced
	// scalar. See Private.
	k := new(edwards25519.Point).MultByCofactor(un)
	return new(edwards25519.Point).ScalarMult(priv.s,
		k).Bytes(), nil
}

// multiplier reduces the derived w octets to a scalar, which is
// upstream's zero-extend-to-64-and-reduce (`memcpy' then `memset'
// then x25519_sc_reduce, edwards25519.c:1666-1669).
func multiplier(wbytes []byte) (*edwards25519.Scalar, error) {
	if len(wbytes) != MultLen {
		return nil, fmt.Errorf(
			"spake: multiplier is %d octets, want %d",
			len(wbytes), MultLen)
	}
	var wide [64]byte
	copy(wide[:MultLen], wbytes)
	return new(edwards25519.Scalar).SetUniformBytes(wide[:])
}

// Hash is the group's hash function, SHA-256 over the concatenation
// of its inputs (builtin_sha256, edwards25519.c:1740-1745).
func Hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
