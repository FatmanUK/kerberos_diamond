package crypto

import (
	"crypto/aes"
	"crypto/sha1"
	"fmt"
)

// PRF is the enctype's pseudo-random function, RFC 3961 section 5.3's
// pseudo-random() (krb5_c_prf, lib/crypto/krb/prf.c).
//
// It is a separate primitive from encryption and from key derivation,
// and FAST is what needs it: the armor key is a combination of two
// keys neither party chose alone, and combining them takes a function
// that turns a key and a string into pseudo-random bytes of a fixed
// length. PRFLength says how many.
//
// The output length is fixed by the enctype and is not a parameter.
// For the RFC 3962 types it is the cipher's block size and for the
// aes-sha2 types the full hash size, which is why the two families
// differ in more than their internals here.
func (p *EncProfile) PRF(key, in []byte) ([]byte, error) {
	if len(key) != p.KeyLength {
		return nil, fmt.Errorf(
			"%w: key is %d bytes, want %d for %s",
			ErrUnsupported, len(key), p.KeyLength, p.Name)
	}
	return p.prf(p, key, in)
}

// prfDK is the RFC 3961 simplified profile's pseudo-random function
// (krb5int_dk_prf, lib/crypto/krb/prf_dk.c:30-70):
//
//	E(DK(key, "prf"), truncate(SHA1(input)))
//
// Three details, each enough on its own to produce plausible wrong
// bytes.
//
// The derivation constant is the three-byte string "prf", not a
// five-byte key-usage label -- so it is n-folded to the block size
// where a usage constant already is one. deriveRandom handles both,
// which is why this can hand it a short string.
//
// The hash is truncated *down to a multiple of the block size* before
// being encrypted, so SHA-1's twenty bytes become sixteen and the
// last four are discarded. Encrypting all twenty would take the CTS
// path instead of the single-block one and give different bytes.
//
// That single block is then encrypted with a forced zero IV, because
// one block is never CTS -- see cts.go. The whole function therefore
// rests on the quirk reproduced there.
func prfDK(p *EncProfile, key, in []byte) ([]byte, error) {
	sum := sha1.Sum(in)
	n := (len(sum) / p.BlockSize) * p.BlockSize
	kp, err := p.derive(p, key, []byte("prf"), p.KeyLength)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kp)
	if err != nil {
		return nil, err
	}
	out, err := ctsEncrypt(block, nil, sum[:n])
	if err != nil {
		return nil, err
	}
	return out[:p.PRFLength], nil
}

// prfSP800108 is RFC 8009 section 5's pseudo-random function
// (krb5int_aes2_prf, prf_aes2.c:36-42), which is the same
// KDF-HMAC-SHA2 the family derives keys with -- label "prf", and the
// input as the *context*.
//
// That is the one place this family uses a non-empty context, and it
// is why sp800108 takes one at all.
func prfSP800108(p *EncProfile, key, in []byte) ([]byte, error) {
	return sp800108(p, key, []byte("prf"), in, p.PRFLength)
}

// PRFPlus is PRF+ of RFC 6113 section 5.1 (krb5_c_prfplus,
// lib/crypto/krb/cf2.c:38-78):
//
//	PRF(k, 1||input) || PRF(k, 2||input) || ...
//
// truncated to the length asked for. The counter is a single octet
// prepended to the input, so at most 255 blocks can be produced --
// and upstream refuses rather than wrapping, which matters because a
// wrapped counter would repeat earlier output silently.
func (p *EncProfile) PRFPlus(
	key, input []byte,
	outLen int,
) ([]byte, error) {
	blocks := (outLen + p.PRFLength - 1) / p.PRFLength
	if blocks > 255 {
		return nil, fmt.Errorf(
			"%w: PRF+ cannot produce %d bytes from %s",
			ErrUnsupported, outLen, p.Name)
	}
	in := make([]byte, 1+len(input))
	copy(in[1:], input)
	out := make([]byte, 0, blocks*p.PRFLength)
	for i := 1; i <= blocks; i++ {
		in[0] = byte(i)
		block, err := p.PRF(key, in)
		if err != nil {
			return nil, err
		}
		out = append(out, block...)
	}
	return out[:outLen], nil
}

// CF2 is KRB-FX-CF2 of RFC 6113 section 5.1 (krb5_c_fx_cf2_simple,
// lib/crypto/krb/cf2.c:121-168):
//
//	random-to-key(PRF+(k1, pepper1) XOR PRF+(k2, pepper2))
//
// It is how FAST produces a key neither party chose. The armor key
// combines the client's subkey with the session key out of its armor
// ticket, and the strengthened reply key combines the client's
// long-term key with a key the KDC chose -- in both cases so that
// learning one of the two is not enough.
//
// The peppers are what stop the two uses colliding. The same pair of
// keys combined under different peppers gives unrelated results,
// which is why they are strings in the protocol rather than a
// convention.
//
// The result takes k1's enctype, as upstream's does: it reads the
// enctype off k1 and never looks at k2's.
func (p *EncProfile) CF2(
	k1 []byte, pepper1 string,
	k2 []byte, pepper2 string,
) ([]byte, error) {
	a, err := p.PRFPlus(k1, []byte(pepper1), p.KeyLength)
	if err != nil {
		return nil, err
	}
	b, err := p.PRFPlus(k2, []byte(pepper2), p.KeyLength)
	if err != nil {
		return nil, err
	}
	for i := range a {
		a[i] ^= b[i]
	}
	return a, nil
}
