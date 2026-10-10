// Package camellia is the Camellia block cipher (RFC 3713), which
// Kerberos uses for the camellia128-cts-cmac and camellia256-cts-cmac
// enctypes (RFC 6803).
//
// # Why it is here at all
//
// Camellia is the only **non-deprecated** enctype this project was
// missing. Every other gap in upstream's table is either deprecated
// (des3-cbc-sha1, arcfour-hmac) or additionally marked weak and
// disabled by default -- but camellia128 and camellia256 carry no
// flags at all (lib/crypto/krb/etypes.c:106-125) and both are in a
// stock client's default enctype list (init_ctx.c:59-67), so a client
// may ask for one and expect an answer.
//
// # Why it is written out rather than imported
//
// Go has neither Camellia nor CMAC, in the standard library or in
// x/crypto, and this project takes a dependency only when the code
// that needs it lands (BOOTSTRAP.md section 4). Camellia is specified
// completely by RFC 3713 and anchored by the vectors in its appendix,
// so writing it is bounded work with a definite answer -- which is
// the test this project applies to primitives it cannot borrow.
//
// It is the 64-bit formulation from the RFC's own pseudocode rather
// than the table-driven one upstream uses
// (lib/crypto/builtin/camellia/camellia.c, 1,544 lines of pre-spread
// tables). The RFC's version is a fifth of the size and reads as the
// specification does, which matters more here than throughput: a KDC
// performs one or two block operations per request.
package camellia

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// BlockSize is Camellia's block size in bytes, which is 16 for every
// key length -- the same as AES, which is why the Kerberos enctypes
// can share a CTS mode.
const BlockSize = 16

// sbox1 is the cipher's single substitution table (RFC 3713 section
// 2.4.1). The other three are rotations of it and are computed
// rather than stored:
//
//	SBOX2[x] = SBOX1[x] <<< 1
//	SBOX3[x] = SBOX1[x] <<< 7
//	SBOX4[x] = SBOX1[x <<< 1]
//
// Storing one table and rotating is not a space optimisation; it is
// the only form in which the table can be checked by eye against the
// RFC. Upstream pre-spreads all four into 32-bit words, which is
// faster and unverifiable.
//
// Ten to a row rather than the RFC's sixteen, which is what fits the
// column limit; the values are in the RFC's order regardless, so a
// reader checking it against the published table counts rather than
// compares rows.
var sbox1 = [256]byte{
	0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85,
	0x57, 0x35, 0xea, 0x0c, 0xae, 0x41, 0x23, 0xef, 0x6b, 0x93,
	0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65,
	0x92, 0xbd, 0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce,
	0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a, 0xa6, 0xe1,
	0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d, 0xd9, 0x01, 0x5a, 0xd6,
	0x51, 0x56, 0x6c, 0x4d, 0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc,
	0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
	0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7,
	0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7, 0x14, 0x58, 0x3a, 0x61,
	0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18,
	0xf2, 0x22, 0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91,
	0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50, 0xaa, 0xd0,
	0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95,
	0xe0, 0xff, 0x64, 0xd2, 0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7,
	0x75, 0xdb, 0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
	0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33, 0x73, 0x67,
	0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2, 0x52, 0x9b, 0xd8, 0x26,
	0xc8, 0x37, 0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe,
	0x63, 0x2e, 0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e,
	0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59, 0x78, 0x98,
	0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42,
	0x88, 0xa2, 0x8d, 0xfa, 0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee,
	0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
	0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3,
	0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e,
}

// The key-schedule constants (RFC 3713 section 2.4.2), which are the
// hexadecimal expansion of the square root of the first six primes.
const (
	sigma1 = 0xA09E667F3BCC908B
	sigma2 = 0xB67AE8584CAA73B2
	sigma3 = 0xC6EF372FE94F82BE
	sigma4 = 0x54FF53A5F1D36F1C
	sigma5 = 0x10E527FADE682D1D
	sigma6 = 0xB05688C2B3E6C1FD
)

// s2, s3 and s4 are the rotated substitution tables, built once.
var s2, s3, s4 [256]byte

func init() {
	for i := 0; i < 256; i++ {
		s2[i] = bits.RotateLeft8(sbox1[i], 1)
		s3[i] = bits.RotateLeft8(sbox1[i], 7)
		s4[i] = sbox1[bits.RotateLeft8(uint8(i), 1)]
	}
}

// f is Camellia's round function (RFC 3713 section 2.4.1).
//
// Eight substitutions and then the P-function, which is eight
// exclusive-ors over subsets of the substituted bytes. The subsets
// are transcribed from the RFC rather than factored, because the
// pattern is the specification and a tidier form would be a different
// thing to check.
func f(in, ke uint64) uint64 {
	x := in ^ ke
	t1 := sbox1[byte(x>>56)]
	t2 := s2[byte(x>>48)]
	t3 := s3[byte(x>>40)]
	t4 := s4[byte(x>>32)]
	t5 := s2[byte(x>>24)]
	t6 := s3[byte(x>>16)]
	t7 := s4[byte(x>>8)]
	t8 := sbox1[byte(x)]

	y1 := t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
	y2 := t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
	y3 := t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
	y4 := t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
	y5 := t1 ^ t2 ^ t6 ^ t7 ^ t8
	y6 := t2 ^ t3 ^ t5 ^ t7 ^ t8
	y7 := t3 ^ t4 ^ t5 ^ t6 ^ t8
	y8 := t1 ^ t4 ^ t5 ^ t6 ^ t7

	return uint64(y1)<<56 | uint64(y2)<<48 |
		uint64(y3)<<40 | uint64(y4)<<32 |
		uint64(y5)<<24 | uint64(y6)<<16 |
		uint64(y7)<<8 | uint64(y8)
}

// fl and flInv are the key-dependent linear layers applied every six
// rounds (RFC 3713 section 2.4.1). They are each other's inverse,
// which is what lets decryption reuse the same subkeys in reverse.
func fl(in, ke uint64) uint64 {
	x1 := uint32(in >> 32)
	x2 := uint32(in)
	k1 := uint32(ke >> 32)
	k2 := uint32(ke)
	x2 ^= bits.RotateLeft32(x1&k1, 1)
	x1 ^= x2 | k2
	return uint64(x1)<<32 | uint64(x2)
}

func flInv(in, ke uint64) uint64 {
	y1 := uint32(in >> 32)
	y2 := uint32(in)
	k1 := uint32(ke >> 32)
	k2 := uint32(ke)
	y1 ^= y2 | k2
	y2 ^= bits.RotateLeft32(y1&k1, 1)
	return uint64(y1)<<32 | uint64(y2)
}

// rotl128 rotates a 128-bit value, held as a pair of 64-bit halves,
// left by n bits. The key schedule is defined entirely in terms of
// these rotations.
func rotl128(hi, lo uint64, n uint) (uint64, uint64) {
	n %= 128
	if n == 0 {
		return hi, lo
	}
	if n < 64 {
		return hi<<n | lo>>(64-n), lo<<n | hi>>(64-n)
	}
	n -= 64
	if n == 0 {
		return lo, hi
	}
	return lo<<n | hi>>(64-n), hi<<n | lo>>(64-n)
}

// cipherState is an expanded key.
//
// The subkeys are held as 64-bit halves in the order the rounds use
// them: two whitening keys at each end, the round keys in between,
// and the FL/FLINV keys at the two or three places they apply.
type cipherState struct {
	kw [4]uint64
	k  []uint64
	ke []uint64
}

// NewCipher returns a Camellia block cipher for a 16, 24 or 32-octet
// key.
//
// Kerberos uses only 16 and 32 -- camellia128 and camellia256 -- but
// 24 is in the specification and costs one branch, and leaving it out
// would mean a cipher that silently refused a key length the RFC
// defines.
func NewCipher(key []byte) (cipher.Block, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf(
			"camellia: key is %d octets, want 16, 24 "+
				"or 32", len(key))
	}
	return expand(key), nil
}

// expand runs the key schedule (RFC 3713 section 2.2).
func expand(key []byte) *cipherState {
	klHi, klLo, krHi, krLo := keyHalves(key)
	kaHi, kaLo := deriveKA(klHi, klLo, krHi, krLo)
	c := &cipherState{}
	if len(key) == 16 {
		schedule128(c, klHi, klLo, kaHi, kaLo)
		return c
	}
	kbHi, kbLo := deriveKB(kaHi, kaLo, krHi, krLo)
	schedule256(c, klHi, klLo, krHi, krLo, kaHi, kaLo,
		kbHi, kbLo)
	return c
}

// keyHalves splits the key into KL and KR (RFC 3713 section 2.2).
//
// A 192-bit key is the odd case: KR's low half is the **complement**
// of its high half, which is how a 24-octet key is stretched to the
// 32 octets the schedule wants.
func keyHalves(key []byte) (uint64, uint64, uint64, uint64) {
	be := binary.BigEndian.Uint64
	klHi, klLo := be(key[0:8]), be(key[8:16])
	switch len(key) {
	case 16:
		return klHi, klLo, 0, 0
	case 24:
		hi := be(key[16:24])
		return klHi, klLo, hi, ^hi
	}
	return klHi, klLo, be(key[16:24]), be(key[24:32])
}

// deriveKA is the first half of the schedule.
func deriveKA(
	klHi, klLo, krHi, krLo uint64,
) (uint64, uint64) {
	d1 := klHi ^ krHi
	d2 := klLo ^ krLo
	d2 ^= f(d1, sigma1)
	d1 ^= f(d2, sigma2)
	d1 ^= klHi
	d2 ^= klLo
	d2 ^= f(d1, sigma3)
	d1 ^= f(d2, sigma4)
	return d1, d2
}

// deriveKB is the second half, needed only for 192 and 256-bit keys.
func deriveKB(
	kaHi, kaLo, krHi, krLo uint64,
) (uint64, uint64) {
	d1 := kaHi ^ krHi
	d2 := kaLo ^ krLo
	d2 ^= f(d1, sigma5)
	d1 ^= f(d2, sigma6)
	return d1, d2
}

// pair is one 128-bit schedule value rotated, split into halves.
type pair struct{ hi, lo uint64 }

// rot rotates a schedule value left by n bits.
func rot(p pair, n uint) pair {
	hi, lo := rotl128(p.hi, p.lo, n)
	return pair{hi, lo}
}

// schedule128 lays out the eighteen-round subkeys for a 128-bit key
// (RFC 3713 section 2.2).
//
// Transcribed from the RFC's own list rather than generated. The
// rotations are irregular -- 0, 15, 30, 45, 60, 77, 94, 111 -- and
// which of KL and KA each one comes from is irregular too: k9 is the
// *high* half of KA rotated 45 while k10 is the *low* half of KL
// rotated 60, with no pattern joining them. A loop that produced this
// would be harder to check against the specification than the list
// is, and the specification is the only thing that can check it.
func schedule128(c *cipherState, klHi, klLo, kaHi, kaLo uint64) {
	kl := pair{klHi, klLo}
	ka := pair{kaHi, kaLo}
	kw1 := rot(kl, 0)
	kw3 := rot(ka, 111)
	c.kw = [4]uint64{kw1.hi, kw1.lo, kw3.hi, kw3.lo}

	ka0, ka15, ka45 := rot(ka, 0), rot(ka, 15), rot(ka, 45)
	ka60, ka94 := rot(ka, 60), rot(ka, 94)
	kl15, kl45 := rot(kl, 15), rot(kl, 45)
	kl60, kl94 := rot(kl, 60), rot(kl, 94)
	kl111 := rot(kl, 111)
	c.k = []uint64{
		ka0.hi, ka0.lo, kl15.hi, kl15.lo,
		ka15.hi, ka15.lo, kl45.hi, kl45.lo,
		ka45.hi, kl60.lo, ka60.hi, ka60.lo,
		kl94.hi, kl94.lo, ka94.hi, ka94.lo,
		kl111.hi, kl111.lo,
	}
	ka30, kl77 := rot(ka, 30), rot(kl, 77)
	c.ke = []uint64{ka30.hi, ka30.lo, kl77.hi, kl77.lo}
}

// schedule256 lays out the twenty-four-round subkeys for a 192 or
// 256-bit key (RFC 3713 section 2.2).
//
// Four schedule values rather than two, and the same irregularity:
// transcribed, for the same reason.
func schedule256(
	c *cipherState,
	klHi, klLo, krHi, krLo, kaHi, kaLo, kbHi, kbLo uint64,
) {
	kl := pair{klHi, klLo}
	kr := pair{krHi, krLo}
	ka := pair{kaHi, kaLo}
	kb := pair{kbHi, kbLo}
	kw1 := rot(kl, 0)
	kw3 := rot(kb, 111)
	c.kw = [4]uint64{kw1.hi, kw1.lo, kw3.hi, kw3.lo}

	kb0, kb30, kb60 := rot(kb, 0), rot(kb, 30), rot(kb, 60)
	kr15, kr60, kr94 := rot(kr, 15), rot(kr, 60), rot(kr, 94)
	ka15, ka45, ka94 := rot(ka, 15), rot(ka, 45), rot(ka, 94)
	kl45, kl77, kl111 := rot(kl, 45), rot(kl, 77),
		rot(kl, 111)
	c.k = []uint64{
		kb0.hi, kb0.lo, kr15.hi, kr15.lo,
		ka15.hi, ka15.lo, kb30.hi, kb30.lo,
		kl45.hi, kl45.lo, ka45.hi, ka45.lo,
		kr60.hi, kr60.lo, kb60.hi, kb60.lo,
		kl77.hi, kl77.lo, kr94.hi, kr94.lo,
		ka94.hi, ka94.lo, kl111.hi, kl111.lo,
	}
	kr30, kl60, ka77 := rot(kr, 30), rot(kl, 60), rot(ka, 77)
	c.ke = []uint64{
		kr30.hi, kr30.lo, kl60.hi, kl60.lo,
		ka77.hi, ka77.lo,
	}
}

// BlockSize is Camellia's block size.
func (c *cipherState) BlockSize() int { return BlockSize }

// Encrypt transforms one block (RFC 3713 section 2.3).
//
// Eighteen or twenty-four Feistel rounds with the key-dependent
// linear layer every six, and whitening at both ends. The halves are
// swapped on output -- the ciphertext is D2 then D1 -- which is the
// detail that makes the same loop run backwards for decryption.
func (c *cipherState) Encrypt(dst, src []byte) {
	d1 := binary.BigEndian.Uint64(src[0:8])
	d2 := binary.BigEndian.Uint64(src[8:16])
	d1 ^= c.kw[0]
	d2 ^= c.kw[1]
	d1, d2 = c.rounds(d1, d2, false)
	d2 ^= c.kw[2]
	d1 ^= c.kw[3]
	binary.BigEndian.PutUint64(dst[0:8], d2)
	binary.BigEndian.PutUint64(dst[8:16], d1)
}

// Decrypt is Encrypt with the subkeys in reverse, which works because
// FL and FLINV are inverses and the Feistel structure is its own
// inverse under reversal.
func (c *cipherState) Decrypt(dst, src []byte) {
	d1 := binary.BigEndian.Uint64(src[0:8])
	d2 := binary.BigEndian.Uint64(src[8:16])
	d1 ^= c.kw[2]
	d2 ^= c.kw[3]
	d1, d2 = c.rounds(d1, d2, true)
	d2 ^= c.kw[0]
	d1 ^= c.kw[1]
	binary.BigEndian.PutUint64(dst[0:8], d2)
	binary.BigEndian.PutUint64(dst[8:16], d1)
}

// rounds runs the Feistel network forwards or backwards.
func (c *cipherState) rounds(
	d1, d2 uint64,
	back bool,
) (uint64, uint64) {
	n := len(c.k)
	for i := 0; i < n; i++ {
		r := i
		if back {
			r = n - 1 - i
		}
		if i > 0 && i%6 == 0 {
			d1, d2 = c.linear(d1, d2, i/6-1, back)
		}
		if i%2 == 0 {
			d2 ^= f(d1, c.k[r])
		} else {
			d1 ^= f(d2, c.k[r])
		}
	}
	return d1, d2
}

// linear applies FL to one half and FLINV to the other, which is what
// happens between every sixth and seventh round.
//
// **Going backwards the keys reverse element by element, not pair by
// pair**, and that is the whole of the difference: decryption is the
// same network with every subkey list reversed, so the pair used at
// the first boundary is (ke4, ke3) and not (ke3, ke4). Reversing by
// pair instead leaves encryption correct and decryption wrong, which
// is exactly what RFC 3713's vectors caught here -- all three
// ciphertexts matched and none of them decrypted.
func (c *cipherState) linear(
	d1, d2 uint64,
	group int,
	back bool,
) (uint64, uint64) {
	a, b := c.ke[2*group], c.ke[2*group+1]
	if back {
		n := len(c.ke)
		a, b = c.ke[n-1-2*group], c.ke[n-2-2*group]
	}
	return fl(d1, a), flInv(d2, b)
}
