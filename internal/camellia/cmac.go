package camellia

import (
	"crypto/cipher"
	"crypto/subtle"
)

// CMACSize is a CMAC tag's length, which is one block.
//
// Kerberos uses the whole thing: camellia128-cts-cmac and
// camellia256-cts-cmac both have a 16-octet trailer, where the
// aes-sha1 enctypes truncate their HMAC to 12.
const CMACSize = BlockSize

// rb is the constant the subkeys are derived with, which is the
// representation of the field polynomial for a 128-bit block (RFC
// 4493 section 2.3). For a 64-bit block it would be 0x1b; CMAC is
// defined for both and Kerberos needs only this one.
const rb = 0x87

// CMAC computes the tag over msg (RFC 4493, generalised from AES to
// any 128-bit block cipher by RFC 4494's structure and used that way
// by RFC 6803 section 3).
//
// Two subkeys are derived from the encryption of a zero block, and
// which one is used depends on whether the message is a whole number
// of blocks: K1 when it is, K2 when it is not. **The empty message is
// not a whole number of blocks** for this purpose -- it takes K2 and
// a padded block -- which is the case a reimplementation gets wrong
// by treating zero length as zero blocks.
func CMAC(b cipher.Block, msg []byte) []byte {
	k1, k2 := subkeys(b)
	n := (len(msg) + BlockSize - 1) / BlockSize
	last := make([]byte, BlockSize)
	switch {
	case n == 0:
		// The empty message: one padded block under K2.
		n = 1
		pad(last, nil)
		xorInto(last, k2)
	case len(msg)%BlockSize == 0:
		copy(last, msg[(n-1)*BlockSize:])
		xorInto(last, k1)
	default:
		pad(last, msg[(n-1)*BlockSize:])
		xorInto(last, k2)
	}
	x := make([]byte, BlockSize)
	for i := 0; i < n-1; i++ {
		xorInto(x, msg[i*BlockSize:(i+1)*BlockSize])
		b.Encrypt(x, x)
	}
	xorInto(x, last)
	b.Encrypt(x, x)
	return x
}

// VerifyCMAC compares a tag in constant time, so that a caller cannot
// accidentally compare with bytes.Equal.
func VerifyCMAC(b cipher.Block, msg, tag []byte) bool {
	return subtle.ConstantTimeCompare(CMAC(b, msg), tag) == 1
}

// subkeys derives K1 and K2 from the encryption of a zero block (RFC
// 4493 section 2.3).
//
// Each is a left shift of the previous value, with the field
// polynomial folded in when the shifted-out bit was set -- a doubling
// in GF(2^128). The conditional is written as a mask rather than a
// branch because it depends on key material.
func subkeys(b cipher.Block) ([]byte, []byte) {
	l := make([]byte, BlockSize)
	b.Encrypt(l, l)
	k1 := double(l)
	return k1, double(k1)
}

// double is multiplication by x in GF(2^128).
func double(in []byte) []byte {
	out := make([]byte, BlockSize)
	carry := byte(0)
	for i := BlockSize - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	// carry is the bit shifted off the top, and the fold is
	// applied only when it was set. The multiply keeps it
	// constant-time.
	out[BlockSize-1] ^= rb * carry
	return out
}

// pad appends the 1-bit-then-zeroes padding RFC 4493 specifies.
func pad(out, in []byte) {
	n := copy(out, in)
	out[n] = 0x80
	for i := n + 1; i < BlockSize; i++ {
		out[i] = 0
	}
}

// xorInto exclusive-ors src into dst.
func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}
