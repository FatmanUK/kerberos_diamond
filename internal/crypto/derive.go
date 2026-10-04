package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
)

// The trailing byte of a derivation constant, which selects what the
// derived key is for. RFC 3961 section 5.3.
const (
	constKc = 0x99 // the checksum key
	constKe = 0xAA // the encryption key
	constKi = 0x55 // the integrity key
)

// usageConstant builds the five-byte derivation constant for a key
// usage: the usage as a four-byte big-endian integer, then the byte
// saying which of the three keys is wanted.
func usageConstant(u Usage, which byte) []byte {
	c := make([]byte, 5)
	binary.BigEndian.PutUint32(c, uint32(u))
	c[4] = which
	return c
}

// deriveRandom is DR() of RFC 3961 section 5.1: n-fold the constant
// to the cipher's block size, then encrypt repeatedly, feeding each
// block's output back in, until enough bytes have been produced.
//
// The encryption is a single block at a time through the CTS path,
// which for one block is CBC with a zero IV -- see cts.go. That is
// why the single-block quirk is load-bearing rather than a curiosity.
func deriveRandom(
	key, constant []byte,
	keyBytes int,
) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()

	// A constant already the block size is used as it stands;
	// anything else is folded to that size first.
	in := constant
	if len(in) != bs {
		in = nfold(constant, bs)
	}

	out := make([]byte, 0, keyBytes+bs)
	for len(out) < keyBytes {
		next, err := ctsEncrypt(block, nil, in)
		if err != nil {
			return nil, err
		}
		out = append(out, next...)
		in = next
	}
	return out[:keyBytes], nil
}

// deriveKey is DK() of RFC 3961 section 5.1: random-to-key(DR(key,
// constant)).
//
// For the AES types random-to-key is the identity, so this is DR with
// the output taken as a key directly. It is kept as its own step
// because the DES3 types do fix parity bits here, and a later enctype
// family will need somewhere to do its own.
func deriveKey(
	key, constant []byte,
	keyBytes int,
) ([]byte, error) {
	if len(key) != keyBytes {
		return nil, fmt.Errorf(
			"key is %d bytes, want %d",
			len(key), keyBytes)
	}
	return deriveRandom(key, constant, keyBytes)
}
