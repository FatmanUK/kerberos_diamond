package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/FatmanUK/diamond_krb/internal/camellia"
)

// newCamellia is the block-cipher constructor for the RFC 6803 rows.
//
// It exists as a row field rather than a call inside the shared
// layout functions because those functions are shared: sealDK and
// openDK are the same message layout for RFC 3962 and RFC 6803, and
// the only difference is which cipher and which MAC. A switch inside
// them would have to be repeated in every one.
func newCamellia(key []byte) (cipher.Block, error) {
	return camellia.NewCipher(key)
}

// macCMAC is the keyed MAC of the RFC 6803 family: CMAC under the
// block cipher, with no truncation at all (krb5int_cmac_checksum
// through krb5int_dk_cmac_checksum,
// lib/crypto/krb/checksum_dk_cmac.c:43-57; cksumtypes.c:86-97 gives
// both lengths as 16).
//
// Where the HMAC families take a prefix of a longer hash, the CMAC
// output *is* the block size and the trailer is the whole of it.
func macCMAC(p *EncProfile, key, msg []byte) ([]byte, error) {
	b, err := p.newBlock(key)
	if err != nil {
		return nil, err
	}
	return camellia.CMAC(b, msg), nil
}

// deriveFeedbackCMAC is SP 800-108 in **feedback** mode with CMAC as
// the PRF (k5_sp800_108_feedback_cmac,
// lib/crypto/builtin/kdf.c:76-137), which is what RFC 6803 derives
// every subkey with.
//
// Feedback, not counter: each block's input begins with the previous
// block's output, where RFC 8009's KDF-HMAC-SHA2 is counter mode and
// has no such chaining. The two are easy to confuse because both are
// "SP 800-108" and both put a counter, the label, a NUL and the
// output length in the input -- so a port that reused the counter
// mode here would produce plausible keys that no peer agrees with.
//
// The output length is not free. Upstream refuses anything but the
// cipher's key length (kdf.c:86-87), and the length also travels
// inside the derivation as [L]2, so a shorter request would not
// merely be a prefix.
func deriveFeedbackCMAC(
	p *EncProfile,
	base, label []byte,
	outLen int,
) ([]byte, error) {
	if len(base) != p.KeyLength || outLen != p.KeyLength {
		return nil, fmt.Errorf(
			"%w: %s derives %d from %d, not %d from %d",
			ErrUnsupported, p.Name, p.KeyLength,
			p.KeyLength, outLen, len(base))
	}
	b, err := p.newBlock(base)
	if err != nil {
		return nil, err
	}
	return feedback(b, label, outLen), nil
}

// feedback is the loop itself: K(i) = CMAC(key, K(i-1) || [i]2 ||
// label || 0x00 || context || [L]2), with K(0) all zeros, an empty
// context and [L]2 the output length **in bits**.
func feedback(b cipher.Block, label []byte, outLen int) []byte {
	in := make([]byte, 0, camellia.BlockSize+4+len(label)+5)
	prev := make([]byte, camellia.BlockSize)
	// label || 0x00 || context || [L]2, with the context empty.
	// The label's own length is whatever it is -- five octets for
	// a key usage, three for "prf" -- so the separator's position
	// is not a constant.
	tail := make([]byte, len(label)+1+4)
	copy(tail, label)
	binary.BigEndian.PutUint32(
		tail[len(label)+1:], uint32(outLen)*8)

	out := make([]byte, 0, outLen+camellia.BlockSize)
	for i := uint32(1); len(out) < outLen; i++ {
		in = append(in[:0], prev...)
		in = binary.BigEndian.AppendUint32(in, i)
		in = append(in, tail...)
		prev = camellia.CMAC(b, in)
		out = append(out, prev...)
	}
	return out[:outLen]
}

// prfCMAC is the RFC 6803 family's pseudo-random function
// (krb5int_dk_cmac_prf, lib/crypto/krb/prf_cmac.c:29-57):
//
//	CMAC(DK(key, "prf"), input)
//
// The input is **not** hashed first, which is the one place this
// differs from prfDK in a way that looks like an omission. RFC 3962's
// PRF has to hash because it then encrypts a single block and so
// needs a fixed-length input; CMAC takes any length, so there is
// nothing to compress.
//
// Upstream publishes no test vector for it -- t_prf.c has no Camellia
// case and neither does any other file in the tree -- so this is the
// one part of the enctype anchored by reading the C rather than by
// comparison. It is reached only by FAST, whose armor key carries its
// own enctype.
func prfCMAC(p *EncProfile, key, in []byte) ([]byte, error) {
	kp, err := p.derive(p, key, []byte("prf"), p.KeyLength)
	if err != nil {
		return nil, err
	}
	b, err := p.newBlock(kp)
	if err != nil {
		return nil, err
	}
	return camellia.CMAC(b, in)[:p.PRFLength], nil
}
