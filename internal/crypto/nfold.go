package crypto

// nfold spreads in over outLen bytes, by the n-fold operation of RFC
// 3961 section 5.1.
//
// The definition is
//
//	l = lcm(n, k)
//	r = l / k
//	s = in | rot13(in) | rot13²(in) | ... | rot13^(r-1)(in)
//	n-fold = the one's-complement sum of s in n-byte chunks
//
// and the loop below is a transliteration of upstream's
// lib/crypto/krb/nfold.c, which computes it without materialising s.
// It is written as one pass that, for each byte of the notional s,
// works out which bit of in that byte starts at.
//
// Translated rather than rewritten on purpose: the arithmetic is
// where every independent implementation of n-fold goes wrong, and a
// readable version that disagrees with upstream by one rotation is
// worth nothing.
func nfold(in []byte, outLen int) []byte {
	inLen := len(in)
	out := make([]byte, outLen)
	if inLen == 0 || outLen == 0 {
		return out
	}

	lcm := outLen * inLen / gcd(outLen, inLen)
	acc := 0
	// Cycles through in lcm/k times, which is r.
	for i := lcm - 1; i >= 0; i-- {
		msbit := bitOffset(inLen, i)
		// The byte straddles two of in's bytes.
		hi := int(in[((inLen-1)-(msbit>>3))%inLen])
		lo := int(in[(inLen-(msbit>>3))%inLen])
		acc += ((hi<<8 | lo) >> ((msbit & 7) + 1)) & 0xFF

		acc += int(out[i%outLen])
		out[i%outLen] = byte(acc & 0xFF)
		acc >>= 8
	}

	// A carry out of the top wraps around and is added back in,
	// which is what makes this a one's-complement sum.
	for i := outLen - 1; acc != 0 && i >= 0; i-- {
		acc += int(out[i])
		out[i] = byte(acc & 0xFF)
		acc >>= 8
	}
	return out
}

// bitOffset gives the bit of in at which the i'th byte of the
// notional rotated-and-concatenated string begins.
//
// The three terms are: the most significant bit of the first,
// unrotated copy; a shift right by 13 bits for each whole repetition
// passed; and the position of the wanted byte within that repetition.
func bitOffset(inLen, i int) int {
	bits := inLen << 3
	return (bits - 1 +
		(bits+13)*(i/inLen) +
		(inLen-(i%inLen))<<3) % bits
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
