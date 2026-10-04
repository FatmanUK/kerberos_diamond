package crypto

import "encoding/hex"

// hx decodes a hex literal, for test vectors.
//
// The vectors are written as hex strings rather than byte slices
// because a 32-byte key as {0x..., 0x...} needs five lines inside a
// table literal and will not fit the column limit; as a string it is
// one line and reads the way the source it was copied from does.
func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex in a test vector: " + s)
	}
	return b
}
