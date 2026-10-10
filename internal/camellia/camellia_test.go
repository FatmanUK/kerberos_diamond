package camellia

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// unhex decodes a vector.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(
		strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad vector: %v", err)
	}
	return b
}

// The vectors from RFC 3713's appendix, which are the whole reason
// writing this cipher out was bounded work: one plaintext, three key
// lengths, three published ciphertexts.
//
// They check the substitution table, all three key schedules, the
// round function, the P-function, both linear layers and the
// whitening at once -- and nothing short of them would, because every
// intermediate value in a block cipher is as opaque as the output.
func TestRFC3713Vectors(t *testing.T) {
	for _, c := range rfc3713Cases() {
		t.Run(c.why, func(t *testing.T) {
			b, err := NewCipher(unhex(t, c.key))
			if err != nil {
				t.Fatal(err)
			}
			in := unhex(t, rfc3713Plain)
			want := unhex(t, c.cipher)
			got := make([]byte, BlockSize)
			b.Encrypt(got, in)
			if !bytes.Equal(got, want) {
				t.Fatalf("encrypted to %X, "+
					"want %X", got, want)
			}
			back := make([]byte, BlockSize)
			b.Decrypt(back, got)
			if !bytes.Equal(back, in) {
				t.Errorf("decrypted to %X, want %X",
					back, in)
			}
		})
	}
}

// rfc3713Plain is the one plaintext all three vectors encrypt, and
// rfc3713Cases the three keys with what it becomes under each.
//
// They are out of line only because the test would otherwise run past
// the function-length rule; the values are RFC 3713 section A's in
// its order.
const rfc3713Plain = "01 23 45 67 89 ab cd ef " +
	"fe dc ba 98 76 54 32 10"

type rfc3713Case struct {
	why    string
	key    string
	cipher string
}

func rfc3713Cases() []rfc3713Case {
	return []rfc3713Case{
		{"128-bit key",
			rfc3713Plain,
			"67 67 31 38 54 96 69 73 " +
				"08 57 06 56 48 ea be 43"},
		{"192-bit key",
			rfc3713Plain + " 00 11 22 33 44 55 66 77",
			"b4 99 34 01 b3 e9 96 f8 " +
				"4e e5 ce e7 d7 9b 09 b9"},
		{"256-bit key",
			rfc3713Plain + " 00 11 22 33 44 55 66 77 " +
				"88 99 aa bb cc dd ee ff",
			"9a cc 23 7d ff 16 d7 6c " +
				"20 ef 7c 91 9e 3a 75 09"},
	}
}

// The substitution table is checked against the first and last values
// RFC 3713 section 2.4.1 prints, so that a transcription slip in the
// middle of 256 entries is at least bounded by two anchors the
// vectors also cover.
func TestTheSubstitutionTable(t *testing.T) {
	if sbox1[0] != 112 || sbox1[1] != 130 ||
		sbox1[2] != 44 || sbox1[3] != 236 {
		t.Errorf("starts %v", sbox1[:4])
	}
	if sbox1[255] != 158 {
		t.Errorf("ends %d", sbox1[255])
	}
	// And the three derived tables are rotations, which is the
	// property that makes storing one of them enough.
	for i := 0; i < 256; i++ {
		if s2[i] != rotl8(sbox1[i], 1) {
			t.Fatalf("s2[%d]", i)
		}
		if s3[i] != rotl8(sbox1[i], 7) {
			t.Fatalf("s3[%d]", i)
		}
		if s4[i] != sbox1[rotl8(byte(i), 1)] {
			t.Fatalf("s4[%d]", i)
		}
	}
}

// rotl8 is an 8-bit rotation, written out so the test does not share
// the implementation's own helper.
func rotl8(b byte, n uint) byte {
	return b<<n | b>>(8-n)
}

// A key of the wrong length is refused rather than padded or
// truncated.
func TestBadKeyLengths(t *testing.T) {
	for _, n := range []int{0, 8, 15, 17, 23, 31, 33, 64} {
		if _, err := NewCipher(
			make([]byte, n)); err == nil {
			t.Errorf("accepted %d octets", n)
		}
	}
}
