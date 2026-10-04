package crypto

import (
	"bytes"
	"testing"
)

// The n-fold vectors from RFC 3961, taken from upstream's own
// lib/crypto/crypto_tests/t_nfold.c rather than retyped from the RFC.
func TestNfold(t *testing.T) {
	cases := []struct {
		in     string
		outLen int
		want   string
	}{
		{"012345", 8, "BE072631276B1955"},
		{"password", 7, "78A07B6CAF85FA"},
		{"Rough Consensus, and Running Code", 8,
			"BB6ED30870B7F0E0"},
		{"password", 21,
			"59E4A8CA7C0385C3C37B3F6D2000247C" +
				"B6E6BD5B3E"},
		{
			"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
			24,
			"DB3B0D8F0B061E603282B308A5084122" +
				"9AD798FAB9540C1B",
		},
	}

	for _, tc := range cases {
		got := nfold([]byte(tc.in), tc.outLen)
		if want := hx(tc.want); !bytes.Equal(got, want) {
			t.Errorf("nfold(%q, %d)\n got %X\nwant %X",
				tc.in, tc.outLen, got, want)
		}
	}
}

// n-fold of a 16-byte input to 16 bytes is the identity, which is the
// case the key-derivation path relies on: a constant already the
// block size is used verbatim.
func TestNfoldSameLengthIsIdentity(t *testing.T) {
	in := []byte("sixteen bytes!!!")
	if got := nfold(in, len(in)); !bytes.Equal(got, in) {
		t.Errorf("nfold(x, len(x)) = %X, want %X", got, in)
	}
}

func TestGCD(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{8, 6, 2},
		{21, 8, 1},
		{16, 16, 16},
		{24, 37, 1},
	}
	for _, tc := range cases {
		if got := gcd(tc.a, tc.b); got != tc.want {
			t.Errorf("gcd(%d, %d) = %d, want %d",
				tc.a, tc.b, got, tc.want)
		}
	}
}
