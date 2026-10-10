package camellia

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// RFC 4493's four inputs -- the empty message and the same message
// truncated to 0, 16, 40 and 64 octets -- keyed with Camellia-128
// instead of AES-128, which is upstream's own t_cmac.c and the only
// place a Camellia CMAC is published with its results.
//
// Upstream explains at t_cmac.c:33-39 why it does not check RFC
// 4493's AES results instead: the AES enc provider has no cbc_mac
// method, so krb5int_cmac_checksum cannot be driven with it. Here
// there is no such obstacle, so the AES side is checked too, below.
const cmacKey = "2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"

const cmacInput = "6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A " +
	"AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51 " +
	"30 C8 1C 46 A3 5C E4 11 E5 FB C1 19 1A 0A 52 EF " +
	"F6 9F 24 45 DF 4F 9B 17 AD 2B 41 7B E6 6C 37 10"

func TestCamelliaCMACVectors(t *testing.T) {
	b, err := NewCipher(unhex(t, cmacKey))
	if err != nil {
		t.Fatal(err)
	}
	msg := unhex(t, cmacInput)
	for _, c := range []struct {
		why  string
		n    int
		want string
	}{
		// The empty message is not zero blocks: it takes K2
		// and a padded block, which is the branch a
		// reimplementation gets wrong (t_cmac.c:62-66).
		{"the empty message", 0,
			"BA 92 57 82 AA A1 F5 D9 A0 0F 89 64 80 94 " +
				"FC 71"},
		{"one whole block", 16,
			"6D 96 28 54 A3 B9 FD A5 6D 7D 45 A9 5E E1 " +
				"79 93"},
		{"two blocks and a half", 40,
			"5C 18 D1 19 CC D6 76 61 44 AC 18 66 13 1D " +
				"9F 22"},
		{"four whole blocks", 64,
			"C2 69 9A 6E BA 55 CE 9D 93 9A 8A 4E 19 46 " +
				"6E E9"},
	} {
		t.Run(c.why, func(t *testing.T) {
			got := CMAC(b, msg[:c.n])
			want := unhex(t, c.want)
			if !bytes.Equal(got, want) {
				t.Errorf("got %X, want %X",
					got, want)
			}
			if !VerifyCMAC(b, msg[:c.n], want) {
				t.Error("VerifyCMAC disagreed")
			}
		})
	}
}

// And the same four messages against RFC 4493's own published AES
// results, which pin the construction rather than this project's
// Camellia: a CMAC that agreed with upstream's Camellia vectors but
// not with the RFC's AES ones would mean the fault was in the block
// cipher and the two bugs had cancelled.
//
// This is the check upstream says it did by hand but could not
// automate (t_cmac.c:33-39).
func TestRFC4493AESVectors(t *testing.T) {
	b, err := aes.NewCipher(unhex(t, cmacKey))
	if err != nil {
		t.Fatal(err)
	}
	msg := unhex(t, cmacInput)
	for _, c := range []struct {
		n    int
		want string
	}{
		{0, "BB 1D 69 29 E9 59 37 28 7F A3 7D 12 9B 75 " +
			"67 46"},
		{16, "07 0A 16 B4 6B 4D 41 44 F7 9B DD 9D D0 4A " +
			"28 7C"},
		{40, "DF A6 67 47 DE 9A E6 30 30 CA 32 61 14 97 " +
			"C8 27"},
		{64, "51 F0 BE BF 7E 3B 9D 92 FC 49 74 17 79 36 " +
			"3C FE"},
	} {
		got := CMAC(b, msg[:c.n])
		if want := unhex(t, c.want); !bytes.Equal(got, want) {
			t.Errorf("%d octets: got %X, want %X",
				c.n, got, want)
		}
	}
}

// Doubling in the field folds the polynomial in only when the top bit
// was set, which is the one branch in the subkey derivation and the
// one place a sign error hides.
func TestDoublingFoldsOnlyOnCarry(t *testing.T) {
	low := make([]byte, BlockSize)
	low[BlockSize-1] = 1
	if out := double(low); out[BlockSize-1] != 2 {
		t.Errorf("no carry: %X", out)
	}
	high := make([]byte, BlockSize)
	high[0] = 0x80
	out := double(high)
	if out[0] != 0 || out[BlockSize-1] != rb {
		t.Errorf("carry: %X", out)
	}
}

// An empty message and a single zero block are different messages,
// which is the observable consequence of the K1/K2 choice and the
// assertion that survives if the vectors above are ever reformatted.
func TestEmptyIsNotAZeroBlock(t *testing.T) {
	b, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(CMAC(b, nil),
		CMAC(b, make([]byte, BlockSize))) {
		t.Error("the empty message and a zero block agree")
	}
	if VerifyCMAC(b, nil, make([]byte, CMACSize)) {
		t.Error("VerifyCMAC accepted a zero tag")
	}
}
