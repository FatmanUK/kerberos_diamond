package crypto

import (
	"bytes"
	"testing"
)

// The base keys the derivation vectors start from. These are
// themselves the string-to-key results for "password" with salt
// "ATHENA.MIT.EDUraeburn" at one iteration.
var (
	aes128Base = hx("42263C6E89F4FC28B8DF68EE09799F15")
	aes256Base = hx(
		"FE697B52BC0D3CE14432BA036A92E65B" +
			"BB52280990A2FA27883998D72AF30161")
)

// dkDeriveCases are the RFC 3961 Kc/Ke/Ki vectors, from upstream's
// lib/crypto/crypto_tests/t_derive.c.
var dkDeriveCases = []struct {
	name  string
	base  []byte
	which byte
	want  []byte
}{
	{"aes128 Kc", aes128Base, constKc,
		hx("34280A382BC92769B2DA2F9EF066854B")},
	{"aes128 Ke", aes128Base, constKe,
		hx("5B14FC4E250E14DDF9DCCF1AF6674F53")},
	{"aes128 Ki", aes128Base, constKi,
		hx("4ED31063621684F09AE8D89991AF3E8F")},
	{"aes256 Kc", aes256Base, constKc,
		hx("BFAB388BDCB238E9F9C98D6A878304F0" +
			"4D30C82556375AC507A7A852790F4674")},
	{"aes256 Ke", aes256Base, constKe,
		hx("C7CFD9CD75FE793A586A542D87E0D139" +
			"6F1134A104BB1A9190B8C90ADA3DDF37")},
	{"aes256 Ki", aes256Base, constKi,
		hx("97151B4C76945063E2EB0529DC067D97" +
			"D7BBA90776D8126D91F34F3101AEA8BA")},
}

func TestDeriveKey(t *testing.T) {
	for _, tc := range dkDeriveCases {
		t.Run(tc.name, func(t *testing.T) {
			p := sha1ProfileFor(t, len(tc.base))
			c := usageConstant(
				UsageKDCRepTicket, tc.which)
			got, err := p.derive(
				p, tc.base, c, len(tc.base))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("\n got %X\nwant %X",
					got, tc.want)
			}
		})
	}
}

// The derivation constant is the usage big-endian followed by the
// selector byte. Getting the byte order wrong derives a
// plausible-looking key that nothing else agrees with.
func TestUsageConstant(t *testing.T) {
	got := usageConstant(UsageKDCRepTicket, constKc)
	if want := hx("0000000299"); !bytes.Equal(got, want) {
		t.Errorf("got %X, want %X", got, want)
	}
	got = usageConstant(UsageASRepEncPart, constKe)
	if want := hx("00000003AA"); !bytes.Equal(got, want) {
		t.Errorf("got %X, want %X", got, want)
	}
}

// Kc, Ke and Ki for one usage must all differ: they are the whole
// reason the selector byte exists. A derivation that ignored it would
// still round-trip, and would still pass every encryption test here.
func TestDerivedKeysDiffer(t *testing.T) {
	var keys [][]byte
	for _, which := range []byte{constKc, constKe, constKi} {
		p := sha1ProfileFor(t, len(aes256Base))
		c := usageConstant(UsageASRepEncPart, which)
		k, err := p.derive(p, aes256Base, c, len(aes256Base))
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("keys %d and %d match", i, j)
			}
		}
	}
}

// Different usages must derive different keys, which is what keeps a
// ticket's enc-part key apart from the reply's.
func TestDifferentUsagesDiffer(t *testing.T) {
	p := sha1ProfileFor(t, 32)
	a, err := p.derive(p, aes256Base,
		usageConstant(UsageKDCRepTicket, constKe), 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.derive(p, aes256Base,
		usageConstant(UsageASRepEncPart, constKe), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("usages 2 and 3 derived the same key")
	}
}

// A key of the wrong length is a programming error, not something to
// derive from anyway.
func TestDeriveKeyChecksLength(t *testing.T) {
	p := sha1ProfileFor(t, 32)
	_, err := p.derive(p, aes128Base,
		usageConstant(UsageASRepEncPart, constKe), 32)
	if err == nil {
		t.Error("derived a 32-byte key from a 16-byte one")
	}
}

// sha1ProfileFor is the RFC 3962 row with the given key length.
//
// These vectors are that family's, so the row has to be chosen by key
// length rather than by whichever enctype happens to come first in
// the table -- the aes-sha2 rows have the same key lengths and an
// entirely different derivation.
func sha1ProfileFor(t *testing.T, keyLen int) *EncProfile {
	t.Helper()
	e := AES256CTSHMACSHA196
	if keyLen == 16 {
		e = AES128CTSHMACSHA196
	}
	p, err := Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
