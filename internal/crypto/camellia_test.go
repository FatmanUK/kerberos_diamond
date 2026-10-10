package crypto

import (
	"bytes"
	"strings"
	"testing"
)

// The two base keys every derivation vector below uses, which are
// also the string-to-key results for "password" with the salt
// ATHENA.MIT.EDUraeburn at one iteration -- so a failure in the first
// test invalidates the second rather than two tests failing
// independently.
const (
	cam128Base = "57D0297298FFD9D35DE5A47FB4BDE24B"
	cam256Base = "B9D6828B2056B7BE656D88A123B1FAC6" +
		"8214AC2B727ECF5F69AFE0C4DF2A6D2C"
)

// Kc, Ke and Ki for both Camellia enctypes at usage 2, from
// upstream's own t_derive.c:140-200.
//
// These are the vectors that distinguish SP 800-108 **feedback** mode
// from the counter mode RFC 8009 uses: the two have the same inputs
// and produce different bytes, so a port that reached for the wrong
// one passes nothing here.
func TestCamelliaDerivation(t *testing.T) {
	for _, c := range []struct {
		enc  EncType
		base string
		kind byte
		want string
	}{
		{Camellia128CTSCMAC, cam128Base, constKc,
			"D155775A209D05F02B38D42A389E5A56"},
		{Camellia128CTSCMAC, cam128Base, constKe,
			"64DF83F85A532F17577D8C37035796AB"},
		{Camellia128CTSCMAC, cam128Base, constKi,
			"3E4FBDF30FB8259C425CB6C96F1F4635"},
		{Camellia256CTSCMAC, cam256Base, constKc,
			"E467F9A9552BC7D3155A6220AF9C1922" +
				"0EEED4FF78B0D1E6A1544991461A9E50"},
		{Camellia256CTSCMAC, cam256Base, constKe,
			"412AEFC362A7285FC3966C6A5181E760" +
				"5AE675235B6D549FBFC9AB6630A4C604"},
		{Camellia256CTSCMAC, cam256Base, constKi,
			"FA624FA0E523993FA388AEFDC67E67EB" +
				"CD8C08E8A0246B1D73B0D1DD9FC582B0"},
	} {
		p, err := Profile(c.enc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.derive(p, hx(c.base),
			usageConstant(2, c.kind), p.KeyLength)
		if err != nil {
			t.Fatalf("%s %#x: %v", p.Name, c.kind, err)
		}
		if want := hx(c.want); !bytes.Equal(got, want) {
			t.Errorf("%s %#x:\n got %X\nwant %X",
				p.Name, c.kind, got, want)
		}
	}
}

// The string-to-key vectors from t_str2key.c:252-390 -- RFC 3961's
// own inputs applied to the Camellia enctypes, which is upstream's
// framing of them.
//
// They pin three things at once that could each go wrong silently:
// the PBKDF2 hash is **SHA-1** and not the family's MAC, because
// upstream's hash field is NULL here and pbkdf2_string_to_key
// substitutes SHA-1 (s2k_pbkdf2.c:163); the salt is peppered with the
// enctype's own name (:190-203); and the result is run through the
// feedback derivation with the label "kerberos".
func TestCamelliaStringToKey(t *testing.T) {
	for _, c := range camS2KCases() {
		p, err := Profile(c.enc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.stringToKeyIter(c.pw,
			[]byte(c.salt), c.iter)
		if err != nil {
			t.Fatalf("%s %q: %v", p.Name, c.salt, err)
		}
		if want := hx(c.want); !bytes.Equal(got, want) {
			t.Errorf("%s %q %d:\n got %X\nwant %X",
				p.Name, c.salt, c.iter, got, want)
		}
	}
}

// camS2KCase is one row of t_str2key.c, and camS2KCases the Camellia
// block of it. They are a function rather than a table literal so
// that the test above stays inside the function-length rule.
type camS2KCase struct {
	enc  EncType
	pw   string
	salt string
	iter uint32
	want string
}

// The salts the vectors use. octets is a salt that is not text at
// all, which is legal -- the field is octets and upstream's vector
// uses binary -- and clef is U+1D11E, the password that is one astral
// character.
const (
	raeburn = "ATHENA.MIT.EDUraeburn"
	equals  = "pass phrase equals block size"
	exceeds = "pass phrase exceeds block size"
	octets  = "\x12\x34\x56\x78\x78\x56\x34\x12"
	clef    = "\xf0\x9d\x84\x9e"
)

func camS2KCases() []camS2KCase {
	return append(camS2KPassword(), camS2KPhrases()...)
}

// camS2KPassword is the half of the table whose password is the word
// "password", varying the salt and the iteration count.
func camS2KPassword() []camS2KCase {
	return []camS2KCase{
		{Camellia128CTSCMAC, "password", raeburn, 1,
			cam128Base},
		{Camellia256CTSCMAC, "password", raeburn, 1,
			cam256Base},
		{Camellia128CTSCMAC, "password", raeburn, 2,
			"73F1B53AA0F310F93B1DE8CCAA0CB152"},
		{Camellia256CTSCMAC, "password", raeburn, 2,
			"83FC5866E5F8F4C6F38663C65C87549F" +
				"342BC47ED394DC9D3CD4D163ADE375E3"},
		{Camellia128CTSCMAC, "password", raeburn, 1200,
			"8E571145452855575FD916E7B04487AA"},
		{Camellia256CTSCMAC, "password", raeburn, 1200,
			"77F421A6F25E138395E837E5D85D385B" +
				"4C1BFD772E112CD9208CE72A530B15E6"},
		{Camellia128CTSCMAC, "password", octets, 5,
			"00498FD916BFC1C2B1031C170801B381"},
		{Camellia256CTSCMAC, "password", octets, 5,
			"11083A00BDFE6A41B2F19716D6202F0A" +
				"FA94289AFE8B27A049BD28B1D76C389A"},
	}
}

// camS2KPhrases is the other half: a pass phrase at the block size
// and one past it, and a password that is a single astral character.
func camS2KPhrases() []camS2KCase {
	return []camS2KCase{
		{Camellia128CTSCMAC, strings.Repeat("X", 64),
			equals, 1200,
			"8BF6C3EF709B981DBB585D086843BE05"},
		{Camellia256CTSCMAC, strings.Repeat("X", 64),
			equals, 1200,
			"119FE2A1CB0B1BE010B9067A73DB63ED" +
				"4665B4E53A98D178035DCFE843A6B9B0"},
		{Camellia128CTSCMAC, strings.Repeat("X", 65),
			exceeds, 1200,
			"5752AC8D6AD1CCFE8430B312871C2F74"},
		{Camellia256CTSCMAC, strings.Repeat("X", 65),
			exceeds, 1200,
			"614D5DFC0BA6D390B412B89AE4D5B088" +
				"B612B316510994679DDB4383C7126DDF"},
		{Camellia128CTSCMAC, clef, "EXAMPLE.COMpianist", 50,
			"CC75C7FD260F1C1658011FCC0D560616"},
		{Camellia256CTSCMAC, clef, "EXAMPLE.COMpianist", 50,
			"163B768C6DB148B4EEC7163DF5AED70E" +
				"206B68CEC078BC069ED68A7ED36B1ECC"},
	}
}

// camCksumCase is one row of the keyed-checksum table below.
type camCksumCase struct {
	enc   EncType
	key   string
	usage Usage
	msg   string
	want  string
}

func camCksumCases() []camCksumCase {
	return []camCksumCase{
		{Camellia128CTSCMAC,
			"1DC46A8D763F4F93742BCBA3387576C3", 7,
			"abcdefghijk",
			"1178E6C5C47A8C1AE0C4B9C7D4EB7B6B"},
		{Camellia128CTSCMAC,
			"5027BC231D0F3A9D23333F1CA6FDBE7C", 8,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"D1B34F7004A731F23A0C00BF6C3F753A"},
		{Camellia256CTSCMAC,
			"B61C86CC4E5D2757545AD423399FB703" +
				"1ECAB913CBB900BD" +
				"7A3C6DD8BF92015B", 9,
			"123456789",
			"87A12CFD2B96214810F01C826E7744B1"},
		{Camellia256CTSCMAC,
			"32164C5B434D1D1538E4CFD9BE8040FE" +
				"8C4AC7ACC4B93D33" +
				"14D2133668147A05", 10,
			"!@#$%^&*()" + "!@#$%^&*()" +
				"!@#$%^&*()",
			"3FA0B42355E52B189187294AA252AB64"},
	}
}

// The keyed checksums from t_cksums.c:105-137, which are the only
// published vectors for the whole stack -- the feedback derivation of
// Kc at a real key usage, then a CMAC over the message, untruncated.
func TestCamelliaChecksum(t *testing.T) {
	for _, c := range camCksumCases() {
		p, err := Profile(c.enc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Checksum(hx(c.key), []byte(c.msg),
			c.usage)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if want := hx(c.want); !bytes.Equal(got, want) {
			t.Errorf("%s usage %d:\n got %X\nwant %X",
				p.Name, c.usage, got, want)
		}
		if err := p.VerifyChecksum(hx(c.key),
			[]byte(c.msg), got, c.usage); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
}

// Encryption has no published vector -- every ciphertext carries a
// fresh confounder, so there could not be one -- but the layout can
// still be pinned: it is RFC 3962's, so the ciphertext is exactly the
// block size of confounder, the plaintext's own length, and a
// sixteen-octet CMAC (krb5int_camellia_crypto_length,
// enc_dk_cmac.c:33-50).
//
// The lengths are the part a reimplementation gets wrong by assuming
// the trailer is truncated the way an HMAC's is.
func TestCamelliaRoundTrip(t *testing.T) {
	for _, e := range []EncType{
		Camellia128CTSCMAC, Camellia256CTSCMAC,
	} {
		p, err := Profile(e)
		if err != nil {
			t.Fatal(err)
		}
		if p.TrailerLength != 16 {
			t.Errorf("%s trailer is %d octets, want 16",
				p.Name, p.TrailerLength)
		}
		key, err := p.StringToKey("password",
			[]byte("saltysalt"), nil)
		if err != nil {
			t.Fatal(err)
		}
		camelliaLengths(t, p, key)
	}
}

func camelliaLengths(t *testing.T, p *EncProfile, key []byte) {
	t.Helper()
	// Lengths either side of the block size, because ciphertext
	// stealing is the interesting case at each of them.
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 100} {
		plain := bytes.Repeat([]byte{byte(n)}, n)
		ct, err := p.Encrypt(key, plain, UsageASRepEncPart)
		if err != nil {
			t.Fatalf("%s n=%d: %v", p.Name, n, err)
		}
		if got := len(ct); got != p.CipherLength(n) {
			t.Errorf("%s n=%d: %d octets, want %d",
				p.Name, n, got, p.CipherLength(n))
		}
		back, err := p.Decrypt(key, ct, UsageASRepEncPart)
		if err != nil {
			t.Fatalf("%s n=%d: %v", p.Name, n, err)
		}
		if !bytes.Equal(back, plain) {
			t.Errorf("%s n=%d: round trip changed it",
				p.Name, n)
		}
	}
}

// A name an operator types, and the alias upstream accepts for it
// (etypes.c:106 and :117).
func TestCamelliaNames(t *testing.T) {
	for name, want := range map[string]EncType{
		"camellia128-cts-cmac": Camellia128CTSCMAC,
		"camellia256-cts-cmac": Camellia256CTSCMAC,
		"camellia128-cts":      Camellia128CTSCMAC,
		"camellia256-cts":      Camellia256CTSCMAC,
	} {
		got, ok := EncTypeByName(name)
		if !ok || got != want {
			t.Errorf("%q gave %d, %v", name, got, ok)
		}
	}
}
