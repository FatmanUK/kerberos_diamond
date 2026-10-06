package crypto

import (
	"bytes"
	"testing"
)

// The RFC 8009 appendix A vectors, as upstream runs them in
// lib/crypto/crypto_tests/. They are the only thing that settles this
// family: every step of it -- the derivation, the pepper, the MAC
// input -- has a plausible wrong answer that round-trips against
// itself perfectly.

// The base keys the vectors start from.
var (
	sha2Base128 = hx("3705D96080C17728A0E800EAB6E0D23C")
	sha2Base256 = hx(
		"6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A0" +
			"26D16B7182460C52")
)

// sha2DeriveCases are the Kc/Ke/Ki vectors for usage 2, from
// upstream's t_derive.c:204-262.
var sha2DeriveCases = []struct {
	name  string
	enc   EncType
	base  []byte
	which byte
	want  []byte
}{
	{"aes128-sha256 Kc", AES128CTSHMACSHA256128,
		sha2Base128, constKc,
		hx("B31A018A48F54776F403E9A396325DC3")},
	{"aes128-sha256 Ke", AES128CTSHMACSHA256128,
		sha2Base128, constKe,
		hx("9B197DD1E8C5609D6E67C3E37C62C72E")},
	{"aes128-sha256 Ki", AES128CTSHMACSHA256128,
		sha2Base128, constKi,
		hx("9FDA0E56AB2D85E1569A688696C26A6C")},
	{"aes256-sha384 Kc", AES256CTSHMACSHA384192,
		sha2Base256, constKc,
		hx("EF5718BE86CC84963D8BBB5031E9F5C4" +
			"BA41F28FAF69E73D")},
	{"aes256-sha384 Ke", AES256CTSHMACSHA384192,
		sha2Base256, constKe,
		hx("56AB22BEE63D82D7BC5227F6773F8EA7" +
			"A5EB1C825160C38312980C442E5C7E49")},
	{"aes256-sha384 Ki", AES256CTSHMACSHA384192,
		sha2Base256, constKi,
		hx("69B16514E3CD8E56B82010D5C73012B6" +
			"22C4D00FFC23ED1F")},
}

// The derivation is the first thing that has to be right, and the
// lengths are part of it: for aes256-sha384 Ke is 32 bytes while Kc
// and Ki are 24. A family that derived all three at the key length
// would produce the right Ke and two wrong keys.
func TestDeriveSHA2(t *testing.T) {
	for _, tc := range sha2DeriveCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Profile(tc.enc)
			if err != nil {
				t.Fatal(err)
			}
			label := usageConstant(
				UsageKDCRepTicket, tc.which)
			got, err := p.derive(
				p, tc.base, label, len(tc.want))
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

// Ke is the key length and Ki is half the hash. Deriving both at one
// length is the obvious mistake and it produces a key nothing agrees
// with.
func TestSHA2SubkeyLengths(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA384192)
	if err != nil {
		t.Fatal(err)
	}
	ke, ki, err := p.subkeys(sha2Base256, UsageKDCRepTicket)
	if err != nil {
		t.Fatalf("subkeys: %v", err)
	}
	if len(ke) != 32 {
		t.Errorf("Ke is %d bytes, want 32", len(ke))
	}
	if len(ki) != 24 {
		t.Errorf("Ki is %d bytes, want 24", len(ki))
	}
}

// sha2S2KSalt is the salt RFC 8009 publishes with its string-to-key
// vectors. The sixteen-byte prefix is simply part of the salt; the
// enctype name the implementation peppers in front of it is not.
var sha2S2KSalt = append(
	hx("10DF9DD783E5BC8ACEA1730E74355F61"),
	[]byte("ATHENA.MIT.EDUraeburn")...)

// The string-to-key vectors, from t_str2key.c:413-437. Same password
// and same salt, two different keys -- which is the pepper working.
func TestStringToKeySHA2(t *testing.T) {
	cases := []struct {
		enc  EncType
		want []byte
	}{
		{AES128CTSHMACSHA256128,
			hx("089BCA48B105EA6EA77CA5D2F39DC5E7")},
		{AES256CTSHMACSHA384192,
			hx("45BD806DBF6A833A9CFFC1C94589A222" +
				"367A79BC21C413718906E9F578A78467")},
	}
	for _, tc := range cases {
		p, err := Profile(tc.enc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.StringToKey(
			"password", sha2S2KSalt, nil)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s\n got %X\nwant %X",
				p.Name, got, tc.want)
		}
	}
}

// The two aes-sha2 enctypes must derive *unrelated* keys from the
// same password and salt, because the pepper is the enctype's own
// name. A missing pepper would round-trip perfectly and make every
// key this derives disagree with every other implementation.
func TestPepperSeparatesTheSHA2Enctypes(t *testing.T) {
	salt := []byte("KDIAMOND.TESTuser")
	a := keyFor(t, AES128CTSHMACSHA256128, salt)
	b := keyFor(t, AES256CTSHMACSHA384192, salt)
	// A shared PBKDF2 input would show up as one key being the
	// other's prefix, because PBKDF2 over the same inputs at two
	// lengths agrees on the shorter.
	if bytes.Equal(a, b[:len(a)]) {
		t.Error("the two enctypes derived related keys")
	}
	// The sha1 family has no pepper at all, which is not the same
	// as an empty one, so it must differ too.
	c := keyFor(t, AES256CTSHMACSHA196, salt)
	if bytes.Equal(c, b) {
		t.Error("aes256-sha1 and aes256-sha2 keys match")
	}
}

func keyFor(t *testing.T, e EncType, salt []byte) []byte {
	t.Helper()
	p, err := Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	k, err := p.StringToKey("password", salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sha2DecryptCases are RFC 8009's published ciphertexts, from
// t_decrypt.c:410-503, all at key usage 2.
var sha2DecryptCases = []struct {
	name  string
	enc   EncType
	base  []byte
	plain []byte
	ct    []byte
}{
	{"aes128 empty", AES128CTSHMACSHA256128, sha2Base128,
		nil,
		hx("EF85FB890BB8472F4DAB20394DCA781D" +
			"AD877EDA39D50C870C0D5A0A8E48C718")},
	{"aes128 six bytes", AES128CTSHMACSHA256128,
		sha2Base128, hx("000102030405"),
		hx("84D7F30754ED987BAB0BF3506BEB09CF" +
			"B55402CEF7E6877CE99E247E52D16ED4" +
			"421DFDF8976C")},
	{"aes128 one block", AES128CTSHMACSHA256128,
		sha2Base128,
		hx("000102030405060708090A0B0C0D0E0F"),
		hx("3517D640F50DDC8AD3628722B3569D2A" +
			"E07493FA8263254080EA65C1008E8FC2" +
			"95FB4852E7D83E1E7C48C37EEBE6B0D3")},
	{"aes128 past a block", AES128CTSHMACSHA256128,
		sha2Base128,
		hx("000102030405060708090A0B0C0D0E0F1011121314"),
		hx("720F73B18D9859CD6CCB4346115CD336" +
			"C70F58EDC0C4437C5573544C31C813BC" +
			"E1E6D072C186B39A413C2F92CA9B8334" +
			"A287FFCBFC")},
	{"aes256 empty", AES256CTSHMACSHA384192, sha2Base256,
		nil,
		hx("41F53FA5BFE7026D91FAF9BE959195A0" +
			"58707273A96A40F0A01960621AC61274" +
			"8B9BBFBE7EB4CE3C")},
	{"aes256 six bytes", AES256CTSHMACSHA384192,
		sha2Base256, hx("000102030405"),
		hx("4ED7B37C2BCAC8F74F23C1CF07E62BC7" +
			"B75FB3F637B9F559C7F664F69EAB7B60" +
			"92237526EA0D1F61CB20D69D10F2")},
	{"aes256 one block", AES256CTSHMACSHA384192,
		sha2Base256,
		hx("000102030405060708090A0B0C0D0E0F"),
		hx("BC47FFEC7998EB91E8115CF8D19DAC4B" +
			"BBE2E163E87DD37F49BECA92027764F6" +
			"8CF51F14D798C2273F35DF574D1F932E" +
			"40C4FF255B36A266")},
	{"aes256 past a block", AES256CTSHMACSHA384192,
		sha2Base256,
		hx("000102030405060708090A0B0C0D0E0F1011121314"),
		hx("40013E2DF58E8751957D2878BCD2D6FE" +
			"101CCFD556CB1EAE79DB3C3EE86429F2" +
			"B2A602AC86FEF6ECB647D6295FAE077A" +
			"1FEB517508D2C16B4192E01F62")},
}

// Decrypting a published ciphertext is the only way to check this
// family end to end. The confounder is random, so an
// encrypt-and-compare is impossible, and an encrypt-then-decrypt
// round trip would pass happily with the MAC over entirely the wrong
// bytes.
func TestDecryptSHA2(t *testing.T) {
	for _, tc := range sha2DecryptCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Profile(tc.enc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.Decrypt(tc.base, tc.ct,
				UsageKDCRepTicket)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, tc.plain) {
				t.Errorf("\n got %X\nwant %X",
					got, tc.plain)
			}
		})
	}
}

// The checksum vectors, from t_cksums.c:139-162.
func TestChecksumSHA2(t *testing.T) {
	msg := hx("000102030405060708090A0B0C0D0E0F1011121314")
	cases := []struct {
		enc  EncType
		base []byte
		want []byte
	}{
		{AES128CTSHMACSHA256128, sha2Base128,
			hx("D78367186643D67B411CBA9139FC1DEE")},
		{AES256CTSHMACSHA384192, sha2Base256,
			hx("45EE791567EEFCA37F4AC1E0222DE80D" +
				"43C3BFA06699672A")},
	}
	for _, tc := range cases {
		p, err := Profile(tc.enc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Checksum(
			tc.base, msg, UsageKDCRepTicket)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s\n got %X\nwant %X",
				p.Name, got, tc.want)
		}
	}
}

// The integrity tag covers the ciphertext with a zero initialisation
// vector in front of it, and the vector is *present* rather than
// skipped. A tag over the ciphertext alone round-trips against itself
// and verifies against nothing else.
func TestETMTagIncludesTheIV(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA384192)
	if err != nil {
		t.Fatal(err)
	}
	ct := hx("000102030405060708090A0B0C0D0E0F")
	if bytes.Equal(p.etmTag(sha2Base256, ct),
		p.tag(sha2Base256, ct)) {
		t.Error("the tag does not include the IV")
	}
}

// Encrypt-then-MAC means a tampered ciphertext is refused before the
// cipher sees it, and the error has to be the integrity one rather
// than a length or padding complaint.
func TestSHA2RejectsTampering(t *testing.T) {
	for _, e := range []EncType{
		AES128CTSHMACSHA256128, AES256CTSHMACSHA384192,
	} {
		p, err := Profile(e)
		if err != nil {
			t.Fatal(err)
		}
		base := sha2BaseFor(t, p)
		ct, err := p.Encrypt(base, []byte("twelve bytes"),
			UsageASRepEncPart)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		ct[p.HeaderLength] ^= 0x01
		_, err = p.Decrypt(base, ct, UsageASRepEncPart)
		if err != ErrIntegrity {
			t.Errorf("%s: tampering gave %v, want %v",
				p.Name, err, ErrIntegrity)
		}
	}
}

func sha2BaseFor(t *testing.T, p *EncProfile) []byte {
	t.Helper()
	if p.KeyLength == 16 {
		return sha2Base128
	}
	return sha2Base256
}

// A round trip has to work at every length around the block boundary,
// because ciphertext stealing is where a length bug lives.
func TestSHA2RoundTrip(t *testing.T) {
	for _, e := range []EncType{
		AES128CTSHMACSHA256128, AES256CTSHMACSHA384192,
	} {
		p, err := Profile(e)
		if err != nil {
			t.Fatal(err)
		}
		roundTripEveryLength(t, p, sha2BaseFor(t, p))
	}
}

func roundTripEveryLength(
	t *testing.T,
	p *EncProfile,
	base []byte,
) {
	t.Helper()
	for n := 0; n <= 40; n++ {
		plain := bytes.Repeat([]byte{byte(n)}, n)
		ct, err := p.Encrypt(base, plain, UsageASRepEncPart)
		if err != nil {
			t.Fatalf("%s n=%d: %v", p.Name, n, err)
		}
		if len(ct) != p.CipherLength(n) {
			t.Errorf("%s n=%d: %d bytes, want %d",
				p.Name, n, len(ct), p.CipherLength(n))
		}
		got, err := p.Decrypt(base, ct, UsageASRepEncPart)
		if err != nil {
			t.Fatalf("%s n=%d: %v", p.Name, n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("%s n=%d: round trip changed it",
				p.Name, n)
		}
	}
}

// The aes-sha2 pair comes first in the table, which is the order a
// client is offered as this KDC's preference.
func TestSHA2IsPreferred(t *testing.T) {
	want := []EncType{
		AES256CTSHMACSHA384192, AES128CTSHMACSHA256128,
		AES256CTSHMACSHA196, AES128CTSHMACSHA196,
	}
	got := Supported()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d is %d, want %d",
				i, got[i], want[i])
		}
	}
}
