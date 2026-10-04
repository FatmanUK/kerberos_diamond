package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// iterParams renders an iteration count as s2kparams does.
func iterParams(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// The string-to-key vectors from RFC 3962 appendix B, taken from
// upstream's lib/crypto/crypto_tests/t_str2key.c rather than retyped
// from the RFC.
var s2kCases = []struct {
	enc      EncType
	password string
	salt     string
	iter     uint32
	want     string
}{
	{AES128CTSHMACSHA196, "password",
		"ATHENA.MIT.EDUraeburn", 1,
		"42263C6E89F4FC28B8DF68EE09799F15"},
	{AES256CTSHMACSHA196, "password",
		"ATHENA.MIT.EDUraeburn", 1,
		"FE697B52BC0D3CE14432BA036A92E65B" +
			"BB52280990A2FA27883998D72AF30161"},
	{AES128CTSHMACSHA196, "password",
		"ATHENA.MIT.EDUraeburn", 2,
		"C651BF29E2300AC27FA469D693BDDA13"},
	{AES256CTSHMACSHA196, "password",
		"ATHENA.MIT.EDUraeburn", 2,
		"A2E16D16B36069C135D5E9D2E25F8961" +
			"02685618B95914B467C67622225824FF"},
	{AES128CTSHMACSHA196, "password",
		"ATHENA.MIT.EDUraeburn", 1200,
		"4C01CD46D632D01E6DBE230A01ED642A"},
	{AES256CTSHMACSHA196, "password",
		"ATHENA.MIT.EDUraeburn", 1200,
		"55A6AC740AD17B4846941051E1E8B0A7" +
			"548D93B0AB30A8BC3FF16280382B8C2A"},
	{AES128CTSHMACSHA196, "password",
		"\x12\x34\x56\x78\x78\x56\x34\x12", 5,
		"E9B23D52273747DD5C35CB55BE619D8E"},
	{AES256CTSHMACSHA196, "password",
		"\x12\x34\x56\x78\x78\x56\x34\x12", 5,
		"97A4E786BE20D81A382D5EBC96D5909C" +
			"ABCDADC87CA48F574504159F16C36E31"},
}

func TestStringToKey(t *testing.T) {
	for _, tc := range s2kCases {
		p, err := Profile(tc.enc)
		if err != nil {
			t.Fatalf("Profile(%d): %v", tc.enc, err)
		}
		// These vectors use counts below the default, which
		// is exactly what the floor refuses, so the count
		// goes in directly rather than through s2kparams.
		got, err := p.stringToKeyIter(
			tc.password, []byte(tc.salt), tc.iter)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if want := hx(tc.want); !bytes.Equal(got, want) {
			t.Errorf("%s iter=%d\n got %X\nwant %X",
				p.Name, tc.iter, got, want)
		}
	}
}

// The default path, with no s2kparams, must use 4096 iterations.
func TestStringToKeyDefaultIterations(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("ATHENA.MIT.EDUraeburn")

	withDefault, err := p.StringToKey("password", salt, nil)
	if err != nil {
		t.Fatalf("StringToKey: %v", err)
	}
	explicit, err := p.stringToKeyIter("password", salt, 4096)
	if err != nil {
		t.Fatalf("stringToKeyIter: %v", err)
	}
	if !bytes.Equal(withDefault, explicit) {
		t.Errorf("no-params result is not 4096 iterations"+
			"\n got %X\nwant %X", withDefault, explicit)
	}
}

// An iteration count below the default arrives from the network, so
// honouring it would let a KDC talk a client into a one-iteration
// derivation. It must be refused.
func TestStringToKeyRefusesWeakIterations(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.StringToKey(
		"password", []byte("salt"), iterParams(1))
	if !errors.Is(err, ErrWeakIterations) {
		t.Errorf("accepted 1 iteration: %v", err)
	}
}

func TestIterationsBounds(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		params []byte
		ok     bool
	}{
		{"absent", nil, true},
		{"the default", iterParams(4096), true},
		{"above the default", iterParams(100000), true},
		{"zero", iterParams(0), false},
		{"below the default", iterParams(4095), false},
		{"over the maximum", iterParams(maxIterations + 1),
			false},
		{"wrong width", []byte{0, 0, 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.iterations(tc.params)
			if tc.ok && err != nil {
				t.Errorf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("accepted")
			}
		})
	}
}

// The default salt is realm followed by name components with no
// separator, which is what makes these two collide. The collision is
// upstream's behaviour, so it is pinned rather than fixed.
func TestSalt(t *testing.T) {
	cases := []struct {
		realm string
		comps []string
		want  string
	}{
		{"ATHENA.MIT.EDU", []string{"raeburn"},
			"ATHENA.MIT.EDUraeburn"},
		{"KDIAMOND.TEST", []string{"user"},
			"KDIAMOND.TESTuser"},
		{"KDIAMOND.TEST", []string{"host", "kdc.example"},
			"KDIAMOND.TESThostkdc.example"},
		{"EXAMPLE.COM", []string{"ab"}, "EXAMPLE.COMab"},
		{"EXAMPLE.COMa", []string{"b"}, "EXAMPLE.COMab"},
	}
	for _, tc := range cases {
		got := string(Salt(tc.realm, tc.comps))
		if got != tc.want {
			t.Errorf("Salt(%q, %q) = %q, want %q",
				tc.realm, tc.comps, got, tc.want)
		}
	}
}
