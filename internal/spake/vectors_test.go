package spake

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
)

// vector is one of upstream's published SPAKE test vectors
// (plugins/preauth/spake/t_vectors.c), which pin **every**
// intermediate value: the multiplier, both private scalars, both
// masked public elements, the shared element, the transcript hash and
// all four derived keys.
//
// That is why SPAKE is in this project's plan and PKINIT is not.
// There is no oracle for either -- upstream's PKINIT backend is
// OpenSSL and its SPAKE group is built in but not reachable as a
// library -- but SPAKE comes with its own answers, published, down to
// each hash input. A reimplementation that agrees with these is right
// for the same reason agreeing with reference_encode.out is right:
// somebody else computed them.
type vector struct {
	why   string
	etype crypto.EncType

	ikey string // the client's long-term key
	w    string // the multiplier derived from it
	x    string // the KDC's private, after the cofactor shift
	y    string // the client's private, likewise
	tval string // the client's masked public, w*M + x*G
	s    string // the KDC's masked public, w*N + y*G
	k    string // the shared element

	support   string // the client's support message, encoded
	challenge string // the KDC's challenge, encoded
	thash     string // the transcript hash after both plus S
	body      string // the encoded KDC-REQ-BODY

	keys [4]string // K'[0] through K'[3]
}

// aesVectors are the two edwards25519 vectors for enctypes this
// project implements. The des3 and arcfour vectors upstream also
// publishes are skipped: both enctypes are deliberately absent here.
func aesVectors() []vector {
	return []vector{aes256Vector(), aes128Vector()}
}

// aes256Vector is t_vectors.c:133-157.
func aes256Vector() vector {
	v := vector{
		why:   "aes256-cts-hmac-sha1-96",
		etype: crypto.AES256CTSHMACSHA196,
		ikey: "01B897121D933AB44B47EB5494DB15E50EB74530DB" +
			"DAE9B634D65020FF5D88C1",
		w: "E902341590A1B4BB4D606A1C643CCCB3F2108F1B6AA9" +
			"7B381012B9400C9E3F4E",
		x: "88C6C0A4F0241EF217C9788F02C32D00B72E4310748C" +
			"D8FB5F94717607E6417D",
		y: "88B859DF58EF5C69BACDFE681C582754EAAB09A74DC2" +
			"9CFF50B328613C232F55",
		tval: "6F301AACAE1220E91BE42868C163C5009AEEA1E9D9" +
			"E28AFCFC339CDA5E7105B5",
		s: "9E2CC32908FC46273279EC75354B4AEAFA70C3D99A4D" +
			"507175ED70D80B255DDA",
		k: "CF57F58F6E60169D2ECC8F20BB923A8E4C16E5BC95B9" +
			"E64B5DC870DA7026321B",
		support: "A0093007A0053003020101",
		challenge: "A1363034A003020101A12204206F301AACAE12" +
			"20E91BE42868C163C5009AEEA1E9D9E28AFCFC339" +
			"CDA5E7105B5A20930073005A003020101",
		thash: "1C605649D4658B58CBE79A5FAF227ACC16C355C58B" +
			"7DADE022F90C158FE5ED8E",
		body: reaburnBody("12"),
	}
	v.keys = [4]string{
		"A9BFA71C95C575756F922871524B65288B3F6955" +
			"73CCC0633E87449568210C23",
		"1865A9EE1EF0640EC28AC007391CAC624C42639C" +
			"714767A974E99AA10003015F",
		"E57781513FEFDB978E374E156B0DA0C1A08148F5" +
			"EB26B8E157AC3C077E28BF49",
		"008E6487293C3CC9FABBBCDD8B392D6DCB882223" +
			"17FD7FE52D12FBC44FA047F1",
	}
	return v
}

// reaburnBody is the encoded KDC-REQ-BODY every vector uses, which
// differs between them in one place only: the trailing enctype.
//
// It is a real request from upstream's own fixture -- client
// `raeburn', realm ATHENA.MIT.EDU, server krbtgt/ATHENA.MIT.EDU --
// and it matters to the derivation rather than being decoration:
// DeriveKey hashes the body, so a key derived for one request cannot
// be used with another.
func reaburnBody(etype string) string {
	return "3075A00703050000000000A1143012A003020101A10B" +
		"30091B07726165627572" +
		"6EA2101B0E415448454E412E4D49542E454455A32" +
		"33021A003020102A11A3018" +
		"1B066B72627467741B0E415448454E412E4D49542" +
		"E454455A511180F31393730" +
		"303130313030303030305AA703020100A80530030" +
		"201" + etype
}

// aes128Vector is t_vectors.c:109-132.
func aes128Vector() vector {
	return vector{
		why:   "aes128-cts-hmac-sha1-96",
		etype: crypto.AES128CTSHMACSHA196,
		ikey:  "FCA822951813FB252154C883F5EE1CF4",
		w: "0D591B197B667E083C2F5F98AC891D3C9F99E710E464" +
			"E62F1FB7C9B67936F3EB",
		x: "50BE049A5A570FA1459FB9F666E6FD80602E4E87790A" +
			"0E567F12438A2C96C138",
		y: "B877AFE8612B406D96BE85BD9F19D423E95BE96C0E1E" +
			"0B5824127195C3ED5917",
		tval: "9E9311D985C1355E022D7C3C694AD8D6F7AD6D647B" +
			"68A90B0FE46992818002DA",
		s: "FBE08F7F96CD5D4139E7C9ECCB95E79B8ACE41E270A6" +
			"0198C007DF18525B628E",
		k: "C2F7F99997C585E6B686CEB62DB42F17CC70932DEF3B" +
			"B4CF009E36F22EA5473D",
		support: "A0093007A0053003020101",
		challenge: "A1363034A003020101A12204209E9311D985C1" +
			"355E022D7C3C694AD8D6F7AD6D647B68A90B0FE46" +
			"992818002DAA20930073005A003020101",
		thash: "951285F107C87F0169B9C918A1F51F60CB1A75B9F8" +
			"BB799A99F53D03ADD94B5F",
		body: reaburnBody("11"),
		keys: [4]string{
			"548022D58A7C47EAE8C49DCCF6BAA407",
			"B2C9BA0E13FC8AB3A9D96B51B601CF4A",
			"69F0EE5FDB6C237E7FCD38D9F87DF1BD",
			"78F91E2240B5EE528A5CC8D7CBEBFBA5",
		},
	}
}

// unhex decodes a vector field.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(
		strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad vector: %v", err)
	}
	return b
}

// The multiplier, derived from the client's long-term key.
func TestDeriveWMatchesTheVectors(t *testing.T) {
	for _, v := range aesVectors() {
		t.Run(v.why, func(t *testing.T) {
			got, err := DeriveW(unhex(t, v.ikey),
				v.etype, GroupEdwards25519)
			if err != nil {
				t.Fatal(err)
			}
			want := unhex(t, v.w)
			if !bytes.Equal(got, want) {
				t.Errorf("got  %X\nwant %X", got,
					want)
			}
		})
	}
}

// privateFrom turns one of the vectors' private scalars back into the
// form this package keeps.
//
// The vectors publish the scalar **after** upstream's cofactor shift,
// and this package keeps the one before it -- see Private for why.
// The two are related by a factor of eight, so recovering one from
// the other is a multiplication by the inverse of eight modulo the
// group order, and that is all this does.
func privateFrom(t *testing.T, raw []byte) *Private {
	t.Helper()
	var wide [64]byte
	copy(wide[:32], raw)
	shifted, err := new(edwards25519.Scalar).SetUniformBytes(
		wide[:])
	if err != nil {
		t.Fatal(err)
	}
	inv := new(edwards25519.Scalar).Invert(eight())
	return &Private{
		s: new(edwards25519.Scalar).Multiply(shifted, inv),
	}
}

// Both masked public elements: the client's T = w*M + x*G and the
// KDC's S = w*N + y*G.
//
// This is the assertion that catches the cofactor handling. The
// private scalars in the vectors are already multiplied by eight, and
// recovering the unshifted scalar and shifting it again has to land
// on the same point -- which it does only if the group arithmetic is
// right in both directions.
func TestPublicElementsMatchTheVectors(t *testing.T) {
	for _, v := range aesVectors() {
		t.Run(v.why, func(t *testing.T) {
			w := unhex(t, v.w)
			// x is the KDC's private and T its public,
			// masked with M; y is the client's and S its
			// public, masked with N. The naming is
			// upstream's and the pairing is not the
			// obvious one.
			assertPublic(t, w, v.x, v.tval, true)
			assertPublic(t, w, v.y, v.s, false)
		})
	}
}

// assertPublic checks one side's masked public element.
func assertPublic(
	t *testing.T,
	w []byte,
	priv, want string,
	useM bool,
) {
	t.Helper()
	_, pub, err := publicFor(privateFrom(t, unhex(t, priv)),
		w, useM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, unhex(t, want)) {
		t.Errorf("got  %X\nwant %s", pub, want)
	}
}

// The shared element, computed from each side and agreeing.
//
// Both directions matter: the KDC computes K from its own private and
// the client's T, and the client computes the same K from its private
// and the KDC's S. A group implementation can get one right and the
// other wrong by confusing M with N.
func TestTheSharedElementMatchesTheVectors(t *testing.T) {
	for _, v := range aesVectors() {
		t.Run(v.why, func(t *testing.T) {
			w := unhex(t, v.w)
			want := unhex(t, v.k)
			// The KDC holds x and receives S, and unmasks
			// with the client's constant N -- which is
			// why useM is false on this side and true on
			// the other.
			kdc, err := Result(
				privateFrom(t, unhex(t, v.x)), w,
				unhex(t, v.s), false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(kdc, want) {
				t.Errorf("kdc side: %X", kdc)
			}
			cl, err := Result(
				privateFrom(t, unhex(t, v.y)), w,
				unhex(t, v.tval), true)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cl, want) {
				t.Errorf("client side: %X", cl)
			}
		})
	}
}

// The transcript hash, after the support message, the challenge, and
// then the client's public element on its own.
//
// Two things in it are easy to get wrong and both are pinned here.
// The hash starts as **a block of zeroes**, not as nothing
// (util.c:80-87), so the first update already hashes thirty-two zero
// octets in front of the support message. And the second update
// passes the client's element as the first of its two arguments with
// the second absent, which is an empty string rather than a skipped
// input.
func TestTheTranscriptHashMatchesTheVectors(t *testing.T) {
	for _, v := range aesVectors() {
		t.Run(v.why, func(t *testing.T) {
			h := UpdateThash(nil, unhex(t, v.support),
				unhex(t, v.challenge))
			h = UpdateThash(h, unhex(t, v.s), nil)
			if !bytes.Equal(h, unhex(t, v.thash)) {
				t.Errorf("got  %X\nwant %s", h,
					v.thash)
			}
		})
	}
}

// And all four derived keys, which is the assertion that covers
// everything at once: the nine hash inputs in order, the block
// counter starting at one, the random-to-key step, and the CF2 with
// the initial key under the pepper pair "SPAKE" and "keyderiv".
//
// K'[0] is the strengthened reply key and K'[1] seals the response's
// factor field. K'[2] and K'[3] are for second-factor rounds that
// neither this project nor upstream implements -- and they are
// checked anyway, because getting the round number into the right
// place in the input is exactly the kind of thing that works for n=0
// and n=1 by luck.
func TestTheDerivedKeysMatchTheVectors(t *testing.T) {
	for _, v := range aesVectors() {
		t.Run(v.why, func(t *testing.T) {
			for n := range v.keys {
				assertDerived(t, v, uint32(n))
			}
		})
	}
}

// assertDerived checks K'[n].
func assertDerived(t *testing.T, v vector, n uint32) {
	t.Helper()
	got, err := DeriveKey(unhex(t, v.ikey), v.etype,
		GroupEdwards25519, unhex(t, v.w), unhex(t, v.k),
		unhex(t, v.thash), unhex(t, v.body), n)
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, v.keys[n])
	if !bytes.Equal(got, want) {
		t.Errorf("K'[%d] is\n %X\nwant\n %X", n, got, want)
	}
}

// A freshly generated exchange agrees with itself, which is the
// property the vectors cannot check: they pin fixed scalars, and this
// pins that random ones work.
func TestAFreshExchangeAgrees(t *testing.T) {
	w := make([]byte, MultLen)
	for i := range w {
		w[i] = byte(i)
	}
	kdcPriv, kdcPub, err := Keygen(w, true)
	if err != nil {
		t.Fatal(err)
	}
	clPriv, clPub, err := Keygen(w, false)
	if err != nil {
		t.Fatal(err)
	}
	// Each side unmasks with the other's constant.
	a, err := Result(kdcPriv, w, clPub, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Result(clPriv, w, kdcPub, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("the two sides disagree:\n%X\n%X", a, b)
	}
	// And a different multiplier -- a different password -- does
	// not agree, which is the whole point of the exchange.
	w2 := append([]byte(nil), w...)
	w2[0] ^= 1
	wrong, err := Result(kdcPriv, w2, clPub, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, wrong) {
		t.Error("a wrong multiplier agreed anyway")
	}
}

// An element that is not a point is refused rather than producing
// nonsense. Upstream checks the same thing and says in a comment that
// it deliberately does *not* check subgroup membership, because the
// private scalar's cofactor handles it (edwards25519.c:1700-1705).
func TestANonPointIsRefused(t *testing.T) {
	w := make([]byte, MultLen)
	priv, _, err := Keygen(w, true)
	if err != nil {
		t.Fatal(err)
	}
	// Two octets off the right length, and a 32-octet string
	// whose y-coordinate has no square root on the curve. All
	// ones is *not* such a string -- it decodes to a point --
	// which is worth knowing, because "obviously invalid" and
	// "not a point" are different sets.
	notAPoint := make([]byte, ElemLen)
	notAPoint[0] = 2
	for _, bad := range [][]byte{
		nil,
		make([]byte, ElemLen-1),
		make([]byte, ElemLen+1),
		notAPoint,
	} {
		if _, err := Result(priv, w, bad,
			false); err == nil {
			t.Errorf("accepted %d octets: % x",
				len(bad), bad)
		}
	}
}

// The vectors' own encoded support and challenge messages, which
// double as byte-exact anchors for the ASN.1.
//
// They are there because the transcript hash is computed over them,
// so upstream had to publish the encodings to publish the hash --
// which makes them reference encodings for the message codec as well,
// and the only ones there are: upstream's asn.1 test suite has no
// PA-SPAKE entries.
func TestTheMessageEncodingsMatchTheVectors(t *testing.T) {
	v := aes256Vector()
	t.Run("support", func(t *testing.T) {
		want := unhex(t, v.support)
		got, err := MarshalMessage(Message{
			Type: MsgSupport,
			Support: &Support{
				Groups: []int32{GroupEdwards25519},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got  %X\nwant %X", got, want)
		}
	})
	t.Run("challenge", func(t *testing.T) {
		want := unhex(t, v.challenge)
		got, err := MarshalMessage(Message{
			Type: MsgChallenge,
			Challenge: &Challenge{
				Group:  GroupEdwards25519,
				PubKey: unhex(t, v.tval),
				Factors: []Factor{
					{Type: SFNone},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got  %X\nwant %X", got, want)
		}
	})
}

// And both decode back to what they were.
func TestTheMessagesDecodeBack(t *testing.T) {
	v := aes256Vector()
	m, err := UnmarshalMessage(unhex(t, v.support))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != MsgSupport || m.Support == nil ||
		len(m.Support.Groups) != 1 ||
		m.Support.Groups[0] != GroupEdwards25519 {
		t.Errorf("support decoded as %+v", m)
	}
	m, err = UnmarshalMessage(unhex(t, v.challenge))
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != MsgChallenge || m.Challenge == nil {
		t.Fatalf("challenge decoded as %+v", m)
	}
	if !bytes.Equal(m.Challenge.PubKey, unhex(t, v.tval)) {
		t.Errorf("pubkey is %X", m.Challenge.PubKey)
	}
	if len(m.Challenge.Factors) != 1 ||
		m.Challenge.Factors[0].Type != SFNone {
		t.Errorf("factors are %v", m.Challenge.Factors)
	}
}

// An arm nobody recognises is refused rather than ignored: a CHOICE
// with an unknown arm cannot be acted on, and guessing which of the
// four was meant would be worse than refusing.
func TestAnUnknownArmIsRefused(t *testing.T) {
	for _, bad := range [][]byte{
		nil,
		{0x30, 0x00},
		{0xA4, 0x00},
		{0xA9, 0x00},
		{0xA0, 0x01},
	} {
		if _, err := UnmarshalMessage(bad); err == nil {
			t.Errorf("accepted % x", bad)
		}
	}
}
