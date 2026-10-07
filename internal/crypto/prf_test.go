package crypto

import (
	"bytes"
	"testing"
)

// prfVectors is every case in upstream's t_prf.c
// (lib/crypto/crypto_tests/t_prf.c:36-115), which asserts its own
// expected values rather than printing them -- so unlike the CTS
// vectors these are a real anchor and not a round trip.
//
// All four of this project's enctypes are represented, and the two
// families differ in output length as well as in method: sixteen
// bytes for the RFC 3962 types, the whole hash for the aes-sha2 pair.
var prfVectors = []struct {
	etype EncType
	key   string
	in    string
	want  string
}{
	{AES128CTSHMACSHA196,
		"AE272E7CDEC86AC5138CDB196D8E297D",
		"0161",
		"77B39A37A868920F2A51F9DD150C5717"},
	{AES128CTSHMACSHA196,
		"67AB1CFEF35E4C27FFDEAC60385A3E9C",
		"0162",
		"E06C0DD31FF02091994F2EF5178BFE3D"},
	{AES256CTSHMACSHA196,
		"C01F157211F7B77EAAF457C3E1566901" +
			"27EE127D810BA6392E97BAA243EB0616",
		"0161",
		"B2628C788E2E9C4A9BB4644678C29F2F"},
	{AES256CTSHMACSHA196,
		"C01F157211F7B77EAAF457C3E1566901" +
			"27EE127D810BA6392E97BAA243EB0616",
		"0261",
		"B406373350CEE8A6126F4A9B65A0CD21"},
	{AES256CTSHMACSHA196,
		"9D520D2D980AA7CB6B693682B62DA258" +
			"B333867951642CE647AE62B1E5E0B5E9",
		"0162",
		"FF0E289EA756C0559A0E911856961A49"},
	{AES256CTSHMACSHA196,
		"9D520D2D980AA7CB6B693682B62DA258" +
			"B333867951642CE647AE62B1E5E0B5E9",
		"0262",
		"0D674DD0F9A6806525A4D92E828BD15A"},
	{AES128CTSHMACSHA256128,
		"3705D96080C17728A0E800EAB6E0D23C",
		"74657374",
		"9D188616F63852FE86915BB840B4A886" +
			"FF3E6BB0F819B49B893393D393854295"},
	{AES256CTSHMACSHA384192,
		"6D404D37FAF79F9DF0D33568D3206698" +
			"00EB4836472EA8A026D16B7182460C52",
		"74657374",
		"9801F69A368C2BF675E59521E177D9A0" +
			"7F67EFE1CFDE8D3C8D6F6A0256E3B17D" +
			"B3C1B62AD1B8553360D17367EB1514D2"},
}

func TestPRFMatchesUpstreamsVectors(t *testing.T) {
	for _, v := range prfVectors {
		p, err := Profile(v.etype)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.PRF(hx(v.key), hx(v.in))
		if err != nil {
			t.Errorf("%s: %v", p.Name, err)
			continue
		}
		if want := hx(v.want); !bytes.Equal(got, want) {
			t.Errorf("%s PRF(%s):\n got %X\nwant %X",
				p.Name, v.in, got, want)
		}
		if len(got) != p.PRFLength {
			t.Errorf("%s produced %d bytes, want %d",
				p.Name, len(got), p.PRFLength)
		}
	}
}

// cf2Vectors is upstream's t_cf2.in with t_cf2.expected
// (lib/crypto/crypto_tests/), minus the two enctypes this project
// does not implement.
//
// The inputs are keys derived with string-to-key where the *password
// is also the salt*, which is what t_cf2.c does (t_cf2.c:66-78):
// krb5_c_string_to_key is handed the same krb5_data twice. Spelling
// that out matters because a wrong salt gives a wrong key and the
// failure would look like a fault in CF2.
var cf2Vectors = []struct {
	etype EncType
	want  string
}{
	{AES128CTSHMACSHA196,
		"97DF97E4B798B29EB31ED7280287A92A"},
	{AES256CTSHMACSHA196,
		"4D6CA4E629785C1F01BAF55E2E548566" +
			"B9617AE3A96868C337CB93B5E72B1C7B"},
	{AES128CTSHMACSHA256128,
		"EDD02A39D2DBDE31611C16E610BE062C"},
	{AES256CTSHMACSHA384192,
		"67F6EA530AEA85A37DCBB23349EA52DC" +
			"C61CA8493FF557252327FD8304341584"},
}

func TestCF2MatchesUpstreamsVectors(t *testing.T) {
	for _, v := range cf2Vectors {
		p, err := Profile(v.etype)
		if err != nil {
			t.Fatal(err)
		}
		k1, err := p.StringToKey(
			"key1", []byte("key1"), nil)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := p.StringToKey(
			"key2", []byte("key2"), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.CF2(k1, "a", p, k2, "b")
		if err != nil {
			t.Errorf("%s: %v", p.Name, err)
			continue
		}
		if want := hx(v.want); !bytes.Equal(got, want) {
			t.Errorf("%s CF2:\n got %X\nwant %X",
				p.Name, got, want)
		}
	}
}

// The peppers are what stop two uses of CF2 colliding, so the same
// pair of keys under different peppers must give unrelated results.
// Without that the armor key and the strengthened reply key would be
// the same value computed twice.
//
// They also decide whether the order of the two keys matters, and the
// answer is a property worth stating: CF2 is an XOR of two PRF+
// values, so with *equal* peppers it is symmetric in its keys and
// swapping them changes nothing. Every use in RFC 6113 passes two
// different peppers, which is what makes the order significant -- the
// armor key is CF2(subkey, "subkeyarmor", session key, "ticketarmor")
// and not the same thing with the keys the other way round.
func TestCF2DependsOnThePeppers(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	k1 := make([]byte, p.KeyLength)
	k2 := make([]byte, p.KeyLength)
	for i := range k1 {
		k1[i], k2[i] = byte(i), byte(255-i)
	}
	cf2 := func(a []byte, pa string, b []byte, pb string) []byte {
		out, err := p.CF2(a, pa, p, b, pb)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	armor := cf2(k1, "subkeyarmor", k2, "ticketarmor")
	if bytes.Equal(armor,
		cf2(k1, "strengthenkey", k2, "strengthenkey")) {
		t.Error("two uses of CF2 gave one key")
	}
	if !bytes.Equal(cf2(k1, "same", k2, "same"),
		cf2(k2, "same", k1, "same")) {
		t.Error("equal peppers are not symmetric after all")
	}
	if bytes.Equal(armor,
		cf2(k2, "subkeyarmor", k1, "ticketarmor")) {
		t.Error("the key order did not matter")
	}
}

// PRF+ produces as many bytes as asked for, and its blocks are the
// PRF of a counter-prefixed input -- so the first PRFLength bytes
// have to be exactly PRF(k, 1||input).
func TestPRFPlusIsCounteredPRF(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA384192)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, p.KeyLength)
	for i := range key {
		key[i] = byte(i)
	}
	out, err := p.PRFPlus(key, []byte("input"), p.PRFLength*2+5)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != p.PRFLength*2+5 {
		t.Fatalf("got %d bytes", len(out))
	}
	first, err := p.PRF(key, append([]byte{1}, "input"...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[:p.PRFLength], first) {
		t.Error("the first block is not PRF(k, 1||input)")
	}
	second, err := p.PRF(key, append([]byte{2}, "input"...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[p.PRFLength:p.PRFLength*2], second) {
		t.Error("the second block is not PRF(k, 2||input)")
	}
}

// The counter is one octet, so PRF+ cannot produce more than 255
// blocks. Upstream refuses rather than wrapping, which matters: a
// wrapped counter would repeat earlier output with nothing to say so.
func TestPRFPlusRefusesTooMuch(t *testing.T) {
	p, err := Profile(AES128CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, p.KeyLength)
	_, err = p.PRFPlus(key, nil, p.PRFLength*256)
	if err == nil {
		t.Error("PRF+ produced more than 255 blocks")
	}
}

// A key of the wrong length is refused rather than used. The PRF is
// reached with keys from several sources during a FAST exchange and a
// silently truncated one would give plausible wrong bytes.
func TestPRFRefusesAWrongKeyLength(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.PRF(make([]byte, 16), nil); err == nil {
		t.Error("a 16-byte key was accepted for aes256")
	}
}

// CF2 across two enctypes, which is the case upstream's vectors
// cannot reach: every line of t_cf2.in uses one enctype for both
// keys, so there is no published anchor and these assertions come
// from reading cf2.c:139-153. The C read is the only authority until
// a differential case drives a real encrypted-challenge key.
//
// It is reached in practice, which is why it matters: the KDC
// combines the armor key with *every* long-term key a client's
// request listed (kdc/kdc_preauth_ec.c:99-111), and a realm holding
// all four enctypes mixes them on the second iteration.
func TestCF2AcrossTwoEnctypes(t *testing.T) {
	long, err := Profile(AES256CTSHMACSHA384192)
	if err != nil {
		t.Fatal(err)
	}
	short, err := Profile(AES128CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	k1 := filled(long.KeyLength, 0x11)
	k2 := filled(short.KeyLength, 0x22)

	// A shorter second key is accepted. The first version of CF2
	// refused this outright, because it ran k2's PRF+ under k1's
	// profile and the length check rejected a 16-byte key.
	out, err := long.CF2(k1, "a", short, k2, "b")
	if err != nil {
		t.Fatalf("a shorter second key was refused: %v", err)
	}
	// The output length belongs to the *first* key even when the
	// second's pseudo-random function produces it.
	if len(out) != long.KeyLength {
		t.Errorf("got %d bytes, want %d",
			len(out), long.KeyLength)
	}
	assertTheSecondProfileIsUsed(t, long, k1)
}

// assertTheSecondProfileIsUsed covers the dangerous case: two keys of
// the *same* length in different families.
//
// aes256-cts-hmac-sha1-96 and aes256-cts-hmac-sha384-192 are both 32
// bytes, so no length check can tell them apart, but their
// pseudo-random functions produce 16 and 48 bytes respectively.
// Running the second under the wrong profile returns plausible bytes
// no peer agrees with, and nothing errors.
func assertTheSecondProfileIsUsed(
	t *testing.T,
	long *EncProfile,
	k1 []byte,
) {
	t.Helper()
	sha1, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	k3 := filled(sha1.KeyLength, 0x33)
	right, err := long.CF2(k1, "a", sha1, k3, "b")
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := long.CF2(k1, "a", long, k3, "b")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(right, wrong) {
		t.Error("the second key's profile changed nothing, " +
			"so one of the two PRFs is unused")
	}
}

// filled is a key of a given length with a recognisable pattern, so a
// failure message says which key it came from.
func filled(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b ^ byte(i)
	}
	return out
}
