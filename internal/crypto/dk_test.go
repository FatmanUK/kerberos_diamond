package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// The keyed-checksum vectors from upstream's
// lib/crypto/crypto_tests/t_cksums.c. These anchor the HMAC, the Kc
// derivation and the 96-bit truncation together.
var checksumCases = []struct {
	enc   EncType
	msg   string
	usage Usage
	key   string
	want  string
}{
	{
		AES128CTSHMACSHA196,
		"eight nine ten eleven twelve thirteen",
		3,
		"9062430C8CDA3388922E6D6A509F5B7A",
		"01A4B088D45628F6946614E3",
	},
	{
		AES256CTSHMACSHA196,
		"fourteen",
		4,
		"B1AE4CD8462AFF1677053CC9279AAC30" +
			"B796FB81CE21474DD3DDBCFEA4EC76D7",
		"E08739E3279E2903EC8E3836",
	},
}

func TestChecksum(t *testing.T) {
	for _, tc := range checksumCases {
		p, err := Profile(tc.enc)
		if err != nil {
			t.Fatalf("Profile: %v", err)
		}
		key, want := hx(tc.key), hx(tc.want)
		got, err := p.Checksum(key, []byte(tc.msg), tc.usage)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s\n got %X\nwant %X",
				p.Name, got, want)
		}
		if err := p.VerifyChecksum(
			key, []byte(tc.msg), want, tc.usage,
		); err != nil {
			t.Errorf("%s: verify: %v", p.Name, err)
		}
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	for _, enc := range Supported() {
		p, err := Profile(enc)
		if err != nil {
			t.Fatalf("Profile: %v", err)
		}
		key := bytes.Repeat([]byte{0x5A}, p.KeyLength)

		// Lengths either side of a block boundary, plus the
		// empty message, which is legal and has to work.
		lengths := []int{0, 1, 15, 16, 17, 31, 64, 100}
		for _, n := range lengths {
			plain := bytes.Repeat([]byte{0xC3}, n)
			ct, err := p.Encrypt(
				key, plain, UsageASRepEncPart)
			if err != nil {
				t.Fatalf("%s len %d: encrypt: %v",
					p.Name, n, err)
			}
			if len(ct) != p.CipherLength(n) {
				t.Errorf("%s len %d: ciphertext %d,"+
					" CipherLength says %d",
					p.Name, n, len(ct),
					p.CipherLength(n))
			}
			got, err := p.Decrypt(
				key, ct, UsageASRepEncPart)
			if err != nil {
				t.Fatalf("%s len %d: decrypt: %v",
					p.Name, n, err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("%s len %d: round trip",
					p.Name, n)
			}
		}
	}
}

// Encrypting the same plaintext twice must give different ciphertext,
// because of the confounder. Without it the protocol leaks that two
// messages were the same.
func TestEncryptConfounds(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x11}, p.KeyLength)
	plain := []byte("the same message twice")

	a, err := p.Encrypt(key, plain, UsageASRepEncPart)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Encrypt(key, plain, UsageASRepEncPart)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("two encryptions of one message match")
	}
}

// A tampered ciphertext must be refused, and refused on the integrity
// tag rather than producing rubbish plaintext.
func TestDecryptRejectsTampering(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x22}, p.KeyLength)
	ct, err := p.Encrypt(
		key, []byte("tamper with me"), UsageASRepEncPart)
	if err != nil {
		t.Fatal(err)
	}

	for _, at := range []int{0, p.HeaderLength, len(ct) - 1} {
		bad := bytes.Clone(ct)
		bad[at] ^= 0x01
		_, err := p.Decrypt(key, bad, UsageASRepEncPart)
		if !errors.Is(err, ErrIntegrity) {
			t.Errorf("flipping byte %d: got %v, want %v",
				at, err, ErrIntegrity)
		}
	}
}

// The usage is part of the key derivation, so a message encrypted for
// one usage must not decrypt under another. This is the property that
// stops a ticket's enc-part being swapped for a reply's.
func TestDecryptWrongUsageFails(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x33}, p.KeyLength)
	ct, err := p.Encrypt(
		key, []byte("for usage 3"), UsageASRepEncPart)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Decrypt(
		key, ct, UsageKDCRepTicket,
	); !errors.Is(err, ErrIntegrity) {
		t.Errorf("decrypted under the wrong usage: %v", err)
	}
}

// A ciphertext too short to hold a confounder and a tag must be
// refused rather than slicing out of range.
func TestDecryptRejectsTruncated(t *testing.T) {
	p, err := Profile(AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x44}, p.KeyLength)
	for _, n := range []int{0, 1, 16, 27} {
		if _, err := p.Decrypt(
			key, make([]byte, n), UsageASRepEncPart,
		); err == nil {
			t.Errorf("accepted a %d-byte ciphertext", n)
		}
	}
}

func TestProfileLookup(t *testing.T) {
	for _, enc := range Supported() {
		if _, err := Profile(enc); err != nil {
			t.Errorf("Profile(%d): %v", enc, err)
		}
	}
	if _, err := Profile(23); !errors.Is(
		err, ErrUnsupported) {
		t.Errorf("enctype 23: got %v, want unsupported", err)
	}
}

// The preference order is what a KDC offers and a client picks from,
// so aes256 coming first is behaviour, not decoration. The strongest
// enctype comes first, because Supported() is what a KDC offers a
// client as its own preference. Which one that is moved when the
// aes-sha2 family landed; TestSHA2IsPreferred pins the whole order.
func TestSupportedPrefersTheStrongest(t *testing.T) {
	got := Supported()
	if len(got) == 0 || got[0] != AES256CTSHMACSHA384192 {
		t.Errorf("Supported() = %v, want aes256-sha384 first",
			got)
	}
}
