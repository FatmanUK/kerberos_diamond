package store

import (
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
)

// Upstream's default is the two RFC 3962 types and **not** the
// aes-sha2 pair, even though upstream implements them
// (KRB5_DEFAULT_SUPPORTED_ENCTYPES, include/osconf.hin:109-111). So a
// realm left at the default creates no sha2 keys at all, which is
// worth asserting because it is the sort of default a
// reimplementation improves on without noticing.
func TestTheDefaultIsUpstreamsAndNotEverything(t *testing.T) {
	got := DefaultSupportedEnctypes()
	want := SupportedEnctypes{
		crypto.AES256CTSHMACSHA196,
		crypto.AES128CTSHMACSHA196,
	}
	if len(got) != len(want) {
		t.Fatalf("default is %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("default is %v, want %v", got, want)
		}
	}
	// And it is a strict subset of what the crypto package can
	// do, which is the point: the list says what to *create*, not
	// what is implemented.
	if len(got) >= len(crypto.Supported()) {
		t.Errorf("the default is not a subset of %v",
			crypto.Supported())
	}
}

// A krb5.conf value transcribes, salt suffix and all.
func TestEnctypeListsTranscribe(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"", 0},
		{"aes256-cts-hmac-sha1-96:normal", 1},
		{"aes256-cts-hmac-sha1-96:normal " +
			"aes128-cts-hmac-sha1-96:normal", 2},
		{"aes256-cts,aes128-cts", 2},
		{"aes256-sha2 aes128-sha2", 2},
	} {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseEnctypes(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Errorf("%v", got)
			}
		})
	}
}

// The order survives parsing, because it decides which key seals a
// ticket: the KDC takes the first key of a principal's highest key
// version whatever its enctype.
func TestTheEnctypeOrderSurvives(t *testing.T) {
	got, err := ParseEnctypes(
		"aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha1-96")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 ||
		got[0] != crypto.AES128CTSHMACSHA196 {
		t.Fatalf("got %v", got)
	}
}

// And the list is what gets created, in that order.
func TestTheConfiguredListIsWhatGetsCreated(t *testing.T) {
	s, _ := testStore(t)
	s.SetEnctypes(SupportedEnctypes{
		crypto.AES128CTSHMACSHA196,
	})
	p := NewPrincipal(testRealm, []string{"one"})
	if err := s.SetPassword(p, "onepassword", 1); err != nil {
		t.Fatal(err)
	}
	if len(p.Keys) != 1 {
		t.Fatalf("%d keys", len(p.Keys))
	}
	if p.Keys[0].EType !=
		int32(crypto.AES128CTSHMACSHA196) {
		t.Errorf("enctype %d", p.Keys[0].EType)
	}
}

// Anything that is not an enctype, and any salt type this project
// does not create, is refused rather than ignored.
//
// The salt suffix matters: `normal' is the only one, because a
// special salt is something rename *pins* afterwards and never
// something an operator chooses up front. Taking `:normal' and
// silently taking `:v4' as well would let a krb5.conf transcribe into
// something that means something else.
func TestBadEnctypeListsAreRefused(t *testing.T) {
	for _, bad := range []string{
		"nonsense",
		"aes256-cts-hmac-sha1-96:v4",
		"aes256-cts-hmac-sha1-96:special",
		"des3-cbc-sha1",
		"aes256-cts-hmac-sha1-96 nonsense",
	} {
		if got, err := ParseEnctypes(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, got)
		}
	}
}
