package wire

import (
	"testing"
)

// The all-fields reference encoding (reference_encode.out:71).
const refCAMMAC = "30 81 F2 A0 1E 30 1C 30 0C A0 03 02 01 01 A1 " +
	"05 04 03 61 64 31 30 0C A0 03 02 01 02 A1 05 04 03 61 64 " +
	"32 A1 3D 30 3B A0 1A 30 18 A0 03 02 01 01 A1 11 30 0F 1B " +
	"06 68 66 74 73 61 69 1B 05 65 78 74 72 61 A1 03 02 01 05 " +
	"A2 03 02 01 10 A3 13 30 11 A0 03 02 01 01 A1 0A 04 08 63 " +
	"6B 73 75 6D 6B 64 63 A2 3D 30 3B A0 1A 30 18 A0 03 02 01 " +
	"01 A1 11 30 0F 1B 06 68 66 74 73 61 69 1B 05 65 78 74 72 " +
	"61 A1 03 02 01 05 A2 03 02 01 10 A3 13 30 11 A0 03 02 01 " +
	"01 A1 0A 04 08 63 6B 73 75 6D 73 76 63 A3 52 30 50 30 13 " +
	"A3 11 30 0F A0 03 02 01 01 A1 08 04 06 63 6B 73 75 6D 31 " +
	"30 39 A0 1A 30 18 A0 03 02 01 01 A1 11 30 0F 1B 06 68 66 " +
	"74 73 61 69 1B 05 65 78 74 72 61 A1 03 02 01 05 A2 03 02 " +
	"01 10 A3 11 30 0F A0 03 02 01 01 A1 08 04 06 63 6B 73 75 " +
	"6D 32"

// And the optionals-absent form (:70), which is the one a
// reimplementation gets wrong: every field but elements is OPTIONAL.
const refCAMMACMinimal = "30 12 A0 10 30 0E 30 0C A0 03 02 01 " +
	"01 A1 05 04 03 61 64 31"

// Both decode and both re-encode to identical octets.
func TestCAMMACMatchesTheReference(t *testing.T) {
	for _, c := range []struct {
		why string
		hex string
	}{
		{"all fields", refCAMMAC},
		{"optionals absent", refCAMMACMinimal},
	} {
		t.Run(c.why, func(t *testing.T) {
			want := ref(t, c.hex)
			got, err := UnmarshalCAMMAC(want)
			if err != nil {
				t.Fatal(err)
			}
			back, err := MarshalCAMMAC(got)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip(t, want, back)
		})
	}
}

// The fields of the all-fields form, so that a round trip through a
// wrong structure cannot pass.
func TestCAMMACFields(t *testing.T) {
	c, err := UnmarshalCAMMAC(ref(t, refCAMMAC))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Elements) != 2 ||
		string(c.Elements[0].Data) != "ad1" ||
		string(c.Elements[1].Data) != "ad2" {
		t.Errorf("elements are %v", c.Elements)
	}
	if c.KDCVerifier == nil || c.SvcVerifier == nil {
		t.Fatal("a verifier is missing")
	}
	if string(c.KDCVerifier.MAC.Checksum) != "cksumkdc" {
		t.Errorf("kdc mac is %q",
			c.KDCVerifier.MAC.Checksum)
	}
	if string(c.SvcVerifier.MAC.Checksum) != "cksumsvc" {
		t.Errorf("svc mac is %q",
			c.SvcVerifier.MAC.Checksum)
	}
	if c.KDCVerifier.KVNO != 5 ||
		c.KDCVerifier.EType != 16 {
		t.Errorf("kvno %d enctype %d",
			c.KDCVerifier.KVNO, c.KDCVerifier.EType)
	}
	if len(c.OtherVerifiers) != 2 {
		t.Errorf("%d other verifiers",
			len(c.OtherVerifiers))
	}
}

// And the minimal form carries nothing but its elements, which is
// what a KDC would produce if it signed with neither key -- and which
// must therefore decode as *no verifiers* rather than as two empty
// ones, because an empty verifier would be a checksum that verifies
// nothing and is trivially forgeable.
func TestAMinimalCAMMACHasNoVerifiers(t *testing.T) {
	c, err := UnmarshalCAMMAC(ref(t, refCAMMACMinimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.KDCVerifier != nil || c.SvcVerifier != nil {
		t.Errorf("got verifiers %+v %+v",
			c.KDCVerifier, c.SvcVerifier)
	}
	if len(c.OtherVerifiers) != 0 {
		t.Errorf("%d other verifiers",
			len(c.OtherVerifiers))
	}
	if len(c.Elements) != 1 {
		t.Errorf("%d elements", len(c.Elements))
	}
}

// The auth-indicator contents are a SEQUENCE OF UTF8String, which
// round-trips and refuses anything else.
func TestAuthIndicatorsRoundTrip(t *testing.T) {
	want := []string{"otp", "pkinit", "high"}
	der, err := MarshalAuthIndicators(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalAuthIndicators(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
	// A SEQUENCE OF something else is refused rather than read as
	// empty strings.
	other, err := MarshalAuthorizationData(
		AuthorizationData{{Type: 1, Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalAuthIndicators(other); err == nil {
		t.Error("a non-UTF8String sequence was accepted")
	}
	// And an empty list round-trips to an empty list.
	der, err = MarshalAuthIndicators(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnmarshalAuthIndicators(
		der); err != nil || len(got) != 0 {
		t.Errorf("got %v, %v", got, err)
	}
}
