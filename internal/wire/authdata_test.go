package wire

import (
	"bytes"
	"testing"
)

// The reference encoding, from upstream's own asn.1 test
// (reference_encode.out:37): two elements, each type 1 with the
// contents "foobar".
const refAuthorizationData = "30 22 30 0F A0 03 02 01 01 A1 08 " +
	"04 06 66 6F 6F 62 61 72 30 0F A0 03 02 01 01 A1 08 04 06 " +
	"66 6F 6F 62 61 72"

// It decodes, and re-encodes to identical octets.
func TestAuthorizationDataMatchesTheReference(t *testing.T) {
	want := ref(t, refAuthorizationData)
	got, err := UnmarshalAuthorizationData(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d elements", len(got))
	}
	for i, d := range got {
		if d.Type != ADIfRelevant {
			t.Errorf("element %d type %d", i, d.Type)
		}
		if string(d.Data) != "foobar" {
			t.Errorf("element %d data %q", i, d.Data)
		}
	}
	back, err := MarshalAuthorizationData(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, want) {
		t.Errorf("re-encoded to\n% X\nwant\n% X", back, want)
	}
}

// The five KDC-issued types are stripped and everything else is kept,
// which is most of what there is (is_kdc_issued_authdatum,
// kdc_authdata.c:130-145).
func TestOnlyKDCIssuedTypesAreStripped(t *testing.T) {
	for _, c := range []struct {
		t      int32
		issued bool
	}{
		{ADKDCIssued, true},
		{ADCAMMAC, true},
		{ADAuthIndicator, true},
		{ADWin2KPAC, true},
		{ADSignTicket, true},
		{ADMandatoryForKDC, false},
		{2, false},
		// 142 is Heimdal's AD-SIGNTICKET and PA-OTP-REQUEST's
		// padata number. MIT uses neither for this, so it is
		// ordinary data here.
		{142, false},
	} {
		d := AuthDatum{Type: c.t, Data: []byte("x")}
		if got := d.IsKDCIssued(); got != c.issued {
			t.Errorf("type %d: %v", c.t, got)
		}
	}
	// A container is judged by what is in it, which the two tests
	// below cover; an empty one holds nothing forbidden.
	empty, err := MarshalAuthorizationData(nil)
	if err != nil {
		t.Fatal(err)
	}
	if (AuthDatum{Type: ADIfRelevant, Data: empty}).
		IsKDCIssued() {
		t.Error("an empty container was stripped")
	}
}

// **The filter descends one level into AD-IF-RELEVANT**, which is the
// whole reason it is not a top-level type check: a service reading a
// ticket unwraps the container without caring who put it there, so
// wrapping a forged PAC in one would otherwise let a client hand
// itself a PAC (:119-127).
func TestAContainerCannotSmuggleAPAC(t *testing.T) {
	inner, err := MarshalAuthorizationData(
		AuthorizationData{{
			Type: ADWin2KPAC,
			Data: []byte("a forged PAC"),
		}})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := AuthDatum{Type: ADIfRelevant, Data: inner}
	if !wrapped.IsKDCIssued() {
		t.Error("a wrapped PAC was not recognised")
	}
	// And a container holding something harmless survives.
	ok, err := MarshalAuthorizationData(
		AuthorizationData{{Type: 2, Data: []byte("fine")}})
	if err != nil {
		t.Fatal(err)
	}
	if (AuthDatum{Type: ADIfRelevant, Data: ok}).
		IsKDCIssued() {
		t.Error("a harmless container was stripped")
	}
}

// A container nobody can decode is **dropped**, which is a deliberate
// divergence: upstream keeps it, because
// krb5int_get_authdata_containee_types failing leaves its result
// false (:120-124). Keeping an element nothing could read is how a
// smuggling path stays open, and dropping it costs a client an
// element it malformed.
func TestAnUndecodableContainerIsDropped(t *testing.T) {
	d := AuthDatum{
		Type: ADIfRelevant,
		Data: []byte{0x05, 0xff, 0xff},
	}
	if !d.IsKDCIssued() {
		t.Error("an unparseable container survived")
	}
}

// AD-MANDATORY-FOR-KDC is checked at the **top level only**, which
// upstream's has_mandatory_for_kdc_authdata does by not descending
// (:152-166). A wrapped one is therefore not a refusal -- and that is
// upstream's behaviour rather than an oversight here, because the
// element's meaning is about the KDC reading the list it was given.
func TestMandatoryForKDCIsNotNested(t *testing.T) {
	top := AuthorizationData{
		{Type: ADMandatoryForKDC, Data: []byte("x")},
	}
	if !top.HasMandatoryForKDC() {
		t.Error("a top-level element was missed")
	}
	inner, err := MarshalAuthorizationData(top)
	if err != nil {
		t.Fatal(err)
	}
	nested := AuthorizationData{
		{Type: ADIfRelevant, Data: inner},
	}
	if nested.HasMandatoryForKDC() {
		t.Error("a nested element was treated as mandatory")
	}
}

// Filtering an all-KDC-issued list yields nil rather than an empty
// list, so that the ticket's [10] field is omitted instead of
// carrying an empty SEQUENCE.
func TestFilteringToNothingYieldsNil(t *testing.T) {
	got := AuthorizationData{
		{Type: ADWin2KPAC, Data: []byte("p")},
		{Type: ADCAMMAC, Data: []byte("c")},
	}.Filtered()
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
