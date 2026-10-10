package wire

import (
	"bytes"
	"testing"
)

// The two S4U2Self request types against upstream's own encoder
// (reference_encode.out:55-56), decoded and re-encoded to identical
// octets.
//
// Only the **all-fields** form is published for either, so the
// optional-absent forms below are hand-asserted -- which is §6's own
// rule turned on its head: absence is most of what there is to get
// wrong, and here the reference encoding cannot say anything about
// it.
func TestS4URoundTripsTheReferenceEncodings(t *testing.T) {
	in := ref(t, refPAForUser)
	p, err := UnmarshalPAForUser(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserName.String() != "hftsai/extra" {
		t.Errorf("name is %q", p.UserName.String())
	}
	if p.UserRealm != "ATHENA.MIT.EDU" {
		t.Errorf("realm is %q", p.UserRealm)
	}
	if p.AuthPackage != "krb5data" {
		t.Errorf("auth-package is %q", p.AuthPackage)
	}
	out, err := MarshalPAForUser(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("re-encoded to\n % X\nwant\n % X", out, in)
	}
}

func TestS4UX509UserRoundTripsTheReference(t *testing.T) {
	in := ref(t, refPAS4UX509User)
	p, err := UnmarshalPAS4UX509User(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID.Nonce != 0x00CA149A {
		t.Errorf("nonce is %#x", p.UserID.Nonce)
	}
	if p.UserID.UserName == nil ||
		p.UserID.UserName.String() != "hftsai/extra" {
		t.Errorf("name is %v", p.UserID.UserName)
	}
	if p.UserID.UserRealm != "ATHENA.MIT.EDU" {
		t.Errorf("realm is %q", p.UserID.UserRealm)
	}
	if string(p.UserID.SubjectCert) != "pa_s4u_x509_user" {
		t.Errorf("cert is %q", p.UserID.SubjectCert)
	}
	// 0x80000000 is bit 0, which is neither of the two [MS-SFU]
	// options -- upstream's fixture sets it to exercise the
	// field, not to mean anything.
	if p.UserID.Options != 0x80000000 {
		t.Errorf("options are %#08x",
			uint32(p.UserID.Options))
	}
	out, err := MarshalPAS4UX509User(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Errorf("re-encoded to\n % X\nwant\n % X", out, in)
	}
}

// The optional-absent forms, which no reference encoding covers.
//
// **A principal of no components is omitted, not encoded empty**
// (is_s4u_principal_present, asn1_k_encode.c:962-970), and that is
// the shape a certificate-only request takes: it names a realm and no
// user, and the KDC then asks its database which principal the
// certificate belongs to. Encoding an empty name instead would be a
// request for the principal whose name is nothing.
func TestAnS4UUserIDWithNoNameOmitsTheField(t *testing.T) {
	in := S4UUserID{
		Nonce:       42,
		UserRealm:   "EXAMPLE.TEST",
		SubjectCert: []byte("cert"),
	}
	der, err := MarshalS4UUserID(in)
	if err != nil {
		t.Fatal(err)
	}
	// [1] must not appear at all.
	if bytes.Contains(der, []byte{0xA1}) {
		t.Errorf("the name field travelled: % X", der)
	}
	back, err := UnmarshalS4UUserID(der)
	if err != nil {
		t.Fatal(err)
	}
	if back.UserName != nil {
		t.Errorf("name came back as %v", back.UserName)
	}
	if back.UserRealm != in.UserRealm ||
		string(back.SubjectCert) != "cert" {
		t.Errorf("round trip changed it: %+v", back)
	}
}

// A name with components but no certificate and no options, which is
// what a real S4U2Self request looks like: the other two fields are
// absent and have to stay absent.
func TestAnS4UUserIDWithOnlyANameAndRealm(t *testing.T) {
	name := PrincipalName{Type: NTPrincipal,
		Components: []string{"user"}}
	in := S4UUserID{Nonce: 7, UserName: &name,
		UserRealm: "EXAMPLE.TEST"}
	der, err := MarshalS4UUserID(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []byte{0xA3, 0xA4} {
		if bytes.Contains(der, []byte{tag}) {
			t.Errorf("tag %#x travelled: % X", tag, der)
		}
	}
	back, err := UnmarshalS4UUserID(der)
	if err != nil {
		t.Fatal(err)
	}
	if back.SubjectCert != nil || back.Options != 0 {
		t.Errorf("round trip invented fields: %+v", back)
	}
	if back.UserName == nil ||
		back.UserName.String() != "user" {
		t.Errorf("name came back as %v", back.UserName)
	}
}

// An options field of exactly zero is omitted rather than written as
// thirty-two zero bits, because upstream's opt_krb5_flags is guarded
// on the value being non-zero -- so a client that sets no options and
// a client that sets the field to nothing are the same request, and
// the checksum over this structure has to agree about which.
func TestZeroS4UOptionsAreOmitted(t *testing.T) {
	name := PrincipalName{Components: []string{"u"}}
	der, err := MarshalS4UUserID(S4UUserID{Nonce: 1,
		UserName: &name, UserRealm: "R", Options: 0})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(der, []byte{0xA4}) {
		t.Errorf("zero options travelled: % X", der)
	}
}

// The PA-FOR-USER checksum input, built by hand from upstream's own
// fixture so that the two surprises in it are written down.
//
// The name type travels **little-endian** and there are **no
// separators**: four octets of type, then "hftsai", then "extra",
// then the realm, then the auth-package, run together.
func TestForUserChecksumDataIsNotDER(t *testing.T) {
	p, err := UnmarshalPAForUser(ref(t, refPAForUser))
	if err != nil {
		t.Fatal(err)
	}
	got := S4UForUserChecksumData(p)
	want := append([]byte{1, 0, 0, 0},
		"hftsaiextraATHENA.MIT.EDUkrb5data"...)
	if !bytes.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// And the collision the missing separators imply, asserted rather
// than left as a remark: it is the same shape of collision the
// default salt has.
func TestForUserChecksumDataCollides(t *testing.T) {
	a := PAForUser{UserName: PrincipalName{Type: 1,
		Components: []string{"a", "b"}}, UserRealm: "R"}
	b := PAForUser{UserName: PrincipalName{Type: 1,
		Components: []string{"ab"}}, UserRealm: "R"}
	if !bytes.Equal(S4UForUserChecksumData(a),
		S4UForUserChecksumData(b)) {
		t.Error("a/b and ab no longer collide, which means " +
			"the concatenation gained a separator")
	}
}

// S4UUserIDBytes returns the octets as they arrived, not a
// re-encoding -- so it has to come back byte-identical to the slice
// of the input it names.
func TestS4UUserIDBytesIsASlice(t *testing.T) {
	in := ref(t, refPAS4UX509User)
	got, err := S4UUserIDBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	// The reference encoding's user-id field is the 0x55 octets
	// after `30 68 A0 55'.
	want := in[4 : 4+0x55]
	if !bytes.Equal(got, want) {
		t.Errorf("got  % X\nwant % X", got, want)
	}
	// And it parses as the structure it claims to be.
	if _, err := UnmarshalS4UUserID(got); err != nil {
		t.Errorf("the extracted field does not parse: %v",
			err)
	}
}
