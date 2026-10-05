package wire

import (
	"bytes"
	"math/big"
	"testing"
)

func TestAuthenticatorMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"all fields", refAuthenticator},
		{"optionals empty", refAuthenticatorEmpty},
		{"optionals absent", refAuthenticatorNoOpt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			a, err := UnmarshalAuthenticator(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalAuthenticator(a)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// cusec is mandatory in an Authenticator, unlike its counterparts in
// a KRB-ERROR and a PA-ENC-TS-ENC. The optionals-absent fixture drops
// the checksum, the subkey, the sequence number and the authorization
// data and still carries cusec, which is how the difference shows.
func TestAuthenticatorFields(t *testing.T) {
	a, err := UnmarshalAuthenticator(ref(t, refAuthenticator))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if a.CRealm != "ATHENA.MIT.EDU" {
		t.Errorf("crealm is %q", a.CRealm)
	}
	if got := a.CName.String(); got != "hftsai/extra" {
		t.Errorf("cname is %q", got)
	}
	if a.CUsec != 123456 {
		t.Errorf("cusec is %d, want 123456", a.CUsec)
	}
	if a.Cksum == nil || string(a.Cksum.Checksum) != "1234" {
		t.Errorf("cksum is %+v", a.Cksum)
	}
	if a.SubKey == nil {
		t.Error("subkey absent")
	}
	if a.SeqNumber != 17 {
		t.Errorf("seq-number is %d, want 17", a.SeqNumber)
	}

	bare, err := UnmarshalAuthenticator(
		ref(t, refAuthenticatorNoOpt))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if bare.Cksum != nil || bare.SubKey != nil {
		t.Error("decoded an optional that is not on the wire")
	}
	if bare.SeqNumber != 0 {
		t.Errorf("seq-number is %d, want 0", bare.SeqNumber)
	}
	if bare.CUsec != 123456 {
		t.Errorf("mandatory cusec lost: %d", bare.CUsec)
	}
}

// A sequence number above 2^31-1 must encode as a positive INTEGER,
// because that is what upstream writes (encode_seqno uses
// k5_asn1_encode_uint). A signed encoder would write the negative
// form, which upstream's decoder tolerates but no upstream encoder
// produces.
func TestSequenceNumberIsUnsignedOnTheWire(t *testing.T) {
	der := seqnoDER(0xFFFFFFFF)
	if der == nil || der.Cmp(
		big.NewInt(0xFFFFFFFF)) != 0 {
		t.Fatalf("encoded as %v", der)
	}
	got, err := seqnoValue(der)
	if err != nil {
		t.Fatalf("seqnoValue: %v", err)
	}
	if got != 0xFFFFFFFF {
		t.Errorf("read back %#x", got)
	}
	// Zero is absent, not an INTEGER 0.
	if seqnoDER(0) != nil {
		t.Error("zero encoded instead of being omitted")
	}
}

// The negative form is accepted on decode, deliberately: upstream
// does it for interoperability with old implementations that encoded
// these signed (decode_seqno, asn1_k_encode.c:133-146).
func TestNegativeSequenceNumberIsAccepted(t *testing.T) {
	got, err := seqnoValue(big.NewInt(-1))
	if err != nil {
		t.Fatalf("rejected the negative form: %v", err)
	}
	if got != 0xFFFFFFFF {
		t.Errorf("read -1 as %#x, want ffffffff", got)
	}
	if _, err := seqnoValue(
		big.NewInt(0x1FFFFFFFF)); err == nil {
		t.Error("accepted a value above 32 bits")
	}
}

func TestAPReqMatchesTheReference(t *testing.T) {
	want := ref(t, refAPReq)
	r, err := UnmarshalAPReq(want)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.Ticket.Realm != "ATHENA.MIT.EDU" {
		t.Errorf("ticket realm is %q", r.Ticket.Realm)
	}
	if r.Options != 0xFEDCBA98 {
		t.Errorf("ap-options are %08X", uint32(r.Options))
	}
	got, err := MarshalAPReq(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	roundTrip(t, want, got)
}

func TestTGSReqMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"all fields", refTGSReq},
		{"only second-ticket", refTGSReqOnlyTkt},
		{"only server", refTGSReqOnlySrv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			r, err := UnmarshalTGSReq(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalTGSReq(r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

func TestTGSRepMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"with padata", refTGSRep},
		{"no padata", refTGSRepNoOpt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			r, err := UnmarshalTGSRep(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalTGSRep(r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// A TGS-REQ and an AS-REQ are the same structure and differ only in
// the application tag and the msg-type. Each decoder must refuse the
// other's message rather than accept it as its own.
func TestTGSAndASAreNotInterchangeable(t *testing.T) {
	as := ref(t, refASReq)
	if _, err := UnmarshalTGSReq(as); err == nil {
		t.Error("the TGS decoder accepted an AS-REQ")
	}
	tgs := ref(t, refTGSReq)
	if _, err := UnmarshalASReq(tgs); err == nil {
		t.Error("the AS decoder accepted a TGS-REQ")
	}
	// The application tags are 10 and 12, so the first byte is
	// the whole of the difference a careless decoder would miss.
	if as[0] != 0x6A || tgs[0] != 0x6C {
		t.Errorf("fixtures open %02X and %02X", as[0], tgs[0])
	}
}

// A TGS-REP's sealed half goes on the wire with application tag 26,
// the same as an AS-REP's -- which is the whole reason the AS one is
// 26 and not the 25 the RFC assigns it.
func TestEncTGSRepPartIsAlsoTag26(t *testing.T) {
	e, err := UnmarshalEncKDCRepPart(ref(t, refEncKDCRepPart))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	as, err := MarshalEncASRepPart(e)
	if err != nil {
		t.Fatal(err)
	}
	tgs, err := MarshalEncTGSRepPart(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(as, tgs) {
		t.Error("the AS and TGS encodings differ")
	}
	if tgs[0] != 0x7A {
		t.Errorf("first byte is %02X, want 7A", tgs[0])
	}
}
