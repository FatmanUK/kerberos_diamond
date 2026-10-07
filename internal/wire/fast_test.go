package wire

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// The reply half of FAST is anchored to upstream's own byte-exact
// output, the same way every other message here is. The *request*
// half is not, and the reason is worth stating: nothing in the C test
// suite encodes PA-FX-FAST-REQUEST, KrbFastArmoredReq, KrbFastReq or
// KrbFastArmor, so there are no reference bytes to compare against.
// Those are derived from the type definitions at
// asn1_k_encode.c:996-1031 and round-tripped against themselves here,
// with their shape asserted by hand; the anchor that actually settles
// them is a stock kinit -T in internal/golden, which will not accept
// a request it cannot read.

func TestFastResponseMatchesTheReference(t *testing.T) {
	want := ref(t, refFastResponse)
	got, err := UnmarshalKrbFastResponse(want)
	if err != nil {
		t.Fatalf("UnmarshalKrbFastResponse: %v", err)
	}
	if got.Nonce != 0x2A {
		t.Errorf("nonce is %d, want 42", got.Nonce)
	}
	if n := len(got.PAData); n != 2 {
		t.Errorf("padata has %d entries, want 2", n)
	}
	if got.StrengthenKey.KeyType != 1 {
		t.Errorf("strengthen key type is %d, want 1",
			got.StrengthenKey.KeyType)
	}
	if s := string(got.StrengthenKey.KeyValue); s != "12345678" {
		t.Errorf("strengthen key is %q", s)
	}
	assertSampleFinished(t, got.Finished)

	again, err := MarshalKrbFastResponse(got)
	if err != nil {
		t.Fatalf("MarshalKrbFastResponse: %v", err)
	}
	roundTrip(t, want, again)
}

// assertSampleFinished checks the KrbFastFinished inside the
// reference reply, which is the only reference bytes that type has.
func assertSampleFinished(t *testing.T, f KrbFastFinished) {
	t.Helper()
	ts := time.Date(1994, 6, 10, 6, 3, 17, 0, time.UTC)
	if !f.Timestamp.Equal(ts) {
		t.Errorf("timestamp is %v, want %v", f.Timestamp, ts)
	}
	if f.Usec != 123456 {
		t.Errorf("usec is %d, want 123456", f.Usec)
	}
	if f.CRealm != "ATHENA.MIT.EDU" {
		t.Errorf("crealm is %q", f.CRealm)
	}
	if got := f.CName.String(); got != "hftsai/extra" {
		t.Errorf("cname is %q, want hftsai/extra", got)
	}
	if s := string(f.TicketChecksum.Checksum); s != "1234" {
		t.Errorf("ticket checksum is %q", s)
	}
}

func TestPAFXFastReplyMatchesTheReference(t *testing.T) {
	want := ref(t, refPAFXFastReply)
	got, err := UnmarshalPAFXFastReply(want)
	if err != nil {
		t.Fatalf("UnmarshalPAFXFastReply: %v", err)
	}
	if got.KVNO != 5 {
		t.Errorf("kvno is %d, want 5", got.KVNO)
	}
	if s := string(got.Cipher); s != "krbASN.1 test message" {
		t.Errorf("cipher is %q", s)
	}
	again, err := MarshalPAFXFastReply(got)
	if err != nil {
		t.Fatalf("MarshalPAFXFastReply: %v", err)
	}
	roundTrip(t, want, again)
}

// An error reply carries neither a strengthen key nor a finished
// field (fast_util.c:402-407), and there is no reference encoding for
// that form -- upstream's fixture sets every field. So the absent
// case is asserted by hand, and it has to be: the two OPTIONALs are
// what tells a success reply from a refusal.
func TestFastResponseWithoutTheOptionals(t *testing.T) {
	in := KrbFastResponse{
		PAData: []PAData{
			{Type: PAFXError, Value: []byte("e")},
		},
		Nonce: 7,
	}
	b, err := MarshalKrbFastResponse(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalKrbFastResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.StrengthenKey.KeyType != 0 ||
		got.StrengthenKey.KeyValue != nil {
		t.Errorf("a strengthen key appeared: %+v",
			got.StrengthenKey)
	}
	if !got.Finished.Timestamp.IsZero() {
		t.Errorf("a finished field appeared: %+v",
			got.Finished)
	}
	if got.Nonce != 7 || len(got.PAData) != 1 {
		t.Errorf("the rest did not survive: %+v", got)
	}
}

// The request types round-trip. This is the weakest kind of test in
// the package -- it would pass against a consistently wrong encoding
// -- and it says so because the real anchor is the stock client.
func TestFastRequestRoundTrips(t *testing.T) {
	in := KrbFastReq{
		Options: FastOptionHideClientNames,
		PAData: []PAData{
			{Type: PAEncTimestamp, Value: []byte("ts")},
		},
		Body: sampleBody(),
	}
	b, err := MarshalKrbFastReq(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalKrbFastReq(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Options != in.Options {
		t.Errorf("options are %08X, want %08X",
			uint32(got.Options), uint32(in.Options))
	}
	if len(got.PAData) != 1 || got.PAData[0].Type !=
		PAEncTimestamp {
		t.Errorf("padata is %+v", got.PAData)
	}
	// The body is the point: it is a whole KDC-REQ-BODY carried
	// as raw DER inside [2], and a wrapper off by one tag would
	// lose it silently.
	if got.Body.Realm != in.Body.Realm ||
		got.Body.Nonce != in.Body.Nonce {
		t.Errorf("the body did not survive: %+v", got.Body)
	}
	if got.Body.SName == nil ||
		got.Body.SName.String() != "krbtgt/EXAMPLE.TEST" {
		t.Errorf("the body's sname is %v", got.Body.SName)
	}
}

// sampleBody is a minimal KDC-REQ-BODY for the request round trips.
func sampleBody() KDCReqBody {
	return KDCReqBody{
		Options: OptForwardable,
		Realm:   "EXAMPLE.TEST",
		SName: &PrincipalName{
			Type: NTSrvInst,
			Components: []string{
				"krbtgt", "EXAMPLE.TEST",
			},
		},
		Till:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Nonce: 0x5A,
		EType: []int32{18, 17},
	}
}

func TestPAFXFastRequestRoundTrips(t *testing.T) {
	in := KrbFastArmoredReq{
		Armor: KrbFastArmor{
			Type:  FastArmorAPRequest,
			Value: []byte("ap-req"),
		},
		ReqChecksum: Checksum{
			Type: 16, Checksum: []byte("sum"),
		},
		EncPart: EncryptedData{
			EType: 18, Cipher: []byte("ct"),
		},
	}
	b, err := MarshalPAFXFastRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPAFXFastRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Armor.Type != FastArmorAPRequest {
		t.Errorf("armor type is %d", got.Armor.Type)
	}
	if !bytes.Equal(got.Armor.Value, in.Armor.Value) {
		t.Errorf("armor value is %q", got.Armor.Value)
	}
	if got.ReqChecksum.Type != 16 {
		t.Errorf("checksum type is %d", got.ReqChecksum.Type)
	}
	if got.EncPart.EType != 18 {
		t.Errorf("enc-part etype is %d", got.EncPart.EType)
	}
}

// A TGS request carries no armor field, and upstream refuses one that
// does (fast_util.c:158-164). The absent form therefore has to encode
// and decode cleanly, which the optional [0] gives only because an
// armor type of zero is not a valid one.
func TestPAFXFastRequestWithoutArmor(t *testing.T) {
	in := KrbFastArmoredReq{
		ReqChecksum: Checksum{
			Type: 16, Checksum: []byte("sum"),
		},
		EncPart: EncryptedData{
			EType: 18, Cipher: []byte("ct"),
		},
	}
	b, err := MarshalPAFXFastRequest(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPAFXFastRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Armor.Type != 0 || got.Armor.Value != nil {
		t.Errorf("an armor field appeared: %+v", got.Armor)
	}
}

// The CHOICE has one alternative and anything else is refused rather
// than read as that one. Upstream's decoder accepts only [0] by
// accident, through a hard-coded tag; this does it on purpose, so a
// second alternative one day is a clear error and not a misread.
func TestPAFXFastRejectsAnotherChoice(t *testing.T) {
	good, err := MarshalPAFXFastReply(EncryptedData{
		EType: 18, Cipher: []byte("ct"),
	})
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), good...)
	bad[0] = 0xA1
	if _, err := UnmarshalPAFXFastReply(bad); !errors.Is(
		err, ErrMalformed) {
		t.Errorf("[1] gave %v, want ErrMalformed", err)
	}
	if _, err := UnmarshalPAFXFastRequest(bad); !errors.Is(
		err, ErrMalformed) {
		t.Errorf("request [1] gave %v", err)
	}
	if _, err := UnmarshalPAFXFastReply(nil); !errors.Is(
		err, ErrMalformed) {
		t.Errorf("empty gave %v", err)
	}
}
