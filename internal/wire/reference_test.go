package wire

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// ref decodes a reference fixture's hex, which the file writes as
// space-separated bytes.
func ref(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(
		strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return b
}

// roundTrip asserts that decode-then-encode reproduces the input
// exactly. Anything less than exact would still interoperate most of
// the time, which is why the assertion is on octets.
func roundTrip(t *testing.T, want []byte, got []byte) {
	t.Helper()
	if bytes.Equal(want, got) {
		return
	}
	t.Errorf("re-encoded bytes differ\n got %s\nwant %s",
		hex.EncodeToString(got), hex.EncodeToString(want))
}

func TestTicketMatchesTheReference(t *testing.T) {
	want := ref(t, refTicket)
	tkt, err := UnmarshalTicket(want)
	if err != nil {
		t.Fatalf("UnmarshalTicket: %v", err)
	}
	if tkt.Realm != "ATHENA.MIT.EDU" {
		t.Errorf("realm is %q", tkt.Realm)
	}
	if got := tkt.SName.String(); got != "hftsai/extra" {
		t.Errorf("sname is %q", got)
	}
	// kvno 5 is present; etype 0 is a mandatory field that
	// happens to be zero, and must still be on the wire.
	if tkt.EncPart.KVNO != 5 || tkt.EncPart.EType != 0 {
		t.Errorf("enc-part is %+v", tkt.EncPart)
	}
	got, err := MarshalTicket(tkt)
	if err != nil {
		t.Fatalf("MarshalTicket: %v", err)
	}
	roundTrip(t, want, got)
}

func TestEncTicketPartMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"all fields", refEncTktPart},
		{"optionals absent", refEncTktPartNoOpt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			e, err := UnmarshalEncTicketPart(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalEncTicketPart(e)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// The fixture's flags are 0xFEDCBA98, and bit 8 -- FlagRenewable --
// is set in it. The second fixture below clears exactly that bit and
// drops renew-till with it, which is how upstream's predicate shows
// up on the wire.
func TestEncTicketPartFlagsAreBigEndianBitZeroFirst(t *testing.T) {
	e, err := UnmarshalEncTicketPart(ref(t, refEncTktPart))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Flags != 0xFEDCBA98 {
		t.Fatalf("flags are %08X, want FEDCBA98", e.Flags)
	}
	if !e.Flags.Has(FlagRenewable) {
		t.Error("FlagRenewable not set in FEDCBA98")
	}
	// Bit 10 is clear in 0xDC, the second octet, so a decoder
	// that had the bit order backwards would report this one set.
	if e.Flags.Has(FlagPreAuthent) {
		t.Error("FlagPreAuthent set in FEDCBA98")
	}
}

func TestEncKDCRepPartMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"all fields", refEncKDCRepPart},
		{"optionals absent", refEncKDCRepPartNoOpt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			e, err := UnmarshalEncKDCRepPart(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalEncASRepPart(e)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// The reference bytes start 7A, which is APPLICATION 26 -- not the 25
// RFC 4120 assigns to EncASRepPart. This asserts the tag directly, so
// that a change to MarshalEncASRepPart cannot quietly switch to the
// RFC's number and break every C client.
func TestEncASRepPartIsWrittenWithApplicationTag26(t *testing.T) {
	e, err := UnmarshalEncKDCRepPart(ref(t, refEncKDCRepPart))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, err := MarshalEncASRepPart(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got[0] != 0x7A {
		t.Errorf("first byte is %02X, want 7A", got[0])
	}
}

// Application tag 25 is what the RFC says, so it has to decode too.
// There is no reference fixture for it -- upstream never writes one
// -- so the input is built by rewriting the tag byte of the fixture
// that exists, which is exactly the message a non-MIT implementation
// would send.
func TestEncASRepPartAlsoDecodesApplicationTag25(t *testing.T) {
	b := ref(t, refEncKDCRepPart)
	b[0] = 0x79 // APPLICATION 25, constructed
	e, err := UnmarshalEncKDCRepPart(b)
	if err != nil {
		t.Fatalf("app tag 25 rejected: %v", err)
	}
	if e.SRealm != "ATHENA.MIT.EDU" {
		t.Errorf("srealm is %q", e.SRealm)
	}
}

// An absent starttime means authtime, which upstream's decoder
// supplies by initialising the field (asn1_k_encode.c:392-399). Here
// the field stays zero so that presence survives for the differential
// harness, and the default lives in EffectiveStartTime -- so this
// asserts both halves.
func TestAbsentStartTimeMeansAuthTime(t *testing.T) {
	e, err := UnmarshalEncKDCRepPart(
		ref(t, refEncKDCRepPartNoOpt))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !e.StartTime.IsZero() {
		t.Error("absent starttime did not stay zero")
	}
	if !e.EffectiveStartTime().Equal(e.AuthTime) {
		t.Errorf("effective starttime %v, authtime %v",
			e.EffectiveStartTime(), e.AuthTime)
	}
}

// The reference encoding writes starttime even though it equals
// authtime, so the encoder must not second-guess the field. This is
// the case that would break if the KDC's own
// starttime-equals-authtime rule were moved into the codec.
func TestStartTimeIsWrittenEvenWhenItEqualsAuthTime(t *testing.T) {
	e, err := UnmarshalEncKDCRepPart(ref(t, refEncKDCRepPart))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !e.StartTime.Equal(e.AuthTime) {
		t.Fatal("fixture no longer has starttime == authtime")
	}
	got, err := MarshalEncASRepPart(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(got, []byte{0xA6, 0x11, 0x18, 0x0F}) {
		t.Error("starttime dropped")
	}
}

// RenewTill without FlagRenewable is dropped, which is upstream's
// rule and a trap for anyone who sets the field and expects it to
// travel.
func TestRenewTillNeedsTheRenewableFlag(t *testing.T) {
	e, err := UnmarshalEncKDCRepPart(
		ref(t, refEncKDCRepPartNoOpt))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	e.RenewTill = e.EndTime
	withoutFlag, err := MarshalEncASRepPart(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	e.Flags |= FlagRenewable
	withFlag, err := MarshalEncASRepPart(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(withFlag) <= len(withoutFlag) {
		t.Error("renew-till absent even with the flag set")
	}
	if bytes.Contains(withoutFlag, []byte{0xA8}) {
		t.Error("renew-till written without the flag")
	}
}

func TestASRepMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"with padata", refASRep},
		{"no padata", refASRepNoOpt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			r, err := UnmarshalASRep(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalASRep(r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// The nested ticket is a context tag wrapped around an
// APPLICATION-tagged type, which encoding/asn1 cannot express as one
// field. This checks the nesting survives rather than just that the
// bytes round-trip, since a RawValue would round-trip even if the
// ticket inside it were never looked at.
func TestASRepCarriesADecodableTicket(t *testing.T) {
	r, err := UnmarshalASRep(ref(t, refASRep))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.CRealm != "ATHENA.MIT.EDU" {
		t.Errorf("crealm is %q", r.CRealm)
	}
	if got := r.CName.String(); got != "hftsai/extra" {
		t.Errorf("cname is %q", got)
	}
	if r.Ticket.Realm != "ATHENA.MIT.EDU" {
		t.Errorf("ticket realm is %q", r.Ticket.Realm)
	}
	if len(r.PAData) != 2 {
		t.Fatalf("got %d padata entries", len(r.PAData))
	}
	if r.PAData[0].Type != 13 {
		t.Errorf("padata type is %d", r.PAData[0].Type)
	}
	if string(r.PAData[0].Value) != "pa-data" {
		t.Errorf("padata value is %q", r.PAData[0].Value)
	}
}

// No padata must mean no field, not an empty SEQUENCE: upstream's
// DEFOPTIONALEMPTYTYPE writes nothing, and encoding/asn1 would
// happily write "30 00" for an empty non-nil slice.
func TestASRepWithoutPADataOmitsTheField(t *testing.T) {
	r, err := UnmarshalASRep(ref(t, refASRepNoOpt))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.PAData != nil {
		t.Errorf("padata decoded as %#v, want nil", r.PAData)
	}
	got, err := MarshalASRep(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(got, []byte{0xA2, 0x00}) {
		t.Error("wrote an empty padata SEQUENCE")
	}
}

func TestASReqMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"all fields", refASReq},
		{"only second-ticket", refASReqOnlyTkt},
		{"only server", refASReqOnlySrv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			r, err := UnmarshalASReq(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalASReq(r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// The body carries one realm and two principals, and the realm
// belongs to both. The only-second-ticket fixture has neither name,
// which is the case a decoder that hung the realm off a principal
// would lose it in.
func TestASReqBodyKeepsTheRealmApartFromTheNames(t *testing.T) {
	r, err := UnmarshalASReq(ref(t, refASReq))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.Body.Realm != "ATHENA.MIT.EDU" {
		t.Errorf("realm is %q", r.Body.Realm)
	}
	if r.Body.CName == nil || r.Body.SName == nil {
		t.Fatal("cname or sname missing")
	}
	if !r.Body.CName.Equal(*r.Body.SName) {
		t.Error("fixture's two names stopped matching")
	}
	if want := []int32{0, 1}; len(r.Body.EType) != len(want) {
		t.Fatalf("etypes are %v, want %v", r.Body.EType, want)
	}

	nameless, err := UnmarshalASReq(ref(t, refASReqOnlyTkt))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if nameless.Body.CName != nil || nameless.Body.SName != nil {
		t.Error("decoded a name that is not on the wire")
	}
	if nameless.Body.Realm != "ATHENA.MIT.EDU" {
		t.Errorf("realm lost: %q", nameless.Body.Realm)
	}
}

// KDC-REQ numbers its context tags from 1. The reference bytes open
// 6A 82 01 E4 30 82 01 E0 A1, and that A1 -- not A0 -- is the whole
// point: a struct numbered from zero decodes as garbage.
func TestASReqContextTagsStartAtOne(t *testing.T) {
	b := ref(t, refASReqOnlySrv)
	if b[4] != 0xA1 {
		t.Fatalf("fixture's first body tag is %02X", b[4])
	}
	if _, err := UnmarshalASReq(b); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Renumbering pvno to [0] must be rejected rather than
	// quietly accepted as some other field.
	b[4] = 0xA0
	if _, err := UnmarshalASReq(b); err == nil {
		t.Error("accepted pvno at [0]")
	}
}

func TestKRBErrorMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"all fields", refKRBError},
		{"optionals absent", refKRBErrorNoOpt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			e, err := UnmarshalKRBError(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalKRBError(e)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// cusec is optional and susec is not, so the optionals-absent fixture
// drops ctime while keeping a cusec of 123456 -- a combination that
// looks like a bug until you read asn1_k_encode.c:914-917.
func TestKRBErrorMicrosecondsAreAsymmetric(t *testing.T) {
	e, err := UnmarshalKRBError(ref(t, refKRBErrorNoOpt))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !e.CTime.IsZero() {
		t.Errorf("ctime decoded as %v, want absent", e.CTime)
	}
	if e.CUsec != 123456 {
		t.Errorf("cusec is %d, want 123456", e.CUsec)
	}
	if e.CName != nil {
		t.Errorf("cname is %v, want absent", e.CName)
	}
	if e.ErrorCode != ErrCodeGeneric {
		t.Errorf("error code is %d", e.ErrorCode)
	}
}

// e-text is a GeneralString and e-data an OCTET STRING, and both hold
// the same eight bytes in the fixture -- so a codec that confused the
// two would round-trip and still be wrong.
func TestKRBErrorETextIsAGeneralString(t *testing.T) {
	e, err := UnmarshalKRBError(ref(t, refKRBError))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.EText != "krb5data" {
		t.Errorf("e-text is %q", e.EText)
	}
	if string(e.EData) != "krb5data" {
		t.Errorf("e-data is %q", e.EData)
	}
	got, err := MarshalKRBError(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Contains(got, []byte{0xAB, 0x0A, 0x1B, 0x08}) {
		t.Error("e-text not written as a GeneralString")
	}
	if !bytes.Contains(got, []byte{0xAC, 0x0A, 0x04, 0x08}) {
		t.Error("e-data not written as an OCTET STRING")
	}
}

func TestETypeInfo2MatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"three entries", refETypeInfo2},
		{"one entry", refETypeInfo2One},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			es, err := UnmarshalETypeInfo2(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalETypeInfo2(es)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// The middle entry of the fixture has no salt at all while the other
// two do. Upstream's presence predicate is length != -1, so a
// zero-length salt would be *present*: absent and empty are different
// here, and this is the one field in the package where they are.
func TestETypeInfo2DistinguishesAbsentFromEmptySalt(t *testing.T) {
	es, err := UnmarshalETypeInfo2(ref(t, refETypeInfo2))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(es) != 3 {
		t.Fatalf("got %d entries, want 3", len(es))
	}
	if es[0].Salt == nil || *es[0].Salt != "Morton's #0" {
		t.Errorf("entry 0 salt is %v", es[0].Salt)
	}
	if es[1].Salt != nil {
		t.Errorf("entry 1 salt is %q, want none",
			*es[1].Salt)
	}
	if string(es[1].S2KParams) != "s2k: 1" {
		t.Errorf("entry 1 s2kparams is %q", es[1].S2KParams)
	}

	// An empty salt must survive as present, which is what the
	// pointer is for.
	empty := ""
	es[1].Salt = &empty
	b, err := MarshalETypeInfo2(es[1:2])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := UnmarshalETypeInfo2(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back[0].Salt == nil {
		t.Error("empty salt came back absent")
	}
}

func TestPAEncTSEncMatchesTheReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		{"with usec", refPAEncTS},
		{"no usec", refPAEncTSNoUsec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ref(t, tc.hex)
			p, err := UnmarshalPAEncTSEnc(want)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			got, err := MarshalPAEncTSEnc(p)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			roundTrip(t, want, got)
		})
	}
}

// An AP-REP is three fields and a reference encoding makes short work
// of it, but the one thing worth asserting by hand is the message
// type: the application tag and the msg-type field are both 15, so a
// reader who confused them would still get 15 and never find out.
func TestAPRepMatchesTheReference(t *testing.T) {
	want := ref(t, refAPRep)
	r, err := UnmarshalAPRep(want)
	if err != nil {
		t.Fatalf("UnmarshalAPRep: %v", err)
	}
	if r.EncPart.KVNO != 5 {
		t.Errorf("kvno = %d, want 5", r.EncPart.KVNO)
	}
	got, err := MarshalAPRep(r)
	if err != nil {
		t.Fatalf("MarshalAPRep: %v", err)
	}
	roundTrip(t, want, got)
}

// Both forms of the sealed half, because absence is most of what
// there is to get wrong: cusec is mandatory here while the subkey and
// the sequence number are not, and upstream publishes an encoding of
// each.
func TestEncAPRepPartMatchesTheReference(t *testing.T) {
	for _, c := range []struct {
		name   string
		fix    string
		subKey bool
		seq    uint32
	}{
		{"all fields", refEncAPRepPart, true, 17},
		{"optionals absent", refEncAPRepPartNoOpt, false, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			checkEncAPRepPart(t, ref(t, c.fix),
				c.subKey, c.seq)
		})
	}
}

func checkEncAPRepPart(
	t *testing.T, want []byte, subKey bool, seq uint32,
) {
	t.Helper()
	p, err := UnmarshalEncAPRepPart(want)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if p.CUsec != 123456 {
		t.Errorf("cusec = %d", p.CUsec)
	}
	if (p.SubKey != nil) != subKey {
		t.Errorf("subkey %v", p.SubKey)
	}
	if p.SeqNumber != seq {
		t.Errorf("seq = %d, want %d", p.SeqNumber, seq)
	}
	got, err := MarshalEncAPRepPart(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	roundTrip(t, want, got)
}

// KRB-PRIV's enc-part is at context tag 3 and not 2, because RFC 4120
// leaves 2 unused. The reference encoding settles it -- which is the
// whole reason these tests exist, because nothing about reading the
// structure definition would have raised the question.
func TestKRBPrivMatchesTheReference(t *testing.T) {
	want := ref(t, refKRBPriv)
	p, err := UnmarshalKRBPriv(want)
	if err != nil {
		t.Fatalf("UnmarshalKRBPriv: %v", err)
	}
	if p.EncPart.KVNO != 5 {
		t.Errorf("kvno = %d, want 5", p.EncPart.KVNO)
	}
	got, err := MarshalKRBPriv(p)
	if err != nil {
		t.Fatalf("MarshalKRBPriv: %v", err)
	}
	roundTrip(t, want, got)
}

// And both forms of its sealed half. The pairing that matters is
// which fields survive in the shorter one: the user data and the
// *sender's* address, because s-address is mandatory and r-address is
// not.
func TestEncKRBPrivPartMatchesTheReference(t *testing.T) {
	for _, c := range []struct {
		name  string
		fix   string
		stamp bool
		seq   uint32
		rAddr bool
	}{
		{"all fields", refEncKRBPrivPart, true, 17, true},
		{"optionals absent", refEncKRBPrivPartNoOpt,
			false, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			checkEncKRBPrivPart(t, ref(t, c.fix),
				c.stamp, c.seq, c.rAddr)
		})
	}
}

func checkEncKRBPrivPart(
	t *testing.T,
	want []byte,
	stamp bool,
	seq uint32,
	rAddr bool,
) {
	t.Helper()
	p, err := UnmarshalEncKRBPrivPart(want)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(p.UserData) != "krb5data" {
		t.Errorf("user-data %q", p.UserData)
	}
	if p.SAddress.Type != 2 || len(p.SAddress.Address) != 4 {
		t.Errorf("s-address %v", p.SAddress)
	}
	if !p.Timestamp.IsZero() != stamp {
		t.Errorf("timestamp %v", p.Timestamp)
	}
	if p.SeqNumber != seq {
		t.Errorf("seq = %d, want %d", p.SeqNumber, seq)
	}
	if (p.RAddress != nil) != rAddr {
		t.Errorf("r-address %v", p.RAddress)
	}
	got, err := MarshalEncKRBPrivPart(p)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	roundTrip(t, want, got)
}

// The directional addresses are what this project sends, because a
// KDC reached over HTTPS has no address of its own to name: the
// kpasswd frame arrives inside an HTTP body and the socket beneath
// belongs to the transport. Upstream falls back to exactly these when
// it cannot determine one (schpw.c:290, kpropd.c:1203), so the bytes
// have to match (lib/krb5/os/addr.c:36-41).
func TestDirectionalAddresses(t *testing.T) {
	init, accept := DirectionalInit(), DirectionalAccept()
	if init.Type != AddrTypeDirectional ||
		accept.Type != AddrTypeDirectional {
		t.Fatalf("types %d and %d", init.Type, accept.Type)
	}
	if string(init.Address) != "\x00\x00\x00\x00" {
		t.Errorf("initiator %v", init.Address)
	}
	if string(accept.Address) != "\x00\x00\x00\x01" {
		t.Errorf("acceptor %v", accept.Address)
	}
	// And they survive a round trip through the only message that
	// carries one.
	der, err := MarshalEncKRBPrivPart(EncKRBPrivPart{
		UserData: []byte("x"),
		SAddress: accept,
	})
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalEncKRBPrivPart(der)
	if err != nil {
		t.Fatal(err)
	}
	if back.SAddress.Type != accept.Type ||
		string(back.SAddress.Address) !=
			string(accept.Address) {
		t.Errorf("round trip gave %v", back.SAddress)
	}
}

// ChangePasswdData has no reference encoding: upstream's test program
// does not cover encode_krb5_setpw_req, so this is a round trip
// against itself with the shape asserted by hand. The same treatment
// KDC-PROXY-MESSAGE gets, and for the same reason -- it is checked
// for real by a stock kpasswd, not here.
func TestChangePasswdDataRoundTrips(t *testing.T) {
	for _, c := range []struct {
		name string
		in   ChangePasswdData
	}{
		// A self change sends no target at all, which is what
		// the server reads as "mine".
		{"self", ChangePasswdData{
			NewPassword: []byte("new-password"),
		}},
		// And setting someone else's splits the one principal
		// across two fields, as upstream's encoder does.
		{"a named target", ChangePasswdData{
			NewPassword: []byte("new-password"),
			TargName: &PrincipalName{
				Type:       NTPrincipal,
				Components: []string{"alice"},
			},
			TargRealm: "KDIAMOND.TEST",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			checkChangePasswdData(t, c.in)
		})
	}
}

func checkChangePasswdData(t *testing.T, in ChangePasswdData) {
	t.Helper()
	der, err := MarshalChangePasswdData(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalChangePasswdData(der)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.NewPassword) != string(in.NewPassword) {
		t.Errorf("password %q", got.NewPassword)
	}
	if (got.TargName != nil) != (in.TargName != nil) {
		t.Errorf("target %v", got.TargName)
	}
	if got.TargRealm != in.TargRealm {
		t.Errorf("realm %q", got.TargRealm)
	}
	if in.TargName != nil &&
		!got.TargName.Equal(*in.TargName) {
		t.Errorf("name %v", got.TargName)
	}
}

// The outer shape is a bare SEQUENCE with no application tag, which
// is what makes it different from every other message here and is
// worth one assertion rather than a comment alone.
func TestChangePasswdDataIsABareSequence(t *testing.T) {
	der, err := MarshalChangePasswdData(ChangePasswdData{
		NewPassword: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(der) == 0 || der[0] != 0x30 {
		t.Errorf("first octet is %#x, want 0x30", der[0])
	}
}
