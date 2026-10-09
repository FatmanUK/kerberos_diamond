package spnego

import (
	"bytes"
	"testing"
)

// The captured token decodes, and every field of it is what the
// framing says it is.
func TestRealNegTokenInitDecodes(t *testing.T) {
	init, err := UnmarshalNegTokenInit(realToken(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(init.MechTypes) != 1 ||
		!init.MechTypes[0].Equal(MechKrb5) {
		t.Fatalf("mechTypes is %v", init.MechTypes)
	}
	// The two optional fields a real initiator omits.
	if init.ReqFlags != 0 {
		t.Errorf("reqFlags appeared: %#x", init.ReqFlags)
	}
	if init.MechListMIC != nil {
		t.Errorf("a mechListMIC appeared")
	}
	// DERMechTypes is kept for a MIC nobody computes here, and it
	// has to be the encoded SEQUENCE OF and not the OID alone.
	if !bytes.HasPrefix(init.DERMechTypes, []byte{tagSeq}) {
		t.Errorf("DERMechTypes is %x", init.DERMechTypes)
	}
}

// And the mechToken inside it is an RFC 4121 AP-REQ token, which is
// the half the acceptor actually authenticates.
func TestRealMechTokenIsAnAPReq(t *testing.T) {
	init, err := UnmarshalNegTokenInit(realToken(t))
	if err != nil {
		t.Fatal(err)
	}
	der, mech, err := APReqToken(init.MechToken)
	if err != nil {
		t.Fatal(err)
	}
	if !mech.Equal(MechKrb5) {
		t.Errorf("mech is %x", mech)
	}
	// APPLICATION 14 is KRB-AP-REQ (asn1_k_encode.c:752).
	if len(der) == 0 || der[0] != 0x6e {
		t.Errorf("not an AP-REQ: % x", der[:min(8, len(der))])
	}
}

// The order rule, which is the whole of RFC 4178's downgrade
// protection: Kerberos at the head of the list is accepted and
// Kerberos anywhere else demands a mechListMIC first (negotiate_mech,
// spnego_mech.c:3240-3250).
func TestNegotiationDependsOnPreferenceOrder(t *testing.T) {
	ntlm := OID("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
	for _, c := range []struct {
		why   string
		offer []OID
		mech  OID
		state NegState
	}{
		{"krb5 alone", []OID{MechKrb5}, MechKrb5,
			AcceptIncomplete},
		{"krb5 first", []OID{MechKrb5, ntlm}, MechKrb5,
			AcceptIncomplete},
		{"krb5 second", []OID{ntlm, MechKrb5}, MechKrb5,
			RequestMIC},
		{"no krb5", []OID{ntlm}, nil, Reject},
	} {
		t.Run(c.why, func(t *testing.T) {
			n := &NegTokenInit{MechTypes: c.offer}
			mech, state := n.Negotiate()
			if state != c.state {
				t.Errorf("state %d, want %d", state,
					c.state)
			}
			if !mech.Equal(c.mech) {
				t.Errorf("mech %x", mech)
			}
		})
	}
}

// Microsoft's mis-encoded OID is accepted and **answered with the
// spelling that arrived** (:3234-3237 and :3251-3254), so that a
// client comparing the supportedMech against what it sent still
// agrees. Answering with the correct OID would be more standards
// compliant and would break the client.
func TestTheBrokenMicrosoftOIDComesBackUnchanged(t *testing.T) {
	n := &NegTokenInit{MechTypes: []OID{MechKrb5Wrong}}
	mech, state := n.Negotiate()
	if state != AcceptIncomplete {
		t.Fatalf("state %d", state)
	}
	if !mech.Equal(MechKrb5Wrong) {
		t.Errorf("answered %x, want the broken OID", mech)
	}
	// It differs from the real one in exactly one octet, which is
	// worth asserting because a transcription slip anywhere else
	// would make the constant match nothing at all.
	var diff int
	for i := range MechKrb5 {
		if MechKrb5[i] != MechKrb5Wrong[i] {
			diff++
		}
	}
	if diff != 1 {
		t.Errorf("the two OIDs differ in %d octets", diff)
	}
}

// ContextFlags has exactly one acceptable encoding, and it is not the
// one DER requires.
//
// get_req_flags (spnego_mech.c:3392-3404) demands four octets reading
// 03 02 01 <flags>: a BIT STRING with two content octets and **one
// padding bit**, whatever the flags actually are. DER requires a BIT
// STRING's padding to be the minimum, so the strictly correct
// encoding of a flags word with its low bits clear has a different
// padding count -- and upstream would refuse it.
//
// So there is one interoperable encoding and it is upstream's.
// Matching the decoder rather than the standard is the
// behaviour-compatible choice, and this asserts it in both directions
// so that a later tidy-up cannot quietly break it.
func TestContextFlagsHasOneAcceptableEncoding(t *testing.T) {
	for _, flags := range []uint32{0x01, 0x20, 0x7f} {
		out := reqFlagsDER(flags)
		if len(out) != 4 || out[1] != 0x02 ||
			out[2] != 0x01 {
			t.Fatalf("%#x encoded as % x", flags, out)
		}
		got, ok := parseReqFlags(out)
		if !ok || got != flags {
			t.Errorf("%#x round-tripped to %#x (%v)",
				flags, got, ok)
		}
	}
	// Anything else is refused, padding count included.
	for _, bad := range [][]byte{
		{},
		{tagBitStr, 0x02, 0x01},
		{tagBitStr, 0x02, 0x00, 0x20},
		{tagBitStr, 0x03, 0x01, 0x20, 0x00},
		{tagOctetStr, 0x02, 0x01, 0x20},
	} {
		if _, ok := parseReqFlags(bad); ok {
			t.Errorf("% x was accepted", bad)
		}
	}
}

// A NegTokenInit this package encoded decodes back, which is what
// makes the cases a capture cannot reach testable at all: a second
// mechanism, a reqFlags field and a mechListMIC never appear in a
// real gss-client token.
func TestNegTokenInitRoundTrips(t *testing.T) {
	want := NegTokenInit{
		MechTypes:   []OID{MechKrb5Old, MechKrb5},
		ReqFlags:    FlagMutual | FlagInteg,
		MechToken:   []byte{0x6e, 0x01},
		MechListMIC: []byte("a MIC"),
	}
	got, err := UnmarshalNegTokenInit(want.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.MechTypes) != 2 ||
		!got.MechTypes[0].Equal(MechKrb5Old) ||
		!got.MechTypes[1].Equal(MechKrb5) {
		t.Errorf("mechTypes %v", got.MechTypes)
	}
	if got.ReqFlags != want.ReqFlags {
		t.Errorf("reqFlags %#x", got.ReqFlags)
	}
	if string(got.MechToken) != string(want.MechToken) ||
		string(got.MechListMIC) != string(want.MechListMIC) {
		t.Errorf("got %+v", got)
	}
	// And the old OID first means the correct one is not the
	// preference, so the negotiation asks for a MIC.
	if _, state := got.Negotiate(); state != AcceptIncomplete {
		t.Errorf("state %d: the old OID is Kerberos too",
			state)
	}
}

// A NegTokenResp round-trips, and an empty one is legal: upstream
// treats every field as optional (:3480-3520).
func TestNegTokenRespRoundTrips(t *testing.T) {
	r, err := UnmarshalNegTokenResp(NegTokenResp{
		State:         RequestMIC,
		SupportedMech: MechKrb5,
		ResponseToken: []byte{0x6f},
		MechListMIC:   []byte("mic"),
	}.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if r.State != RequestMIC ||
		!r.SupportedMech.Equal(MechKrb5) ||
		string(r.MechListMIC) != "mic" {
		t.Errorf("got %+v", r)
	}
	// An absent negState decodes as -1 rather than as
	// AcceptComplete, which is zero: a caller must be able to
	// tell "the acceptor said nothing" from "the acceptor said we
	// are done".
	bare := []byte{tagContext | 0x01, 0x02, tagSeq, 0x00}
	empty, err := UnmarshalNegTokenResp(bare)
	if err != nil {
		t.Fatal(err)
	}
	if empty.State != -1 {
		t.Errorf("an absent negState decoded as %d",
			empty.State)
	}
}
