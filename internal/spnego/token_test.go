package spnego

import (
	"bytes"
	"testing"
)

// The outermost length must account for the whole input and not
// merely fit inside it (g_verify_token_header,
// generic/util_token.c:109-118). Trailing octets are a refusal.
//
// It matters here more than it does in a C library: an HTTP Negotiate
// header is base64 decoded by somebody else, and an encoder that
// padded the token would otherwise hand the extra octets to the
// AP-REQ parser.
func TestATokenWithTrailingOctetsIsRefused(t *testing.T) {
	good := realToken(t)
	if _, err := UnmarshalNegTokenInit(good); err != nil {
		t.Fatalf("the fixture stopped parsing: %v", err)
	}
	long := append(append([]byte{}, good...), 0)
	if _, err := UnmarshalNegTokenInit(long); err == nil {
		t.Error("an extra octet was accepted")
	}
	short := good[:len(good)-1]
	if _, err := UnmarshalNegTokenInit(short); err == nil {
		t.Error("a truncated token was accepted")
	}
}

// The framing round-trips, and the two-octet token identifier lands
// where RFC 4121 puts it: immediately after the mechanism OID, big
// endian, inside the outermost length.
func TestMechTokenFramingRoundTrips(t *testing.T) {
	body := []byte{0x6e, 0x01, 0x02}
	out := MechToken{
		Mech: MechKrb5, TokID: TokIDAPReq, Body: body,
	}.Marshal()
	// 60 <len> 06 09 <oid> 01 00 <body>
	want := []byte{0x60, byte(2 + 9 + 2 + len(body)),
		0x06, 0x09}
	want = append(want, MechKrb5...)
	want = append(want, 0x01, 0x00)
	want = append(want, body...)
	if !bytes.Equal(out, want) {
		t.Fatalf("got % x\nwant % x", out, want)
	}
	back, err := ParseMechToken(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.TokID != TokIDAPReq ||
		!bytes.Equal(back.Body, body) {
		t.Errorf("got %+v", back)
	}
}

// A token under a mechanism that is not Kerberos is refused with its
// own error, because an acceptor answers differently for it: the
// wrong mechanism is a renegotiation and bad framing is a malformed
// request.
func TestANonKerberosMechTokenIsRefused(t *testing.T) {
	out := MechToken{
		Mech:  OID("\x2b\x06\x01\x05\x05\x02"),
		TokID: TokIDAPReq,
		Body:  []byte{1},
	}.Marshal()
	if _, err := ParseMechToken(out); err != ErrWrongMech {
		t.Errorf("got %v, want ErrWrongMech", err)
	}
}

// An AP-REP token, and the one thing about it that is a decision: the
// mechanism OID in the reply is the one that *arrived*
// (accept_sec_context.c:1101 uses mech_used), so a client that sent
// Microsoft's broken spelling is answered in it.
func TestAPRepTokenAnswersUnderTheSameMech(t *testing.T) {
	out := APRepToken(MechKrb5Wrong, []byte{0x6f, 0x00})
	back, err := ParseMechToken(out)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Mech.Equal(MechKrb5Wrong) {
		t.Errorf("answered under %x", back.Mech)
	}
	if back.TokID != TokIDAPRep {
		t.Errorf("token id %#x", back.TokID)
	}
}

// A NegTokenResp carries **no RFC 2743 framing**, which is the
// easiest thing to get wrong about it: the 0x60 wrapper and the
// SPNEGO OID appear on the first token of a conversation only, and
// upstream's emitter writes the [1] choice tag directly
// (make_spnego_tokenTarg_msg, spnego_mech.c:3761-3763).
func TestNegTokenRespIsNotFramed(t *testing.T) {
	out := NegTokenResp{
		State:         AcceptComplete,
		SupportedMech: MechKrb5,
		ResponseToken: []byte{0x6f, 0x00},
	}.Marshal()
	if out[0] != tagContext|0x01 {
		t.Fatalf("starts %#x, want a [1] tag", out[0])
	}
	// [1] { SEQUENCE { [0] ENUMERATED 0 ... } }
	want := []byte{0xa1, 0x1a, 0x30, 0x18, 0xa0, 0x03, 0x0a,
		0x01, 0x00, 0xa1, 0x0b, 0x06, 0x09}
	want = append(want, MechKrb5...)
	want = append(want, 0xa2, 0x04, 0x04, 0x02, 0x6f, 0x00)
	if !bytes.Equal(out, want) {
		t.Errorf("got  % x\nwant % x", out, want)
	}
}

// The optional fields of a NegTokenResp come out when they are set
// and stay out when they are not, and supportedMech staying out is
// the case that matters: upstream sends it on the acceptor's first
// reply only (:3736-3742).
func TestNegTokenRespOmitsWhatIsUnset(t *testing.T) {
	out := NegTokenResp{State: Reject}.Marshal()
	want := []byte{0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a,
		0x01, 0x02}
	if !bytes.Equal(out, want) {
		t.Errorf("got  % x\nwant % x", out, want)
	}
}
