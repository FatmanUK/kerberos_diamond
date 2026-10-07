package golden

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// armoredTGS is a FAST-armored TGS-REQ built the way a stock client
// builds one, and the enctype choices are not incidental.
//
// The subkey takes the *session key's* enctype, because
// krb5_generate_subkey copies the base key's
// (lib/krb5/krb/send_tgs.c:173) -- a subkey of some other enctype
// would make the two CF2 inputs disagree with what any real client
// produces.
//
// The outer and inner req-bodies are byte-identical, which is not a
// shortcut: krb5int_fast_prep_req_body encodes the outer from the
// same request with only the padata nulled
// (lib/krb5/krb/fast.c:143-168), and a KDC-REQ-BODY has no padata
// field. So one body serves both.
type armoredTGS struct {
	msg   []byte
	armor []byte
	p     *crypto.EncProfile
	nonce int32

	// sub is the authenticator's subkey, and it is the key the
	// reply's enc-part is sealed with -- not the ticket's session
	// key. A subkey in the authenticator replaces it and takes
	// key usage 9 with it (do_tgs_req.c:1113-1114). Keeping it
	// here is what stops the FAST cases reaching for the wrong
	// base key, which is exactly what the first draft of them
	// did.
	sub []byte
}

// buildArmoredTGS assembles one. The order is forced and worth
// following: body, then AP-REQ over that body, then the checksum over
// that AP-REQ, then the tunnel, then the outer message.
func buildArmoredTGS(
	t *testing.T,
	g tgt,
	body wire.KDCReqBody,
) armoredTGS {
	t.Helper()
	p, err := crypto.Profile(g.sessionEType)
	if err != nil {
		t.Fatal(err)
	}
	sub := randomKeyOf(t, p)
	armor, err := p.CF2(sub, "subkeyarmor", p, g.session,
		"ticketarmor")
	if err != nil {
		t.Fatal(err)
	}
	inner := []wire.PAData{{Type: wire.PAReqEncPARep}}
	ap := armorAPReq(t, g, p, sub, body)
	fast := sealFastReq(t, p, armor, inner, body, ap)
	msg, err := wire.MarshalTGSReq(wire.TGSReq{
		PAData: []wire.PAData{ap, fast},
		Body:   body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return armoredTGS{
		msg: msg, armor: armor, p: p, nonce: body.Nonce,
		sub: sub,
	}
}

// armorAPReq builds the PA-TGS-REQ, with the subkey in its
// authenticator -- which is what makes the armor key fresh.
func armorAPReq(
	t *testing.T,
	g tgt,
	p *crypto.EncProfile,
	sub []byte,
	body wire.KDCReqBody,
) wire.PAData {
	t.Helper()
	draft, err := wire.MarshalTGSReq(wire.TGSReq{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	ct := sealAuthenticatorSub(t, p, g.session, bodyDER,
		FarRealmNone, UserName, sub)
	apreq, err := wire.MarshalAPReq(wire.APReq{
		Ticket: g.ticket,
		Authenticator: wire.EncryptedData{
			EType:  int32(p.EncType),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{Type: wire.PATGSReq, Value: apreq}
}

// FarRealmNone is this realm, named for readability where a client's
// own realm is meant rather than a foreign one.
const FarRealmNone = Realm

// sealFastReq encrypts the inner request and wraps it as the
// PA-FX-FAST the outer message carries.
//
// The checksum is over the *AP-REQ*, not the body -- upstream's
// comment names both cases and the TGS path passes the AP-REQ bytes
// (kdc/fast_util.c:120-124, kdc/do_tgs_req.c:633-634). There is no
// armor field, because an AP-REQ armor is refused on this path.
func sealFastReq(
	t *testing.T,
	p *crypto.EncProfile,
	armor []byte,
	inner []wire.PAData,
	body wire.KDCReqBody,
	ap wire.PAData,
) wire.PAData {
	t.Helper()
	plain, err := wire.MarshalKrbFastReq(wire.KrbFastReq{
		PAData: inner,
		Body:   body,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(armor, plain, crypto.UsageFASTEnc)
	if err != nil {
		t.Fatal(err)
	}
	return wrapFastReq(t, p, armor, ct, ap.Value)
}

// wrapFastReq builds the PA-FX-FAST around an encrypted inner request
// and the checksum that binds it to the AP-REQ.
func wrapFastReq(
	t *testing.T,
	p *crypto.EncProfile,
	armor, ct, apreq []byte,
) wire.PAData {
	t.Helper()
	sum, err := p.Checksum(armor, apreq,
		crypto.UsageFASTReqCksum)
	if err != nil {
		t.Fatal(err)
	}
	val, err := wire.MarshalPAFXFastRequest(
		wire.KrbFastArmoredReq{
			ReqChecksum: wire.Checksum{
				Type:     int32(p.RequiredCksum),
				Checksum: sum,
			},
			EncPart: wire.EncryptedData{
				EType:  int32(p.EncType),
				Cipher: ct,
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{Type: wire.PAFXFast, Value: val}
}

func randomKeyOf(t *testing.T, p *crypto.EncProfile) []byte {
	t.Helper()
	k := make([]byte, p.KeyLength)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// openArmored decodes a FAST-armored reply the way a client does, and
// the order of the checks is the client's order
// (krb5int_fast_process_response, lib/krb5/krb/fast.c).
//
// This is worth more than the field diff that follows it. The diff
// cannot see a wrong ticket checksum, because both sides' ticket
// ciphertexts differ by their confounder anyway; and it cannot see a
// missing finished field as anything but an absence. A client treats
// either as KRB5_KDCREP_MODIFIED and refuses the reply outright, so
// the checks have to be made here or not at all.
func openArmored(
	t *testing.T,
	raw []byte,
	a armoredTGS,
	base []byte,
) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	resp := openFastResponse(t, rep, a)
	assertFinished(t, rep, resp, a)

	// The reply key is the strengthened one, and only the
	// strengthen key out of the tunnel produces it.
	key, err := a.p.CF2(resp.StrengthenKey.KeyValue,
		"strengthenkey", a.p, base, "replykey")
	if err != nil {
		t.Fatal(err)
	}
	enc := decryptPart(t, rep.EncPart, key,
		crypto.UsageTGSRepEncPartSubKey)
	tkt := decrypt(t, rep.Ticket.EncPart, ServicePassword,
		ServiceName, crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// openFastResponse unwraps the tunnel and checks the reply carries
// nothing but it.
func openFastResponse(
	t *testing.T,
	rep wire.TGSRep,
	a armoredTGS,
) wire.KrbFastResponse {
	t.Helper()
	if n := len(rep.PAData); n != 1 {
		t.Fatalf("the reply carries %d padata items, want "+
			"exactly one PA-FX-FAST", n)
	}
	if rep.PAData[0].Type != wire.PAFXFast {
		t.Fatalf("the reply's padata is type %d, want %d",
			rep.PAData[0].Type, wire.PAFXFast)
	}
	ed, err := wire.UnmarshalPAFXFastReply(rep.PAData[0].Value)
	if err != nil {
		t.Fatalf("PA-FX-FAST-REPLY: %v", err)
	}
	plain, err := a.p.Decrypt(a.armor, ed.Cipher,
		crypto.UsageFASTRep)
	if err != nil {
		t.Fatalf("the armor key did not open the reply: %v",
			err)
	}
	resp, err := wire.UnmarshalKrbFastResponse(plain)
	if err != nil {
		t.Fatalf("KrbFastResponse: %v", err)
	}
	return resp
}

// assertFinished makes the three checks a client makes before it will
// look at the reply at all.
func assertFinished(
	t *testing.T,
	rep wire.TGSRep,
	resp wire.KrbFastResponse,
	a armoredTGS,
) {
	t.Helper()
	if resp.Nonce != a.nonce {
		t.Errorf("the tunnel's nonce is %d, want the inner "+
			"request's %d", resp.Nonce, a.nonce)
	}
	if resp.Finished.Timestamp.IsZero() {
		t.Fatal("no finished field; a client refuses that")
	}
	der, err := wire.MarshalTicket(rep.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	err = a.p.VerifyChecksum(a.armor, der,
		resp.Finished.TicketChecksum.Checksum,
		crypto.UsageFASTFinished)
	if err != nil {
		t.Errorf("the ticket checksum fails: %v", err)
	}
	if resp.StrengthenKey.KeyType == 0 {
		t.Error("no strengthen key in the tunnel")
	}
}

// TestFASTTGSExchangeMatchesTheC is the differential test for an
// armored TGS exchange: one hand-built FAST request through both
// implementations, both replies unwrapped and checked, then diffed.
func TestFASTTGSExchangeMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, authTime := getTGTFromTheC(t, ctx, o)
	a := buildArmoredTGS(t, g, serviceBody())

	cRaw, err := o.SendRaw(ctx, a.msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openArmored(t, cRaw, a, a.sub)

	d := diamond(t, "kd_golden_fast_tgs",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(a.msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openArmored(t, goRaw, a, a.sub)

	assertTGSSucceeded(t, "oracle", cx, authTime)
	assertTGSSucceeded(t, "diamond", gx, authTime)
	// The two advertisement differences are the project's
	// standing exemption and nothing to do with this step; step 5
	// removes both the advertisement gap and the exemption
	// together.
	reportDiffs(t, cx, gx)
}

// The strengthened reply key is not the key the client started with,
// and asserting that is what says the strengthening happened at all
// -- a KDC that put a strengthen key in the tunnel and then sealed
// the enc-part with the unstrengthened key would pass every other
// check here.
func TestFASTStrengthensTheReplyKey(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, _ := getTGTFromTheC(t, ctx, o)
	a := buildArmoredTGS(t, g, serviceBody())
	d := diamond(t, "kd_golden_fast_strengthen", nil)
	raw, err := d.KDC.Handle(a.msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	rep := decodeTGSRep(t, raw)
	assertStrengthened(t, rep, a)
}

// assertStrengthened checks which key the enc-part was sealed with,
// both ways round.
//
// The first half says the strengthening was applied; the second that
// it was not applied and then ignored. Neither alone is enough: a KDC
// that put a strengthen key in the tunnel and sealed the enc-part
// with the unstrengthened key would pass every other check in this
// file.
func assertStrengthened(
	t *testing.T,
	rep wire.TGSRep,
	a armoredTGS,
) {
	t.Helper()
	resp := openFastResponse(t, rep, a)
	key, err := a.p.CF2(resp.StrengthenKey.KeyValue,
		"strengthenkey", a.p, a.sub, "replykey")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, a.sub) {
		t.Fatal("the strengthened key equals the base key")
	}
	_, err = a.p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageTGSRepEncPartSubKey)
	if err != nil {
		t.Errorf("the strengthened key did not open it: %v",
			err)
	}
	_, err = a.p.Decrypt(a.sub, rep.EncPart.Cipher,
		crypto.UsageTGSRepEncPartSubKey)
	if err == nil {
		t.Error("the base key opened the reply, so the " +
			"enc-part was not strengthened")
	}
}
