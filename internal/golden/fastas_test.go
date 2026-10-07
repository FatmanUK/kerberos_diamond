package golden

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// armoredAS is a FAST-armored AS-REQ.
//
// It needs something a TGS request does not: a *separate* ticket to
// armor with, because an AS request carries nothing authenticated of
// its own. That is the whole asymmetry of FAST -- it cannot protect
// the first exchange a client ever makes, only every one after it.
type armoredAS struct {
	msg   []byte
	armor []byte
	p     *crypto.EncProfile
	nonce int32
}

// buildArmoredAS assembles one from an armor TGT the caller already
// holds. inner is the padata that goes *inside* the tunnel, and
// getting it there is the whole point: the outer request's padata
// holds only PA-FX-FAST. The first draft of this passed the body
// alone and dropped the PA-PAC-REQUEST(false) that declines a Windows
// PAC, so the C KDC put a signed one in its ticket and the Go KDC did
// not -- which the comparison reported as 182 octets of authorization
// data.
func buildArmoredAS(
	t *testing.T,
	g tgt,
	body wire.KDCReqBody,
	inner []wire.PAData,
) armoredAS {
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
	ap := armorField(t, g, p, sub)
	// The outer body is the inner body with the padata stripped,
	// and a KDC-REQ-BODY has no padata field -- so they are the
	// same bytes (krb5int_fast_prep_req_body, fast.c:143-168).
	draft, err := wire.MarshalASReq(wire.ASReq{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	fast := sealFastASReq(t, p, armor, body, ap, outer, inner)
	msg, err := wire.MarshalASReq(wire.ASReq{
		PAData: []wire.PAData{fast},
		Body:   body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return armoredAS{
		msg: msg, armor: armor, p: p, nonce: body.Nonce,
	}
}

// armorField builds the AP-REQ that goes in the armor field.
//
// Its authenticator is encrypted at key usage 11, not 7: this is an
// ordinary application AP-REQ that happens to travel inside a KDC
// request, and upstream reaches it through krb5_rd_req rather than
// through its TGS path.
func armorField(
	t *testing.T,
	g tgt,
	p *crypto.EncProfile,
	sub []byte,
) wire.KrbFastArmor {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	plain, err := wire.MarshalAuthenticator(wire.Authenticator{
		CRealm: Realm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{UserName},
		},
		CUsec:  1234,
		CTime:  now,
		SubKey: subKeyOf(p, sub),
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(g.session, plain,
		crypto.UsageAPReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	der, err := wire.MarshalAPReq(wire.APReq{
		Ticket: g.ticket,
		Authenticator: wire.EncryptedData{
			EType:  int32(p.EncType),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.KrbFastArmor{
		Type:  wire.FastArmorAPRequest,
		Value: der,
	}
}

// sealFastASReq wraps the inner AS request. The checksum is over the
// *outer* req-body here, where the TGS path checksums the AP-REQ
// (do_as_req.c:525-531).
func sealFastASReq(
	t *testing.T,
	p *crypto.EncProfile,
	armor []byte,
	body wire.KDCReqBody,
	ap wire.KrbFastArmor,
	outer []byte,
	inner []wire.PAData,
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
	sum, err := p.Checksum(armor, outer, crypto.UsageFASTReqCksum)
	if err != nil {
		t.Fatal(err)
	}
	val, err := wire.MarshalPAFXFastRequest(
		wire.KrbFastArmoredReq{
			Armor: ap,
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

// openArmoredAS decodes a FAST-armored AS reply the way a client
// does.
func openArmoredAS(
	t *testing.T,
	raw []byte,
	a armoredAS,
	password string,
	components []string,
) Exchange {
	t.Helper()
	rep := decodeReply(t, raw)
	resp := openASFastResponse(t, rep, a)

	p, err := crypto.Profile(crypto.EncType(rep.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	base, err := p.StringToKey(password,
		crypto.Salt(Realm, components), nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.CF2(resp.StrengthenKey.KeyValue,
		"strengthenkey", p, base, "replykey")
	if err != nil {
		t.Fatal(err)
	}
	enc := decryptPart(t, rep.EncPart, key,
		crypto.UsageASRepEncPart)
	tkt := decrypt(t, rep.Ticket.EncPart, TgtPassword,
		[]string{"krbtgt", Realm}, crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// openASFastResponse unwraps the tunnel and makes the three checks a
// client makes before it will look at the reply at all.
func openASFastResponse(
	t *testing.T,
	rep wire.ASRep,
	a armoredAS,
) wire.KrbFastResponse {
	t.Helper()
	if n := len(rep.PAData); n != 1 ||
		rep.PAData[0].Type != wire.PAFXFast {
		t.Fatalf("the reply's padata is %+v, want one "+
			"PA-FX-FAST", rep.PAData)
	}
	ed, err := wire.UnmarshalPAFXFastReply(rep.PAData[0].Value)
	if err != nil {
		t.Fatalf("PA-FX-FAST-REPLY: %v", err)
	}
	plain, err := a.p.Decrypt(a.armor, ed.Cipher,
		crypto.UsageFASTRep)
	if err != nil {
		t.Fatalf("the armor key did not open it: %v", err)
	}
	resp, err := wire.UnmarshalKrbFastResponse(plain)
	if err != nil {
		t.Fatalf("KrbFastResponse: %v", err)
	}
	if resp.Nonce != a.nonce {
		t.Errorf("nonce is %d, want %d", resp.Nonce, a.nonce)
	}
	if resp.Finished.Timestamp.IsZero() {
		t.Fatal("no finished field; a client refuses that")
	}
	assertTicketChecksum(t, rep.Ticket, resp, a)
	return resp
}

func assertTicketChecksum(
	t *testing.T,
	tkt wire.Ticket,
	resp wire.KrbFastResponse,
	a armoredAS,
) {
	t.Helper()
	der, err := wire.MarshalTicket(tkt)
	if err != nil {
		t.Fatal(err)
	}
	err = a.p.VerifyChecksum(a.armor, der,
		resp.Finished.TicketChecksum.Checksum,
		crypto.UsageFASTFinished)
	if err != nil {
		t.Errorf("the ticket checksum fails: %v", err)
	}
}

// TestFASTASExchangeMatchesTheC is the differential test for an
// armored AS exchange.
//
// **No stock client reaches this path yet**, because kinit -T needs
// either fast_avail in its cache or an advertised hint list, and this
// KDC provides neither until step 5 and step 4 respectively. So the
// harness is the only anchor here, and that is worth stating rather
// than leaving to be inferred.
func TestFASTASExchangeMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	// The armor ticket is an ordinary TGT, obtained the ordinary
	// way. A client would use one it already held.
	g, _ := getTGTFromTheC(t, ctx, o)
	req := asRequest(t, UserName, in(requestedLife))
	// The request's own padata goes inside the tunnel,
	// PA-PAC-REQUEST included, plus a PA-REQ-ENC-PA-REP so the
	// reply checksum is exercised here too -- it is keyed with
	// the *strengthened* key under FAST, which nothing else would
	// catch.
	inner := append(req.PAData,
		wire.PAData{Type: wire.PAReqEncPARep})
	a := buildArmoredAS(t, g, req.Body, inner)

	cRaw, err := o.SendRaw(ctx, a.msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openArmoredAS(t, cRaw, a, UserPassword,
		[]string{UserName})

	d := diamond(t, "kd_golden_fast_as",
		pinned(cx.Enc.AuthTime))
	goRaw, err := d.KDC.Handle(a.msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openArmoredAS(t, goRaw, a, UserPassword,
		[]string{UserName})

	assertSucceeded(t, cx)
	assertSucceeded(t, gx)
	reportDiffs(t, cx, gx, fastExemptions()...)
}
