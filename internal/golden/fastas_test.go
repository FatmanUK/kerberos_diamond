package golden

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
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
// holds only PA-FX-FAST.
//
// The first draft of this passed the body alone and dropped the
// request's padata, which at the time included the
// PA-PAC-REQUEST(false) that declined a Windows PAC -- so the C KDC
// put a signed one in its ticket and the Go KDC did not, and the
// comparison reported 182 octets of authorization data. Both sides
// issue a PAC now, so that particular symptom has gone; what the note
// still records is that padata which does not reach the inside of the
// tunnel has not been sent at all.
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
	outer := outerBody(t, body)
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

// outerBody is the encoded KDC-REQ-BODY the FAST checksum covers.
//
// It is the inner body with the padata stripped, and a KDC-REQ-BODY
// has no padata field -- so they are the same bytes
// (krb5int_fast_prep_req_body, lib/krb5/krb/fast.c:143-168).
func outerBody(t *testing.T, body wire.KDCReqBody) []byte {
	t.Helper()
	draft, err := wire.MarshalASReq(wire.ASReq{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	return out
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
	ct := sealArmorAuth(t, p, g.session, sub)
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

// sealArmorAuth encrypts the armor AP-REQ's authenticator at key
// usage 11, which is an application AP-REQ's usage and not a TGS
// request's.
func sealArmorAuth(
	t *testing.T,
	p *crypto.EncProfile,
	session, sub []byte,
) []byte {
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
	ct, err := p.Encrypt(session, plain,
		crypto.UsageAPReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	return ct
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
	return wrapFastASReq(t, p, armor, ct, outer, ap)
}

// wrapFastASReq builds the PA-FX-FAST around an encrypted inner AS
// request, its armor field and the checksum over the outer body.
func wrapFastASReq(
	t *testing.T,
	p *crypto.EncProfile,
	armor, ct, outer []byte,
	ap wire.KrbFastArmor,
) wire.PAData {
	t.Helper()
	sum, err := p.Checksum(armor, outer,
		crypto.UsageFASTReqCksum)
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
	// The request's own padata goes inside the tunnel, plus a
	// PA-REQ-ENC-PA-REP so the reply checksum is exercised here
	// too -- it is keyed with the *strengthened* key under FAST,
	// which nothing else would catch.
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
	reportDiffs(t, cx, gx)
}

// TestStockKinitFASTAgainstTheGoKDC is the end-to-end check for FAST,
// and the first point in this work where a real client authenticates
// through the tunnel.
//
// It needs two kinits: the first obtains an ordinary TGT to armor
// with, because FAST cannot protect a client's first exchange, and
// the second upgrades to FAST with -T and answers an encrypted
// challenge. The principal is the one that demands
// pre-authentication, which is what makes the challenge happen at
// all.
func TestStockKinitFASTAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "fast", true)
	// SPAKE off for this case, because what it tests is the
	// **encrypted challenge** -- and a client takes the first
	// mechanism it understands, so a realm offering SPAKE gets
	// SPAKE and this case would stop covering what it is for. Off
	// is also the default a realm has until it is configured
	// (DEFAULT_GROUPS_KDC, groups.c:59-60), so this is an
	// ordinary realm rather than a contrived one.
	withoutSPAKE(t)
	armor := "/realm/fast-armor.ccache"
	out, err := o.ExecEnv(ctx,
		append(env, "KRB5CCNAME="+armor),
		UserPassword+"\n", "kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("the armor kinit failed: %v\n%s", err, out)
	}
	out, err = o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "-T", armor, PreauthName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -T failed: %v\n%s", err, out)
	}
	assertUsedFAST(t, out)
	assertTicket(t, ctx, o, env, PreauthName)
}

// assertUsedFAST reads the client's trace for the three things that
// say the tunnel was real.
//
// "FAST armor key" is the client deriving it; the challenge module
// returning success is the factor this KDC had to implement; and the
// armored error round trip is what the cookie exists for -- without
// one the client would not have retried at all.
func assertUsedFAST(t *testing.T, trace string) {
	t.Helper()
	for _, want := range []string{
		"FAST armor key",
		"Encoding request body and padata into FAST request",
		"Decoding FAST response",
		"encrypted_challenge (138) (real) returned: " +
			"0/Success",
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("no %q in the trace:\n%s",
				want, trace)
		}
	}
	// And a timestamp must *not* have been used: upstream's KDC
	// does not offer one inside a tunnel
	// (kdc/kdc_preauth_encts.c:38-43), so a client that sent one
	// would mean the hint list was wrong.
	if strings.Contains(trace, "PA-ENC-TIMESTAMP (2) (real)") {
		t.Errorf("a timestamp inside FAST:\n%s", trace)
	}
}

// TestFASTHintsMatchTheC compares the armored PREAUTH_REQUIRED both
// KDCs answer with, which is where the hint list and the cookie live.
//
// It compares types and not contents, deliberately. The etype-info's
// bytes are the same on both sides and already compared elsewhere;
// what this exists for is the *shape* -- which offers are made, in
// what order, and whether a cookie is there at all. A client acts on
// exactly that: it takes the first mechanism it understands, and it
// will not retry without a cookie.
func TestFASTHintsMatchTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, _ := getTGTFromTheC(t, ctx, o)
	req := asRequest(t, PreauthName, in(requestedLife))
	a := buildArmoredAS(t, g, req.Body, req.PAData)

	cRaw, err := o.SendRaw(ctx, a.msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	d := diamond(t, "kd_golden_fast_hints", nil)
	goRaw, err := d.KDC.Handle(a.msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	c := armoredHints(t, "oracle", cRaw, a)
	gh := armoredHints(t, "diamond", goRaw, a)
	if c != gh {
		t.Errorf("the hint lists differ:\n oracle:  %s\n"+
			"diamond: %s", c, gh)
	}
	// And the shape has to be the right one, not merely a shared
	// one: two KDCs that both omitted the cookie would agree
	// perfectly and neither would work.
	for _, want := range []string{"133", "137", "138"} {
		if !strings.Contains(c, want) {
			t.Errorf("the C's own hints lack type %s: %s",
				want, c)
		}
	}
}

// armoredHints unwraps an armored refusal and renders its inner
// padata types in order.
func armoredHints(
	t *testing.T,
	side string,
	raw []byte,
	a armoredAS,
) string {
	t.Helper()
	e, err := wire.UnmarshalKRBError(raw)
	if err != nil {
		t.Fatalf("%s: expected a KRB-ERROR: %v", side, err)
	}
	if e.ErrorCode != wire.ErrCodePreauthRequired {
		t.Fatalf("%s: code %d, want PREAUTH_REQUIRED",
			side, e.ErrorCode)
	}
	outer, err := wire.UnmarshalPADataSeq(e.EData)
	if err != nil {
		t.Fatalf("%s: e-data: %v", side, err)
	}
	if len(outer) != 1 || outer[0].Type != wire.PAFXFast {
		t.Fatalf("%s: e-data is %+v, want one PA-FX-FAST",
			side, outer)
	}
	ed, err := wire.UnmarshalPAFXFastReply(outer[0].Value)
	if err != nil {
		t.Fatalf("%s: reply wrapper: %v", side, err)
	}
	plain, err := a.p.Decrypt(a.armor, ed.Cipher,
		crypto.UsageFASTRep)
	if err != nil {
		t.Fatalf("%s: the armor key did not open it: %v",
			side, err)
	}
	resp, err := wire.UnmarshalKrbFastResponse(plain)
	if err != nil {
		t.Fatalf("%s: KrbFastResponse: %v", side, err)
	}
	return renderTypes(resp.PAData)
}

func renderTypes(ps []wire.PAData) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = strconv.Itoa(int(p.Type))
	}
	return strings.Join(out, " ")
}

// TestStockKinitFindsFASTFromTheCache is what the advertisement is
// for.
//
// The first kinit asks for nothing but a ticket. The reply's
// encrypted padata carries an empty PA-FX-FAST, so the client writes
// "fast_avail: yes" against that ticket in its cache
// (get_in_tkt.c:1635-1640). A second kinit armed from that cache then
// goes straight to FAST -- "Using FAST due to armor ccache
// negotiation result" -- with no probe round trip and nothing told to
// it on the command line.
//
// It is the only test here that distinguishes advertising FAST from
// merely implementing it.
func TestStockKinitFindsFASTFromTheCache(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "avail", true)
	// Off for the same reason as the case above: this one is
	// about the encrypted challenge too.
	withoutSPAKE(t)
	armor := "/realm/avail-armor.ccache"
	out, err := o.ExecEnv(ctx,
		append(env, "KRB5CCNAME="+armor),
		UserPassword+"\n", "kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("the armor kinit failed: %v\n%s", err, out)
	}
	out, err = o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "-T", armor, PreauthName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -T failed: %v\n%s", err, out)
	}
	want := "Using FAST due to armor ccache negotiation result"
	if !strings.Contains(out, want) {
		t.Errorf("no %q in the trace, so the advertisement "+
			"did not reach the cache:\n%s", want, out)
	}
}

// withoutSPAKE turns SPAKE off on the Go KDC the test just started.
//
// The harness turns it **on** by default so that the differential
// hint-list cases have something to compare -- the oracle's kdc.conf
// sets spake_preauth_groups, and both halves have to agree -- but a
// stock-client case about some *other* factor has to turn it off,
// because a client takes the first mechanism it understands and SPAKE
// is offered first.
//
// That is not a contrivance: off is the default a realm has until it
// is configured (DEFAULT_GROUPS_KDC is the empty string where
// DEFAULT_GROUPS_CLIENT is "edwards25519",
// plugins/preauth/spake/groups.c:59-60).
func withoutSPAKE(t *testing.T) {
	t.Helper()
	diamondOf(t).KDC.SPAKEGroups = nil
}

// TestStockKinitSPAKEInsideFAST is D7's stock-client anchor: an
// unmodified kinit runs the whole SPAKE exchange and gets a ticket.
//
// It is the case the published vectors cannot reach. They pin every
// derivation against fixed scalars; this pins that a real client,
// choosing its own scalars, deriving its own multiplier from its own
// password and encoding its own messages, ends up with the same keys
// -- and the reply only opens with K'[0], so the ticket arriving is
// the assertion.
//
// **It also found the last bug in the step.** The exchange ran to
// completion and the client then reported "Password incorrect",
// because inside FAST the KDC was hashing the *outer* request body
// into the derivation and the client was hashing the inner one. The
// two differ after the first round trip -- the outer body is encoded
// once per restart, before the nonce and the times are set, and the
// inner one is re-encoded every round trip (get_in_tkt.c:805-838
// against :1272-1286) -- so they were 139 octets against 142. No
// in-process test could have caught it: both sides of one would have
// used whichever body the implementation chose.
func TestStockKinitSPAKEInsideFAST(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "spakefast", true)
	armor := "/realm/spake-armor.ccache"
	out, err := o.ExecEnv(ctx,
		append(env, "KRB5CCNAME="+armor),
		UserPassword+"\n", "kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("the armor kinit failed: %v\n%s", err, out)
	}
	out, err = o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "-T", armor, PreauthName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -T failed: %v\n%s", err, out)
	}
	assertUsedSPAKE(t, out)
	assertTicket(t, ctx, o, env, PreauthName)
}

// assertUsedSPAKE reads the client's trace for the steps that say the
// exchange really happened.
//
// Every line is the client's own report: it sent a support message,
// received a challenge naming a group and a public element, generated
// its own, computed a shared result and a transcript hash, and sent a
// response. A KDC that got any derivation wrong would have failed the
// factor and the client would have said "Password incorrect" instead.
func assertUsedSPAKE(t *testing.T, trace string) {
	t.Helper()
	for _, want := range []string{
		"Sending SPAKE support message",
		"SPAKE challenge received with group 1",
		"SPAKE key generated with pubkey",
		"SPAKE algorithm result",
		"SPAKE final transcript hash",
		"Sending SPAKE response",
		"spake (151) (real) returned: 0/Success",
		"Decrypted AS reply",
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("no %q in the trace:\n%s", want,
				trace)
		}
	}
	// And the cookie was a real one, not the three constant
	// octets: SPAKE is the first mechanism here with state to put
	// in it.
	if !strings.Contains(trace, "Received cookie: MIT1") {
		t.Errorf("no MIT1 cookie in the trace:\n%s", trace)
	}
}
