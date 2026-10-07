package golden

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// tgt is a ticket-granting ticket and the session key inside it.
//
// The TGT is carried opaquely and the session key is read out of the
// reply, which is what a client does. It can be presented to *either*
// implementation, because both hold the same krbtgt key -- the
// fixture derives it from a password for exactly that reason.
type tgt struct {
	ticket  wire.Ticket
	session []byte

	// sessionEType is the session key's enctype, which is *not*
	// the ticket's. The ticket is sealed with the krbtgt's key --
	// this realm's strongest -- while the session key's enctype
	// comes from select_session_keytype over the request's list
	// (kdc/kdc_util.c:1085-1111). Keying the authenticator from
	// the ticket's enctype instead produces something the KDC
	// cannot decrypt, which is exactly how the first draft of
	// this harness failed once the realm held more than one
	// enctype.
	sessionEType crypto.EncType
}

// getTGTFromTheC runs an AS exchange against the C KDC and keeps what
// a client would keep.
func getTGTFromTheC(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
) (tgt, time.Time) {
	t.Helper()
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	x := open(t, raw, UserPassword, []string{UserName})
	return tgtOf(x), x.Enc.AuthTime
}

// tgtOf keeps what a client keeps out of an AS reply.
func tgtOf(x Exchange) tgt {
	return tgt{
		ticket:       x.Rep.Ticket,
		session:      x.Enc.Key.KeyValue,
		sessionEType: crypto.EncType(x.Enc.Key.KeyType),
	}
}

// tgsRequestFor builds the TGS-REQ both implementations answer.
//
// It carries PA-REQ-ENC-PA-REP so that the reply checksum is
// exercised here too. That is deliberate: the AS path's last
// divergence was a missing one, and it was invisible until a request
// asked for it.
func tgsRequestFor(
	t *testing.T,
	g tgt,
	till time.Time,
) []byte {
	t.Helper()
	body := wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  till,
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
	req := wire.TGSReq{PAData: []wire.PAData{
		{Type: wire.PAReqEncPARep},
	}, Body: body}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = append(req.PAData,
		tgsAPReq(t, g, bodyDER))
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// tgsAPReq builds the PA-TGS-REQ a client sends.
func tgsAPReq(t *testing.T, g tgt, bodyDER []byte) wire.PAData {
	t.Helper()
	return tgsAPReqAs(t, g, bodyDER, Realm, UserName)
}

// tgsAPReqAs is tgsAPReq with the client named, which a cross-realm
// case needs: the authenticator says who the client is and it has to
// agree with the presented ticket, whose client is of another realm.
func tgsAPReqAs(
	t *testing.T,
	g tgt,
	bodyDER []byte,
	crealm, cname string,
) wire.PAData {
	t.Helper()
	// The authenticator is keyed with the session key, so its
	// profile is the session key's and not the ticket's.
	p, err := crypto.Profile(g.sessionEType)
	if err != nil {
		t.Fatal(err)
	}
	ct := sealAuthenticator(t, p, g.session, bodyDER,
		crealm, cname)
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

// sealAuthenticator builds the authenticator and encrypts it under
// the presented ticket's session key with key usage 7.
//
// Its checksum is over the req-body bytes, keyed with the same
// session key under key usage 6. Two usages for one message is what
// keeps a captured checksum from being replayed as a ciphertext.
func sealAuthenticator(
	t *testing.T,
	p *crypto.EncProfile,
	session, bodyDER []byte,
	crealm, cname string,
) []byte {
	t.Helper()
	return sealAuthenticatorSub(t, p, session, bodyDER,
		crealm, cname, nil)
}

// sealAuthenticatorSub is the same with a subkey, which a
// FAST-armored request needs: the subkey is one of the two inputs to
// the armor key, and it is what makes that key fresh rather than as
// old as the ticket.
func sealAuthenticatorSub(
	t *testing.T,
	p *crypto.EncProfile,
	session, bodyDER []byte,
	crealm, cname string,
	sub []byte,
) []byte {
	t.Helper()
	sum, err := p.Checksum(session, bodyDER,
		crypto.UsageTGSReqAuthCksum)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	plain, err := wire.MarshalAuthenticator(wire.Authenticator{
		CRealm: crealm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{cname},
		},
		Cksum: &wire.Checksum{
			Type:     int32(p.RequiredCksum),
			Checksum: sum,
		},
		CUsec:  1234,
		CTime:  now,
		SubKey: subKeyOf(p, sub),
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(session, plain, crypto.UsageTGSReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

// subKeyOf renders a subkey, or nil when there is none.
func subKeyOf(
	p *crypto.EncProfile,
	sub []byte,
) *wire.EncryptionKey {
	if sub == nil {
		return nil
	}
	return &wire.EncryptionKey{
		KeyType: int32(p.EncType), KeyValue: sub,
	}
}

// openTGS decrypts a TGS-REP into an Exchange.
//
// The enc-part opens with the TGT's session key -- no subkey was sent
// -- and the ticket with the service's own, so both halves are
// compared rather than just the one a client can read.
func openTGS(
	t *testing.T,
	raw []byte,
	g tgt,
) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	enc := decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey)
	tkt := decrypt(t, rep.Ticket.EncPart, ServicePassword,
		ServiceName, crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// decodeTGSRep insists the reply is a TGS-REP and not a refusal,
// which is the same guard the AS cases use and for the same reason:
// two KDCs that both say no agree perfectly while testing nothing.
func decodeTGSRep(t *testing.T, raw []byte) wire.TGSRep {
	t.Helper()
	rep, err := wire.UnmarshalTGSRep(raw)
	if err == nil {
		return rep
	}
	if kerr, e := wire.UnmarshalKRBError(raw); e == nil {
		t.Fatalf("expected a TGS-REP, got %v (e-text %q)",
			kerr.Error(), kerr.EText)
	}
	t.Fatalf("reply is no TGS-REP and no KRB-ERROR: %v", err)
	return wire.TGSRep{}
}

// decryptPart opens an EncryptedData with a key already in hand.
func decryptPart(
	t *testing.T,
	ed wire.EncryptedData,
	key []byte,
	usage crypto.Usage,
) []byte {
	t.Helper()
	p, err := crypto.Profile(crypto.EncType(ed.EType))
	if err != nil {
		t.Fatalf("enctype %d: %v", ed.EType, err)
	}
	plain, err := p.Decrypt(key, ed.Cipher, usage)
	if err != nil {
		t.Fatalf("decrypting under usage %d: %v", usage, err)
	}
	return plain
}

func decodeEncPart(t *testing.T, b []byte) wire.EncKDCRepPart {
	t.Helper()
	enc, err := wire.UnmarshalEncKDCRepPart(b)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return enc
}

func decodeTktPart(t *testing.T, b []byte) wire.EncTicketPart {
	t.Helper()
	tkt, err := wire.UnmarshalEncTicketPart(b)
	if err != nil {
		t.Fatalf("EncTicketPart: %v", err)
	}
	return tkt
}

// TestTGSExchangeMatchesTheC is the differential test for the TGS
// exchange.
//
// One TGT, obtained from the C KDC, is presented to both
// implementations in the same encoded TGS-REQ. Both hold the same
// krbtgt key, so the same ticket is valid at either -- which makes
// the comparison exact rather than approximate.
func TestTGSExchangeMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, authTime := getTGTFromTheC(t, ctx, o)
	till := time.Now().UTC().Add(2 * time.Hour).Truncate(
		time.Second)
	msg := tgsRequestFor(t, g, till)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openTGS(t, cRaw, g)

	// The Go clock is pinned to the C reply's *starttime*, not
	// its authtime. A TGS ticket's authtime comes from the TGT
	// and its starttime is "now", so pinning to the authtime
	// would make the Go KDC compute start == authtime, drop the
	// starttime field, and manufacture a divergence the
	// implementations do not have.
	d := diamond(t, "kd_golden_tgs",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openTGS(t, goRaw, g)

	assertTGSSucceeded(t, "oracle", cx, authTime)
	assertTGSSucceeded(t, "diamond", gx, authTime)
	reportDiffs(t, cx, gx, fastExemptions()...)
}

// fastExemptions declares the one difference this comparison does not
// make, and why.
//
// kdc_handle_protected_negotiation adds an empty PA-FX-FAST beside
// the reply checksum unconditionally (kdc/kdc_util.c:1800-1802),
// which is how a client learns FAST is available -- it stores
// "fast_avail: yes" in its credential cache and may arm later
// exchanges with it. This KDC does not implement FAST, so it does not
// claim to: a client told FAST were available and then refused it
// would be a broken deployment, where one told it is unavailable
// simply does not use it, which is what every passing end-to-end case
// here does.
//
// The reply's ciphertext length is exempt as a consequence: the
// missing padata element is exactly twelve octets of plaintext. It is
// listed separately rather than folded in, so that a length
// difference arising from anything else would still fail.
func fastExemptions() []Exemption {
	const why = "FAST is not implemented, so it is not advertised"
	return []Exemption{
		{Field: "enc.enc-padata", Reason: why},
		{Field: "rep.enc-part",
			Reason: why + " (12 octets of padata)"},
	}
}

// assertTGSSucceeded checks the exchange produced a usable service
// ticket rather than a message that merely parsed.
//
// The authtime assertion is the interesting one: a TGS ticket carries
// the *TGT's* authtime, so it must equal the one the AS exchange
// returned and not the moment this exchange happened.
func assertTGSSucceeded(
	t *testing.T,
	side string,
	x Exchange,
	authTime time.Time,
) {
	t.Helper()
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Errorf("%s: reply carries no session key", side)
	}
	want := "host/service.kdiamond.test"
	if got := x.Enc.SName.String(); got != want {
		t.Errorf("%s: reply names server %q", side, got)
	}
	if !x.Enc.EndTime.After(x.Enc.AuthTime) {
		t.Errorf("%s: endtime %v is not after authtime %v",
			side, x.Enc.EndTime, x.Enc.AuthTime)
	}
	if !x.Enc.AuthTime.Equal(authTime) {
		t.Errorf("%s: authtime is %v, want the TGT's %v",
			side, x.Enc.AuthTime, authTime)
	}
	// A derived ticket is not initial, and saying so is worth a
	// test: it is the bit a service reads to tell a
	// password-backed ticket from one spent out of a TGT.
	if x.Enc.Flags.Has(wire.FlagInitial) {
		t.Errorf("%s: derived ticket marked initial", side)
	}
	if x.Tkt.CName.String() != UserName {
		t.Errorf("%s: ticket client is %q", side, x.Tkt.CName)
	}
}

// TestStockKvnoAgainstTheGoKDC is the end-to-end TGS check: an
// unmodified kinit gets a TGT and an unmodified kvno spends it.
//
// kvno is the right tool for this because it does nothing but a TGS
// exchange and print the result, so a failure is the exchange's and
// not a client library's.
func TestStockKvnoAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "tgs", true)
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)

	service := "host/service.kdiamond.test@" + Realm
	out, err = o.ExecEnv(ctx, env, "", "kvno", service)
	if err != nil {
		t.Fatalf("kvno failed: %v\n%s", err, out)
	}
	// The trace has to show the TGS exchange reaching the shim,
	// or a ticket already in the cache would satisfy kvno without
	// the Go KDC answering anything.
	assertWentToTheShim(t, out)
	if !strings.Contains(out, "kvno = 1") {
		t.Errorf("kvno did not report the key version:\n%s",
			out)
	}
	assertArmored(t, out)
	assertServiceTicket(t, ctx, o, env, service)
}

// assertArmored checks the exchange went through a FAST tunnel.
//
// It is not optional decoration. A stock client armors *every* TGS
// request unconditionally -- krb5int_fast_tgs_armor is called from
// lib/krb5/krb/send_tgs.c:178 with no gate on any advertisement --
// and a client tolerates a reply that ignores it, because
// lib/krb5/krb/decode_kdc.c:65-66 maps KRB5_ERR_FAST_REQUIRED back to
// success. So this KDC answered armored requests as if the padata
// were absent for as long as the TGS exchange has existed, and every
// test here passed. Without these three lines it would go on passing.
//
// "FAST reply key" is the one that matters most: the client only logs
// it after it has verified the finished field, checked the ticket
// checksum under the armor key, matched the nonce and combined the
// strengthen key. It is the whole chain in one assertion.
func assertArmored(t *testing.T, trace string) {
	t.Helper()
	for _, want := range []string{
		"Encoding request body and padata into FAST request",
		"Decoding FAST response",
		"FAST reply key",
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("the trace has no %q:\n%s",
				want, trace)
		}
	}
}

// assertServiceTicket checks klist lists the service ticket beside
// the TGT.
//
// Both have to be there: the TGT alone would be what a kinit left,
// and a test that only looked for the service name could be satisfied
// by kvno's own stdout rather than by anything in the cache.
func assertServiceTicket(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	service string,
) {
	t.Helper()
	list, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, list)
	}
	for _, want := range []string{
		service,
		"krbtgt/" + Realm + "@" + Realm,
		UserName + "@" + Realm,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("klist shows no %s:\n%s", want, list)
		}
	}
}

// renewableTGTFromTheC obtains a renewable TGT from the C KDC.
//
// The realm's principals have max_renewable_life zero by kadmin's
// default, so a renewable request would otherwise be answered with a
// renew-till equal to the start time and there would be nothing to
// renew. kadmin.local is the way to change that, which is also the
// first thing in this project that wants a kadmin of its own.
func renewableTGTFromTheC(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
) (tgt, wire.EncKDCRepPart) {
	t.Helper()
	grantRenewableLife(t, ctx, o)
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	req.Body.Options |= wire.OptRenewable
	req.Body.RTime = till.Add(48 * time.Hour)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	x := open(t, raw, UserPassword, []string{UserName})
	if !x.Enc.Flags.Has(wire.FlagRenewable) {
		t.Fatal("the C KDC issued a non-renewable TGT")
	}
	return tgtOf(x), x.Enc
}

// renewRequest builds the TGS-REQ a client sends to renew a TGT.
//
// The options carry the presented ticket's own flags masked by
// KDC_TKT_COMMON_MASK, which is what a real client does
// (lib/krb5/krb/val_renew.c:61) and what keeps the renewed ticket
// renewable.
func renewRequest(
	t *testing.T,
	g tgt,
	carry wire.Flags,
	till time.Time,
) []byte {
	t.Helper()
	const mask = wire.FlagForwardable | wire.FlagProxiable |
		wire.FlagMayPostdate | wire.FlagRenewable
	req := wire.TGSReq{
		PAData: []wire.PAData{{Type: wire.PAReqEncPARep}},
		Body:   renewBody(carry&mask, till),
	}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = append(req.PAData, tgsAPReq(t, g, bodyDER))
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// renewBody is a renewal's request body, naming the krbtgt because
// that is the ticket being renewed.
func renewBody(carried wire.Flags, till time.Time) wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptRenew | carried,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{"krbtgt", Realm},
		},
		Till:  till,
		Nonce: 0x7E,
		EType: []int32{int32(crypto.AES256CTSHMACSHA196)},
	}
}

// TestRenewalMatchesTheC compares a renewal field for field.
//
// Renewal is the case where the two implementations have the most
// room to disagree without either looking wrong on its own: the times
// come from three places at once -- the presented ticket's lifetime,
// its renew-till, and the clock -- and the flags arrive already set
// and have to be partly cleared.
func TestRenewalMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g, before := renewableTGTFromTheC(t, ctx, o)
	till := before.EndTime
	msg := renewRequest(t, g, before.Flags, till)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openRenewed(t, cRaw, g)

	d := diamond(t, "kd_golden_renew",
		pinned(cx.Enc.EffectiveStartTime()))
	provisionRenewable(t, ctx, d)
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openRenewed(t, goRaw, g)

	assertRenewed(t, "oracle", cx, before)
	assertRenewed(t, "diamond", gx, before)
	reportDiffs(t, cx, gx, fastExemptions()...)
}

// openRenewed decrypts a renewed TGT. Both halves open with keys the
// harness holds: the reply with the old session key, the ticket with
// the krbtgt's.
func openRenewed(t *testing.T, raw []byte, g tgt) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	enc := decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey)
	tkt := decrypt(t, rep.Ticket.EncPart, TgtPassword,
		[]string{"krbtgt", Realm}, crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// provisionRenewable gives the Go realm's principals the renewable
// lifetime the C side was just given by kadmin, so the comparison is
// of the implementations and not of two differently configured
// realms.
func provisionRenewable(
	t *testing.T,
	ctx context.Context,
	d *Diamond,
) {
	t.Helper()
	for _, cs := range [][]string{
		{UserName}, {"krbtgt", Realm},
	} {
		name := storeName(cs)
		p, err := d.Store.Lookup(ctx, name)
		if err != nil {
			t.Fatalf("Lookup %s: %v", name, err)
		}
		p.MaxRenewableLife = int32(
			(7 * 24 * time.Hour) / time.Second)
		if err := d.Store.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", name, err)
		}
	}
}

// assertRenewed checks a renewal did what renewal means, on each side
// separately, before the two are compared.
//
// Without this a pair of implementations that both refused to move
// the window, or both dropped the renewable flag, would agree
// perfectly.
func assertRenewed(
	t *testing.T,
	side string,
	x Exchange,
	before wire.EncKDCRepPart,
) {
	t.Helper()
	if !x.Enc.AuthTime.Equal(before.AuthTime) {
		t.Errorf("%s: authtime changed from %v to %v", side,
			before.AuthTime, x.Enc.AuthTime)
	}
	if !x.Enc.Flags.Has(wire.FlagRenewable) {
		t.Errorf("%s: the renewed ticket is not renewable",
			side)
	}
	if !x.Enc.RenewTill.Equal(before.RenewTill) {
		t.Errorf("%s: renew-till moved from %v to %v", side,
			before.RenewTill, x.Enc.RenewTill)
	}
	if x.Enc.EndTime.After(before.RenewTill) {
		t.Errorf("%s: endtime %v is past renew-till %v", side,
			x.Enc.EndTime, before.RenewTill)
	}
	if x.Enc.SName.String() != "krbtgt/"+Realm {
		t.Errorf("%s: renewed ticket names %q", side,
			x.Enc.SName)
	}
}

// TestStockKinitRenewsAgainstTheGoKDC drives a renewal with the real
// client: kinit gets a TGT, kinit -R renews it.
//
// A renewal is the one exchange where a client checks the reply
// against its own copy of the ticket it presented, so this is worth
// more than the field comparison alone -- it is the only case so far
// where a *stale* answer would be caught by the client rather than by
// a test.
func TestStockKinitRenewsAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "renew", true)
	grantRenewableLife(t, ctx, o)
	d := diamondOf(t)
	provisionRenewable(t, ctx, d)

	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", "-r", "7d", "-l", "4h",
		UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -r failed: %v\n%s", err, out)
	}
	before := renewUntil(t, ctx, o, env)

	out, err = o.ExecEnv(ctx, env, "", "kinit", "-R")
	if err != nil {
		t.Fatalf("kinit -R failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)
	// The renew-till must survive: it is the wall renewal cannot
	// push, and a KDC that moved it would hand out an
	// indefinitely-renewable credential.
	after := renewUntil(t, ctx, o, env)
	if after != before {
		t.Errorf("renew-until moved from %q to %q",
			before, after)
	}
	assertTicket(t, ctx, o, env, UserName)
}

// grantRenewableLife sets a renewable lifetime on the C realm's
// principals, which kadmin's defaults leave at zero, and puts it back
// afterwards.
//
// Restoring it matters because the oracle container is shared by
// every test in this package: a realm left with a seven-day renewable
// life would change what the AS comparison expects of renew-till, and
// the two tests would then pass or fail depending on the order they
// ran in.
func grantRenewableLife(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
) {
	t.Helper()
	setRenewLife(t, ctx, o, "7 days")
	t.Cleanup(func() {
		// A fresh context: t.Cleanup runs after the test
		// function returns, by which time the test's own
		// context has already been cancelled by its defer.
		done, cancel := context.WithTimeout(
			context.Background(), 20*time.Second)
		defer cancel()
		setRenewLife(t, done, o, "0")
	})
}

func setRenewLife(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	life string,
) {
	t.Helper()
	for _, princ := range []string{
		UserName, "krbtgt/" + Realm,
	} {
		out, err := o.Exec(ctx, "kadmin.local", "-q",
			"modprinc -maxrenewlife \""+life+"\" "+
				princ+"@"+Realm)
		if err != nil {
			t.Fatalf("modprinc %s: %v\n%s",
				princ, err, out)
		}
	}
}

// renewUntil reads the renew-until line klist prints, which is where
// a renewable ticket's wall shows up in the client's own words.
func renewUntil(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
) string {
	t.Helper()
	list, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, list)
	}
	for _, line := range strings.Split(list, "\n") {
		if strings.Contains(line, "renew until") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("klist shows no renew-until line:\n%s", list)
	return ""
}
