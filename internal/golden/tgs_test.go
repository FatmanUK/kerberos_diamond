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
	return tgt{
		ticket:  x.Rep.Ticket,
		session: x.Enc.Key.KeyValue,
	}, x.Enc.AuthTime
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
	p, err := crypto.Profile(
		crypto.EncType(g.ticket.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	ct := sealAuthenticator(t, p, g.session, bodyDER)
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
) []byte {
	t.Helper()
	sum, err := p.Checksum(session, bodyDER,
		crypto.UsageTGSReqAuthCksum)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	plain, err := wire.MarshalAuthenticator(wire.Authenticator{
		CRealm: Realm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{UserName},
		},
		Cksum: &wire.Checksum{
			Type:     int32(p.RequiredCksum),
			Checksum: sum,
		},
		CUsec: 1234,
		CTime: now,
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
	assertServiceTicket(t, ctx, o, env, service)
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
