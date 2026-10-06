package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// interRealmName is the principal the two realms share: its name says
// this realm and its realm says the foreign one.
var interRealmName = []string{"krbtgt", Realm}

// remoteTGT runs an AS exchange at the oracle's *foreign* realm and
// keeps what a client keeps.
func remoteTGT(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
) tgt {
	t.Helper()
	req := asRequest(t, RemoteName, in(requestedLife))
	req.Body.Realm = ForeignRealm
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{"krbtgt", ForeignRealm},
	}
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the foreign realm: %v", err)
	}
	rep := decodeReply(t, raw)
	enc := decodeEncPart(t, decryptIn(t, rep.EncPart,
		ForeignRealm, RemotePassword, []string{RemoteName},
		crypto.UsageASRepEncPart))
	return tgt{
		ticket:       rep.Ticket,
		session:      enc.Key.KeyValue,
		sessionEType: crypto.EncType(enc.Key.KeyType),
	}
}

// crossTGT obtains a cross-realm ticket-granting ticket the way a
// client does: an ordinary TGS exchange at the client's *own* KDC for
// krbtgt/<other realm>.
//
// Nothing about that exchange is cross-realm. The inter-realm
// principal is an ordinary entry in the foreign realm's own database,
// so its own KDC issues the ticket with no special path at all. What
// is cross-realm is what happens next, when the ticket is presented
// somewhere else.
func crossTGT(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	g tgt,
) tgt {
	t.Helper()
	msg := signTGSReqAs(t, g, wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   ForeignRealm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: interRealmName,
		},
		Till:  in(requestedLife),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}, ForeignRealm, RemoteName)
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the foreign realm: %v", err)
	}
	rep := decodeTGSRep(t, raw)
	enc := decodeEncPart(t, decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey))
	if rep.Ticket.Realm != ForeignRealm {
		t.Fatalf("the cross TGT's realm is %q",
			rep.Ticket.Realm)
	}
	return tgt{
		ticket:       rep.Ticket,
		session:      enc.Key.KeyValue,
		sessionEType: crypto.EncType(enc.Key.KeyType),
	}
}

// signTGSReqAs is signTGSReq with the client named, for a request
// whose presented ticket belongs to another realm's user.
func signTGSReqAs(
	t *testing.T,
	g tgt,
	body wire.KDCReqBody,
	crealm, cname string,
) []byte {
	t.Helper()
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
		tgsAPReqAs(t, g, bodyDER, crealm, cname))
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestCrossRealmMatchesTheC is the differential test for cross-realm.
//
// The oracle serves both realms, so the cross TGT presented to the
// two implementations is the *same* ticket, issued by the same KDC,
// sealed with the one inter-realm key both databases hold. There is
// nothing approximate about the comparison: either side's reply is a
// ticket to a service of this realm for a client of another.
func TestCrossRealmMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	cross := crossTGT(t, ctx, o, remoteTGT(t, ctx, o))
	msg := signTGSReqAs(t, cross, wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  in(2 * time.Hour),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}, ForeignRealm, RemoteName)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openTGS(t, cRaw, cross)

	d := diamond(t, "kd_golden_xrealm",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openTGS(t, goRaw, cross)

	assertCrossRealm(t, "oracle", cx)
	assertCrossRealm(t, "diamond", gx)
	reportDiffs(t, cx, gx, fastExemptions()...)
}

// assertCrossRealm checks the exchange issued a ticket of this realm
// to a client of another, rather than merely matching the other side.
func assertCrossRealm(t *testing.T, side string, x Exchange) {
	t.Helper()
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Errorf("%s: reply carries no session key", side)
	}
	if x.Tkt.CRealm != ForeignRealm {
		t.Errorf("%s: ticket client realm is %q, want %q",
			side, x.Tkt.CRealm, ForeignRealm)
	}
	if got := x.Tkt.CName.String(); got != RemoteName {
		t.Errorf("%s: ticket client is %q, want %q",
			side, got, RemoteName)
	}
	// The issued ticket belongs to *this* realm whatever realm
	// the client came from: it is this realm's service it names.
	if x.Rep.Ticket.Realm != Realm {
		t.Errorf("%s: issued ticket's realm is %q",
			side, x.Rep.Ticket.Realm)
	}
	if x.Enc.SRealm != Realm {
		t.Errorf("%s: reply server realm is %q",
			side, x.Enc.SRealm)
	}
	// One hop records nothing. The realm that issued the
	// presented ticket is the client's own, so no realm has been
	// passed through that the two ends do not already name
	// (gather_tgs_req_info, do_tgs_req.c:786-790).
	if len(x.Tkt.Transited.Contents) != 0 {
		t.Errorf("%s: transited path is %q",
			side, x.Tkt.Transited.Contents)
	}
	if x.Enc.Flags.Has(wire.FlagInitial) {
		t.Errorf("%s: derived ticket marked initial", side)
	}
}

// A foreign realm may not assert a client of *this* realm. The ticket
// here is genuine -- sealed with the inter-realm key both sides hold
// -- and names a local client, which is exactly the forgery the check
// exists for (check_tgs_lineage, kdc/tgs_policy.c:249-258). Both
// sides must refuse it, and with the same code.
func TestCrossRealmCannotClaimALocalClient(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	cross := crossTGT(t, ctx, o, remoteTGT(t, ctx, o))
	forged := resealCross(t, cross, func(e *wire.EncTicketPart) {
		e.CRealm = Realm
	})
	// The authenticator names the client the forged ticket does:
	// the forgery is the client's *realm*, not its name, and a
	// mismatched name would be refused for that instead.
	msg := signTGSReqAs(t, forged, serviceBody(),
		Realm, RemoteName)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	d := diamond(t, "kd_golden_xrealm_lineage", nil)
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	cCode := refusalCode(t, "oracle", cRaw)
	goCode := refusalCode(t, "diamond", goRaw)
	if cCode != wire.ErrCodePolicy {
		t.Errorf("the C refused with %d, want POLICY (%d)",
			cCode, wire.ErrCodePolicy)
	}
	if goCode != cCode {
		t.Errorf("codes differ: C %d, Go %d", cCode, goCode)
	}
}

// assertSpentAtTheShim checks the client took its cross-realm TGT to
// the Go KDC's shim and not to the C KDC sharing the container.
func assertSpentAtTheShim(t *testing.T, trace string) {
	t.Helper()
	if !strings.Contains(
		trace, "Resolving hostname "+HostAlias) {
		t.Errorf("no shim in the trace:\n%s", trace)
	}
	// The client asked its own realm's KDC for the cross TGT,
	// which *is* the C KDC, so a trace naming it is expected --
	// but only for that request. The service ticket must come
	// after the shim is dialled.
	tgs := "Requesting tickets for host/" +
		"service.kdiamond.test@" + Realm
	i := strings.Index(trace, tgs)
	if i < 0 {
		t.Errorf("no TGS request in the trace:\n%s", trace)
		return
	}
	if !strings.Contains(trace[i:], HostAlias) {
		t.Errorf("the service ticket came from\n%s", trace)
	}
}

// serviceBody is a plain request for a ticket to this realm's
// service.
func serviceBody() wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  in(2 * time.Hour),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
}

// resealCross reopens a cross TGT with the inter-realm key, applies a
// change and seals it again -- which is what a malicious KDC on the
// other side of the trust would have sent.
func resealCross(
	t *testing.T,
	g tgt,
	change func(*wire.EncTicketPart),
) tgt {
	t.Helper()
	ed := g.ticket.EncPart
	p, err := crypto.Profile(crypto.EncType(ed.EType))
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(InterRealmPassword,
		crypto.Salt(ForeignRealm, interRealmName), nil)
	if err != nil {
		t.Fatal(err)
	}
	part := decodeTktPart(t, decryptPart(t, ed, key,
		crypto.UsageKDCRepTicket))
	change(&part)
	out, err := wire.MarshalEncTicketPart(part)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(key, out, crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatal(err)
	}
	g.ticket.EncPart.Cipher = ct
	return g
}

// crossRealmConf is a client configuration whose *local* realm is the
// foreign one -- served by the oracle's own KDC inside the container
// -- and whose service realm is reached through the Go KDC's shim.
//
// Splitting the two realms across the two KDCs is the whole point.
// The client gets its TGT and its cross-realm TGT from the C KDC,
// exactly as its own realm's users would, and then presents that
// cross TGT to the Go KDC. Nothing about the client knows the
// difference.
func crossRealmConf(port int) string {
	return fmt.Sprintf(`[libdefaults]
	default_realm = %[1]s
	dns_lookup_kdc = false
	dns_lookup_realm = false
	dns_canonicalize_hostname = false
	rdns = false
	qualify_shortname = ""
	udp_preference_limit = 1
	noaddresses = true

[realms]
	%[1]s = {
		kdc = 127.0.0.1:%[4]d
	}

	%[2]s = {
		kdc = %[3]s:%[5]d
	}

[capaths]
	%[1]s = {
		%[2]s = .
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, ForeignRealm, Realm, HostAlias, OraclePort, port)
}

// TestStockKvnoCrossRealmAgainstTheGoKDC is the end-to-end
// cross-realm check, and it is the only evidence that the cross-realm
// path works for a client rather than merely for this harness.
//
// An unmodified kinit authenticates to the C KDC's foreign realm; an
// unmodified kvno then asks for a service of this realm, which makes
// the client fetch a cross-realm TGT from the C KDC and spend it at
// the *Go* KDC through the shim. Both hops are the client's own
// doing.
func TestStockKvnoCrossRealmAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "xrealm",
		crossRealmConf)
	env = append(env, "KRB5_TRACE=/dev/stderr")
	out, err := o.ExecEnv(ctx, env, RemotePassword+"\n",
		"kinit", RemoteName+"@"+ForeignRealm)
	if err != nil {
		t.Fatalf("kinit at the foreign realm failed: %v\n%s",
			err, out)
	}
	svc := "host/service.kdiamond.test@" + Realm
	out, err = o.ExecEnv(ctx, env, "", "kvno", svc)
	if err != nil {
		t.Fatalf("kvno against the Go KDC failed: %v\n%s",
			err, out)
	}
	if !strings.Contains(out, svc+": kvno = ") {
		t.Errorf("kvno said:\n%s", out)
	}
	// Which KDC answered which request is the hazard here, and
	// the trace is the only thing that says. The referral hop is
	// the C KDC's -- it is the client's own realm -- and the hop
	// that spends the cross TGT has to be the Go KDC's, or this
	// case would pass with the C KDC doing all of the work.
	assertSpentAtTheShim(t, out)
	assertCrossRealmCache(t, ctx, o, env, svc)
}

// assertCrossRealmCache reads the client's own klist, which is the
// assertion that matters: the cache must hold the cross-realm TGT as
// well as the service ticket, and that is what says the referral hop
// happened rather than being skipped.
func assertCrossRealmCache(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	svc string,
) {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist: %v\n%s", err, out)
	}
	for _, want := range []string{
		"krbtgt/" + ForeignRealm + "@" + ForeignRealm,
		"krbtgt/" + Realm + "@" + ForeignRealm,
		svc,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("klist has no %s:\n%s", want, out)
		}
	}
}
