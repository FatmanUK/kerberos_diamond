package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/kdc"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// realmTGT runs an AS exchange at one of the oracle's realms for one
// of its principals, and keeps what a client keeps.
func realmTGT(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	realm, name, password string,
) tgt {
	t.Helper()
	req := asRequest(t, name, in(requestedLife))
	req.Body.Realm = realm
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{"krbtgt", realm},
	}
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking %s: %v", realm, err)
	}
	rep := decodeReply(t, raw)
	enc := decodeEncPart(t, decryptIn(t, rep.EncPart, realm,
		password, []string{name}, crypto.UsageASRepEncPart))
	return tgt{
		ticket:       rep.Ticket,
		session:      enc.Key.KeyValue,
		sessionEType: crypto.EncType(enc.Key.KeyType),
	}
}

// crossHop spends a ticket at the oracle for a ticket-granting
// service in another realm, which is one step of a client's walk
// along a path.
//
// at is the realm the request is addressed to and want the realm
// being asked for; the client named is always the far realm's user,
// because the ticket presented is always theirs.
func crossHop(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	g tgt,
	at, want string,
) tgt {
	t.Helper()
	msg := signTGSReqAs(t, g, wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   at,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{"krbtgt", want},
		},
		Till:  in(requestedLife),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}, FarRealm, FarUser)
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("hop at %s for %s: %v", at, want, err)
	}
	rep := decodeTGSRep(t, raw)
	enc := decodeEncPart(t, decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey))
	if got := enc.SName.String(); got != "krbtgt/"+want {
		t.Fatalf("hop at %s returned %q, want krbtgt/%s",
			at, got, want)
	}
	return tgt{
		ticket:       rep.Ticket,
		session:      enc.Key.KeyValue,
		sessionEType: crypto.EncType(enc.Key.KeyType),
	}
}

// twoHopTGT walks the far realm to this one through the middle realm,
// and returns the ticket a client would then present here.
//
// Each hop is asked for by name rather than letting the KDC pick an
// intermediate, so that this case is about the transited field and
// nothing else. Both sides do pick one now --
// TestAlternateTGSMatchesTheC compares exactly that -- and leaving
// the choice to the KDC here would fold two features into one
// comparison.
func twoHopTGT(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
) tgt {
	t.Helper()
	g := realmTGT(t, ctx, o, FarRealm, FarUser, FarPassword)
	g = crossHop(t, ctx, o, g, FarRealm, MidRealm)
	return crossHop(t, ctx, o, g, MidRealm, Realm)
}

// TestTransitedPathMatchesTheC is the differential test for the
// transited field, and it is the only case in the harness that
// reaches it: with a single realm boundary the field stays empty, so
// everything internal/transit does goes untested until a path has a
// middle.
//
// The ticket presented here crossed two boundaries, so the realm in
// the middle has to be written down -- and both implementations have
// to write it down the same way, because the field goes on the wire
// and a service will read it.
func TestTransitedPathMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := twoHopTGT(t, ctx, o)
	msg := signTGSReqAs(t, g, serviceBody(), FarRealm, FarUser)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openTGS(t, cRaw, g)

	d := diamond(t, "kd_golden_transit",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openTGS(t, goRaw, g)

	assertTransited(t, "oracle", cx)
	assertTransited(t, "diamond", gx)
	reportDiffs(t, cx, gx)
}

// assertTransited checks the middle realm was recorded and the path
// was checked, rather than the two sides merely agreeing.
func assertTransited(t *testing.T, side string, x Exchange) {
	t.Helper()
	if got := string(x.Tkt.Transited.Contents); got != MidRealm {
		t.Errorf("%s: transited path is %q, want %q",
			side, got, MidRealm)
	}
	if x.Tkt.Transited.Type !=
		wire.TransitedDomainX500Compress {
		t.Errorf("%s: transited type is %d",
			side, x.Tkt.Transited.Type)
	}
	// The flag is the evidence a service acts on. It says the KDC
	// looked at the path and was satisfied, which is a different
	// claim from the path merely being present -- and upstream
	// sets it only when the check passed (do_tgs_req.c:924-937).
	if !x.Tkt.Flags.Has(wire.FlagTransitedPolicyChecked) {
		t.Errorf("%s: the path was not checked", side)
	}
	if x.Tkt.CRealm != FarRealm {
		t.Errorf("%s: ticket client realm is %q",
			side, x.Tkt.CRealm)
	}
}

// farRealmConf points the far realm and the middle one at the C KDC
// and this realm at the Go KDC's shim, so a client walks two hops
// through the C and spends the result at the Go KDC.
//
// The three realms are a hierarchy and there is no [capaths] entry
// for them, deliberately: the hierarchical walk is what both sides
// implement, and a capaths entry would replace it.
func farRealmConf(port int) string {
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
		kdc = 127.0.0.1:%[5]d
	}

	%[2]s = {
		kdc = 127.0.0.1:%[5]d
	}

	%[3]s = {
		kdc = %[4]s:%[6]d
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, FarRealm, MidRealm, Realm, HostAlias, OraclePort, port)
}

// TestStockKvnoTwoHopsAgainstTheGoKDC is the end-to-end check for a
// three-realm path: an unmodified client authenticates two realms
// away and reaches a service here, with only the last hop answered by
// the Go KDC.
//
// The last hop is the one that writes the transited field and checks
// it, so this is the only end-to-end evidence that a real client
// accepts what internal/transit produces.
func TestStockKvnoTwoHopsAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "twohop", farRealmConf)
	env = append(env, "KRB5_TRACE=/dev/stderr")
	out, err := o.ExecEnv(ctx, env, FarPassword+"\n",
		"kinit", FarUser+"@"+FarRealm)
	if err != nil {
		t.Fatalf("kinit at the far realm failed: %v\n%s",
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
	// The trace has to show the middle realm being passed
	// through, or the client found some shorter route and the
	// transited field this case exists for was never written.
	if !strings.Contains(out, "krbtgt/"+Realm+"@"+MidRealm) {
		t.Errorf("the path did not go through %s:\n%s",
			MidRealm, out)
	}
	assertSpentAtTheShim(t, out)
}

// TestAlternateTGSMatchesTheC is the differential test for the
// referral a KDC offers when the trust asked for does not exist.
//
// It is the one case here addressed to a realm other than this one,
// and it has to be: the search runs where the *client* asks from,
// which is the far end of a path. So both implementations stand up as
// the far realm and answer the same request.
func TestAlternateTGSMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := realmTGT(t, ctx, o, FarRealm, FarUser, FarPassword)
	msg := signTGSReqAs(t, g, farToLocalBody(), FarRealm,
		FarUser)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openCrossTGT(t, cRaw, g)

	d := diamond(t, "kd_golden_alttgs",
		pinned(cx.Enc.EffectiveStartTime()))
	far := asFarRealm(d, pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := far.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openCrossTGT(t, goRaw, g)

	assertAlternate(t, "oracle", cx)
	assertAlternate(t, "diamond", gx)
	reportDiffs(t, cx, gx)
}

// farToLocalBody asks the far realm for a trust with this one, which
// it does not hold: it holds one with the middle realm only, so the
// answer must name the middle realm.
func farToLocalBody() wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   FarRealm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{"krbtgt", Realm},
		},
		Till:  in(requestedLife),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
}

// asFarRealm builds a Go KDC serving the far realm over the same
// store.
func asFarRealm(d *Diamond, now func() time.Time) *kdc.KDC {
	return &kdc.KDC{
		Store:     d.Store,
		Realm:     FarRealm,
		ClockSkew: 5 * time.Minute,
		Now:       now,
	}
}

// openCrossTGT decodes a reply whose ticket is a cross-realm
// ticket-granting ticket, opened with the inter-realm key the far and
// middle realms share.
func openCrossTGT(t *testing.T, raw []byte, g tgt) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	enc := decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey)
	tkt := decryptIn(t, rep.Ticket.EncPart, FarRealm,
		FarMidPassword, []string{"krbtgt", MidRealm},
		crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// assertAlternate checks the reply offers the middle realm rather
// than the realm asked for, in both halves.
func assertAlternate(t *testing.T, side string, x Exchange) {
	t.Helper()
	want := "krbtgt/" + MidRealm
	if got := x.Rep.Ticket.SName.String(); got != want {
		t.Errorf("%s: the ticket names %q, want %q",
			side, got, want)
	}
	// The sealed half has to agree with the ticket, or a client
	// would cache the credential under the name it asked for and
	// present it to the wrong realm.
	if got := x.Enc.SName.String(); got != want {
		t.Errorf("%s: the reply names %q, want %q",
			side, got, want)
	}
	if x.Enc.SRealm != FarRealm {
		t.Errorf("%s: the reply's server realm is %q",
			side, x.Enc.SRealm)
	}
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Errorf("%s: reply carries no session key", side)
	}
}
