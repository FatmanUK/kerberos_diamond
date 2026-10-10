package golden

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// TestHostReferralMatchesTheC is the differential test for the
// referral a KDC offers when the service asked for is host-based and
// lives in another realm.
//
// Unlike the alternate-TGS case this one is addressed to this realm:
// the client is a local user, and what it asks for is a service that
// does not exist here and whose host name the realm's own
// [domain_realm] maps elsewhere. Both implementations must answer
// with the same cross-realm ticket-granting ticket rather than with
// "unknown".
func TestHostReferralMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := realmTGT(t, ctx, o, Realm, UserName, UserPassword)
	msg := signTGSReqAs(t, g, referralBody(), Realm, UserName)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openReferral(t, cRaw, g)

	d := diamond(t, "kd_golden_referral",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openReferral(t, goRaw, g)

	assertReferral(t, "oracle", cx)
	assertReferral(t, "diamond", gx)
	reportDiffs(t, cx, gx)
}

// referralBody asks this realm for a host-based service it does not
// have, in a domain its kdc.conf maps to the foreign realm.
//
// KDC_OPT_CANONICALIZE is what makes it a referral request rather
// than a request for something unknown: without it upstream refuses
// outright (is_referral_req, kdc/do_tgs_req.c:446), and so does this.
func referralBody() wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK |
			wire.OptCanonicalize,
		Realm: Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ReferralService,
		},
		Till:  in(requestedLife),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
}

// openReferral decodes a reply whose ticket is the cross-realm
// ticket-granting ticket that takes a client from here to the foreign
// realm, opened with the key both realms hold for it.
//
// That is the *outbound* half of the trust and a different principal
// from the one every earlier cross-realm case used, which is the one
// detail of this test worth getting wrong twice.
func openReferral(t *testing.T, raw []byte, g tgt) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	enc := decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey)
	tkt := decryptIn(t, rep.Ticket.EncPart, Realm,
		LocalForeignPassword,
		[]string{"krbtgt", ForeignRealm},
		crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// assertReferral checks the reply names the foreign realm's
// ticket-granting service in both halves, and that nothing extra came
// with it.
func assertReferral(t *testing.T, side string, x Exchange) {
	t.Helper()
	want := "krbtgt/" + ForeignRealm
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
	if x.Enc.SRealm != Realm {
		t.Errorf("%s: the reply's server realm is %q",
			side, x.Enc.SRealm)
	}
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Errorf("%s: reply carries no session key", side)
	}
	// The client is unchanged: a referral tells a client where to
	// ask, and says nothing about who it is.
	if x.Tkt.CRealm != Realm {
		t.Errorf("%s: the ticket's client realm is %q",
			side, x.Tkt.CRealm)
	}
}

// TestHostReferralIsNotOfferedMatchesTheC covers the four ways the
// referral is refused, each of which is one line of C and each of
// which both implementations have to refuse the same way.
//
// Agreeing on a refusal proves less than agreeing on a ticket, so
// each case also asserts the *code* a client acts on rather than
// merely that both said no.
func TestHostReferralIsNotOfferedMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	g := realmTGT(t, ctx, o, Realm, UserName, UserPassword)
	d := diamond(t, "kd_golden_noreferral", time.Now().UTC)

	for _, c := range []struct {
		why  string
		body wire.KDCReqBody
	}{
		{"no canonicalize", noCanonBody()},
		{"an NT-PRINCIPAL name", principalNameBody()},
		{"a host name with no dot", shortHostBody()},
		{"an unmapped domain", ownDomainBody()},
	} {
		msg := signTGSReqAs(t, g, c.body, Realm, UserName)
		cRaw, err := o.SendRaw(ctx, msg)
		if err != nil {
			t.Fatalf("%s: asking the C KDC: %v",
				c.why, err)
		}
		goRaw, err := d.KDC.Handle(msg)
		if err != nil {
			t.Fatalf("%s: asking the Go KDC: %v",
				c.why, err)
		}
		want := wire.ErrCodeSPrincipalUnknown
		cCode := refusalCode(t, "oracle", cRaw)
		gCode := refusalCode(t, "diamond", goRaw)
		if cCode != want || gCode != want {
			t.Errorf("%s: oracle %d, diamond %d, want %d",
				c.why, cCode, gCode, want)
		}
	}
}

// noCanonBody is the referral request with the one option that makes
// it one removed.
func noCanonBody() wire.KDCReqBody {
	b := referralBody()
	b.Options &^= wire.OptCanonicalize
	return b
}

// principalNameBody asks for the same two components under
// NT-PRINCIPAL, which gets no referral whatever the configuration
// says: every type but SRV-HST, SRV-INST and a configured UNKNOWN
// falls through upstream's switch (do_tgs_req.c:472).
func principalNameBody() wire.KDCReqBody {
	b := referralBody()
	b.SName = &wire.PrincipalName{
		Type:       wire.NTPrincipal,
		Components: ReferralService,
	}
	return b
}

// shortHostBody asks for a host name with no dot in it, which is not
// a fully qualified domain name and so is not referred on
// (do_tgs_req.c:502-504).
func shortHostBody() wire.KDCReqBody {
	b := referralBody()
	b.SName = &wire.PrincipalName{
		Type:       wire.NTSrvHst,
		Components: []string{"host", "www"},
	}
	return b
}

// ownDomainBody asks for a host in a domain nothing maps, which
// resolves to the empty realm and is no answer (:511-515).
//
// The neighbouring refusal -- a map pointing *back* at the realm the
// request named, upstream's own fix for its bug #7483 -- cannot be
// driven from here, because it would need a second [domain_realm]
// entry in the oracle's own kdc.conf mapping a domain to this realm.
// internal/kdc covers it instead, where the map is a test's to
// choose.
func ownDomainBody() wire.KDCReqBody {
	b := referralBody()
	b.SName = &wire.PrincipalName{
		Type:       wire.NTSrvHst,
		Components: []string{"host", "www.unmapped.test"},
	}
	return b
}

// TestStockKvnoHostReferralAgainstTheGoKDC is the end-to-end check,
// and the only evidence that a real client follows this referral.
//
// An unmodified kinit authenticates to the *Go* KDC through the shim,
// and an unmodified kvno -C then asks it for a host-based service
// that exists only in the foreign realm. The Go KDC answers with a
// cross-realm ticket-granting ticket; the client follows it to the C
// KDC and comes back with a service ticket for a realm it was never
// told about. Every hop is the client's own doing.
//
// kvno -C is what sets KRB5_GC_CANONICALIZE (clients/kvno/kvno.c:92
// and :470-471) and -S builds an NT-SRV-HST name, so upstream's own
// gcred test program is not needed.
func TestStockKvnoHostReferralAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamondWith(t, ctx, o, "referral",
		referralConf)
	env = append(env, "KRB5_TRACE=/dev/stderr")
	out, err := o.ExecEnv(ctx, env, UserPassword+"\n",
		"kinit", UserName+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit at the Go KDC failed: %v\n%s",
			err, out)
	}
	host := ReferralService[1]
	out, err = o.ExecEnv(ctx, env, "", "kvno", "-C",
		"-S", ReferralService[0], host)
	if err != nil {
		t.Fatalf("kvno failed: %v\n%s", err, out)
	}
	svc := ReferralService[0] + "/" + host
	assertFollowedTheReferral(t, out, svc)
	// And which KDC answered which hop is the hazard, because the
	// two are in the same container and this case would pass with
	// the C doing all of the work.
	assertReferredByTheGoKDC(t, out, svc)
	assertReferralCache(t, ctx, o, env, svc)
}

// referralConf points the client's own realm at the Go KDC and the
// foreign realm at the C KDC, which is the reverse of the cross-realm
// case: there the client belonged to the C KDC's realm and reached a
// service here, and here it belongs to this realm and is sent away.
//
// There is deliberately no [domain_realm] section. The oracle's
// kdc.conf has one and the client's krb5.conf must not, or the client
// would resolve the host's realm itself, ask the foreign realm
// directly, and never need the referral this case exists for.
func referralConf(port int) string {
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
		kdc = %[3]s:%[5]d
	}

	%[2]s = {
		kdc = 127.0.0.1:%[4]d
	}

[capaths]
	%[1]s = {
		%[2]s = .
	}
	%[2]s = {
		%[1]s = .
	}

[plugins]
	clpreauth = {
		disable = pkinit
	}
`, Realm, ForeignRealm, HostAlias, OraclePort, port)
}

// assertReferralCache reads the client's own klist, which reports the
// referral in the one way a user would ever see it: the credential is
// filed under the name that was *asked for*, with a separate "Ticket
// server" line naming what actually came back. klist prints that line
// only when the two differ, so its presence is the client agreeing
// that it was referred.
//
// Worth recording because it is not what the cross-realm case sees:
// there the cross-realm ticket-granting ticket is left in the cache
// beside the service ticket, and here the referral TGT is not. The
// client keeps the ticket it wanted and discards the one that got it
// there.
func assertReferralCache(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	svc string,
) {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, "", "klist")
	if err != nil {
		t.Fatalf("klist failed: %v\n%s", err, out)
	}
	want := "Ticket server: " + svc + "@" + ForeignRealm
	if !strings.Contains(out, want) {
		t.Errorf("the cache does not report %q:\n%s",
			want, out)
	}
}

// assertReferredByTheGoKDC splits the client's trace at the moment it
// turns to the foreign realm, and checks the right KDC answered on
// each side of that line.
//
// This is the reverse of the cross-realm case's assertion and cannot
// share it. There the client's own realm was the C KDC's and the Go
// KDC answered the *second* hop; here the client belongs to this
// realm, so the Go KDC must answer the first -- the referral itself
// -- and the C KDC the second. Getting that backwards is exactly the
// failure mode where the test passes while proving nothing.
func assertReferredByTheGoKDC(
	t *testing.T, trace, svc string,
) {
	t.Helper()
	turn := "Requesting tickets for " + svc + "@" + ForeignRealm
	i := strings.Index(trace, turn)
	if i < 0 {
		t.Errorf("the client never turned to %s:\n%s",
			ForeignRealm, trace)
		return
	}
	if !strings.Contains(trace[:i],
		"Resolving hostname "+HostAlias) {
		t.Errorf("the referral was not the shim's:\n%s",
			trace[:i])
	}
	oracleAddr := fmt.Sprintf("127.0.0.1:%d", OraclePort)
	if !strings.Contains(trace[i:], oracleAddr) {
		t.Errorf("the service ticket did not come from the "+
			"C KDC:\n%s", trace[i:])
	}
}

// assertFollowedTheReferral reads the client's own trace, which names
// both hops and is the only thing that says the client understood
// what it was given.
//
// It has to be told the reply names a server it did not ask for,
// follow that, and then ask the *foreign* realm -- one it was never
// configured to know anything about. A KDC that answered the outer
// request with something plausible but not a referral would fail here
// and nowhere else.
func assertFollowedTheReferral(t *testing.T, trace, svc string) {
	t.Helper()
	for _, want := range []string{
		"Reply server krbtgt/" + ForeignRealm + "@" + Realm,
		"Following referral TGT krbtgt/" + ForeignRealm,
		"Requesting tickets for " + svc + "@" + ForeignRealm,
		"Received creds for desired service " + svc + "@" +
			ForeignRealm,
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("the trace has no %q:\n%s",
				want, trace)
		}
	}
}
