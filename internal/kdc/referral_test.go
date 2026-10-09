package kdc

import (
	"context"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/hostrealm"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// refRealm is the realm the map points at, and refHost a host in the
// domain it is mapped by. The shape mirrors upstream's own referral
// fixture, which maps the single label "d" and creates a/x.d only in
// the other realm (tests/t_referral.py:5-11).
const (
	refRealm = "REFREALM.TEST"
	refHost  = "x.d"
)

// gateKDC is a KDC with the referral configuration and nothing else:
// no store, no realm fixture. Every gate case runs against it,
// because is_referral_req reaches no database at all and a case that
// needed Postgres to assert a name type would be the wrong shape.
func gateKDC(hosts, hostBased, noReferral string) *KDC {
	m, err := hostrealm.Parse(hosts)
	if err != nil {
		panic(err)
	}
	return &KDC{
		Realm:             testRealm,
		Hosts:             m,
		HostBasedServices: hostrealm.Services(hostBased),
		NoHostReferral:    hostrealm.Services(noReferral),
	}
}

// askFor builds just enough state for the gate: a request naming a
// service of some name type, with canonicalize set unless a case says
// otherwise.
func askFor(
	nameType int32, components []string, opts wire.Flags,
) *tgsState {
	return &tgsState{req: wire.TGSReq{Body: wire.KDCReqBody{
		Options: wire.OptCanonicalize | opts,
		Realm:   testRealm,
		SName: &wire.PrincipalName{
			Type:       nameType,
			Components: components,
		},
	}}}
}

// referred is the realm the gate would refer to, or "" for a refusal,
// which is what every gate case asserts.
func referred(k *KDC, s *tgsState) string {
	name, ok := k.referralTGSName(s)
	if !ok {
		return ""
	}
	return name.Components[1]
}

// With nothing configured but the map, a referral is offered for an
// NT-SRV-HST or NT-SRV-INST server name and refused for NT-UNKNOWN or
// NT-PRINCIPAL -- which is exactly upstream's first block of
// assertions (t_referral.py:41-45).
//
// The reason the type decides it is worth stating, because it reads
// as arbitrary: an unknown type says nothing about whether the second
// component is a host name, so referring on one would mean guessing.
func TestReferralTurnsOnTheNameType(t *testing.T) {
	k := gateKDC("d="+refRealm, "", "")
	for _, c := range []struct {
		nameType int32
		name     string
		want     string
	}{
		{wire.NTSrvHst, "srv-hst", refRealm},
		{wire.NTSrvInst, "srv-inst", refRealm},
		{wire.NTUnknown, "unknown", ""},
		{wire.NTPrincipal, "principal", ""},
	} {
		s := askFor(c.nameType, []string{"a", refHost}, 0)
		if got := referred(k, s); got != c.want {
			t.Errorf("%s: referred to %q, want %q",
				c.name, got, c.want)
		}
	}
}

// host_based_services makes an NT-UNKNOWN name eligible, and leaves
// NT-SRV-HST and NT-PRINCIPAL alone -- the first was eligible already
// and the second never is, whatever the configuration says
// (t_referral.py:53-69).
func TestHostBasedServicesAdmitsAnUnknownType(t *testing.T) {
	for _, list := range []string{"*", "a", "b,a", "a b c"} {
		k := gateKDC("d="+refRealm, list, "")
		s := askFor(wire.NTUnknown,
			[]string{"a", refHost}, 0)
		if got := referred(k, s); got != refRealm {
			t.Errorf("%q: referred to %q, want %q",
				list, got, refRealm)
		}
		s = askFor(wire.NTPrincipal,
			[]string{"a", refHost}, 0)
		if got := referred(k, s); got != "" {
			t.Errorf("%q: a principal name referred "+
				"to %q", list, got)
		}
	}
	// A list that does not name the service leaves it where it
	// started, and an NT-SRV-HST name is unaffected either way.
	k := gateKDC("d="+refRealm, "b,c", "")
	if got := referred(k, askFor(wire.NTUnknown,
		[]string{"a", refHost}, 0)); got != "" {
		t.Errorf("an unlisted service referred to %q", got)
	}
	if got := referred(k, askFor(wire.NTSrvHst,
		[]string{"a", refHost}, 0)); got != refRealm {
		t.Errorf("srv-hst referred to %q, want %q",
			got, refRealm)
	}
}

// no_host_referral excludes a service whatever its name type, and
// overrides host_based_services rather than being weighed against it
// (t_referral.py:73-93).
func TestNoHostReferralOverridesEverything(t *testing.T) {
	for _, list := range []string{"*", "a", "b,a"} {
		k := gateKDC("d="+refRealm, "", list)
		s := askFor(wire.NTSrvHst,
			[]string{"a", refHost}, 0)
		if got := referred(k, s); got != "" {
			t.Errorf("%q: srv-hst still referred to %q",
				list, got)
		}
	}
	// Both wildcards at once: the exclusion wins.
	k := gateKDC("d="+refRealm, "*", "*")
	s := askFor(wire.NTUnknown, []string{"a", refHost}, 0)
	if got := referred(k, s); got != "" {
		t.Errorf("no_host_referral lost to "+
			"host_based_services: %q", got)
	}
}

// The referral is opt-in by the client. Without KDC_OPT_CANONICALIZE
// the service is simply unknown, which is the truth
// (do_tgs_req.c:446) -- and this is the first use of the option
// anywhere in this project, so a test that it is read at all earns
// its place.
func TestNoReferralWithoutCanonicalize(t *testing.T) {
	k := gateKDC("d="+refRealm, "", "")
	s := askFor(wire.NTSrvHst, []string{"a", refHost}, 0)
	s.req.Body.Options &^= wire.OptCanonicalize
	if got := referred(k, s); got != "" {
		t.Errorf("referred to %q with no canonicalize", got)
	}
}

// Each of the other three refusals inside find_referral_tgs, which
// are easy to leave out because each is one line of C.
func TestTheThreeRefusalsInsideTheLookup(t *testing.T) {
	for _, c := range []struct {
		why        string
		hosts      string
		components []string
	}{
		// A name with no dot is not a fully qualified domain
		// name (:502-504).
		{"no dot in the host", "d=" + refRealm,
			[]string{"a", "x"}},
		// No match is the empty realm, which is not an answer
		// (:511-515).
		{"no entry matches", "e=" + refRealm,
			[]string{"a", refHost}},
		// And a map pointing back at the realm the request
		// named is upstream's own fix for its bug #7483:
		// without it a client is told to ask the realm it
		// just asked.
		{"back to the same realm", "d=" + testRealm,
			[]string{"a", refHost}},
	} {
		k := gateKDC(c.hosts, "", "")
		s := askFor(wire.NTSrvHst, c.components, 0)
		if got := referred(k, s); got != "" {
			t.Errorf("%s: referred to %q", c.why, got)
		}
	}
}

// User-to-user names a ticket the client already holds, so a referral
// would answer a different question (:449). The rest of
// NO_REFERRAL_OPTION is checked one level up, in alternate, and
// transited_test.go already covers it there.
func TestNoReferralForUserToUser(t *testing.T) {
	k := gateKDC("d="+refRealm, "", "")
	s := askFor(wire.NTSrvHst, []string{"a", refHost},
		wire.OptEncTktInSKey)
	if got := referred(k, s); got != "" {
		t.Errorf("referred to %q for user-to-user", got)
	}
}

// A name with the wrong number of components is not a host-based
// service name (:452). One component cannot name a host and three is
// not a shape the referral understands.
func TestReferralNeedsExactlyTwoComponents(t *testing.T) {
	k := gateKDC("d="+refRealm, "", "")
	for _, components := range [][]string{
		{"a"}, {"a", refHost, "extra"},
	} {
		s := askFor(wire.NTSrvHst, components, 0)
		if got := referred(k, s); got != "" {
			t.Errorf("%v referred to %q", components, got)
		}
	}
}

// And the whole thing end to end: a real request for a service this
// realm has never heard of comes back as a ticket for the referred
// realm's ticket-granting service, sealed with the inter-realm key.
//
// The issued ticket names something other than what was asked for,
// which is what a referral is, and the reply's sealed half has to
// agree with it -- a client that cached the credential under the name
// it asked for would present it to the wrong realm.
func TestHostReferralIssuesACrossRealmTGT(t *testing.T) {
	k := testKDC(t)
	addRefTrust(t, k, refRealm, "refrealm-trust")
	m, err := hostrealm.Parse("d=" + refRealm)
	if err != nil {
		t.Fatal(err)
	}
	k.Hosts = m

	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session,
		[]string{"a", refHost},
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptCanonicalize
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the TGS refused: %v", kerr)
	}
	want := tgsName + "/" + refRealm
	if got := rep.Ticket.SName.String(); got != want {
		t.Errorf("the ticket names %q, want %q", got, want)
	}
	enc := openTGSRep(t, rep, session)
	if got := enc.SName.String(); got != want {
		t.Errorf("the reply names %q, want %q", got, want)
	}
}

// Without canonicalize the same request is refused, and with the same
// code a client would get for any service that does not exist. That
// pairing is the point: the referral adds an answer and takes none
// away.
func TestWithoutCanonicalizeTheServiceIsUnknown(t *testing.T) {
	k := testKDC(t)
	addRefTrust(t, k, refRealm, "refrealm-trust")
	m, err := hostrealm.Parse("d=" + refRealm)
	if err != nil {
		t.Fatal(err)
	}
	k.Hosts = m

	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session,
		[]string{"a", refHost}, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("issued a ticket with no canonicalize")
	}
	if kerr.ErrorCode != wire.ErrCodeSPrincipalUnknown {
		t.Errorf("code %d, want S_PRINCIPAL_UNKNOWN",
			kerr.ErrorCode)
	}
}

// A map may name a realm this one holds no direct trust with, and
// upstream does not treat that as the end: search_sprinc runs the
// alternate-TGS search on the *referral* name (do_tgs_req.c:562-571)
// so the client is handed an intermediate towards the realm the map
// named.
//
// The two referrals are usually described separately and this is the
// one place they meet. Here the map points at the far realm, this
// realm holds no trust with it, and the hierarchy's first hop from
// here is the middle realm -- so that is what comes back.
func TestAMapToAnUntrustedRealmFallsThroughToTheSearch(t *testing.T) {
	k := testKDC(t)
	threeRealms(t, k)
	addRefTrust(t, k, midRealm, "local-mid")
	m, err := hostrealm.Parse("d=" + farRealm)
	if err != nil {
		t.Fatal(err)
	}
	k.Hosts = m

	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session,
		[]string{"a", refHost},
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptCanonicalize
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the TGS refused: %v", kerr)
	}
	want := tgsName + "/" + midRealm
	if got := rep.Ticket.SName.String(); got != want {
		t.Errorf("the ticket names %q, want %q", got, want)
	}
}

// addRefTrust gives this realm the inter-realm key for another, which
// is the whole of a trust: holding krbtgt/<there>@<here> is what lets
// this KDC issue a ticket-granting ticket for there.
func addRefTrust(t *testing.T, k *KDC, realm, pw string) {
	t.Helper()
	p := store.NewPrincipal(testRealm,
		[]string{tgsName, realm})
	if err := k.Store.SetPassword(p, pw,
		1); err != nil {
		t.Fatal(err)
	}
	if err := k.Store.Save(context.Background(), p); err != nil {
		t.Fatal(err)
	}
}
