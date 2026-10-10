package kdc

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/transit"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// A hierarchy of three realms below this one's name, so that the path
// between the ends runs through the middle by the naming convention
// alone -- which is all this implementation has, having no [capaths].
//
// farRealm is where the client is, midRealm is what it passes
// through, and testRealm is where the service is.
const (
	midRealm = "OTHER." + testRealm
	farRealm = "SUB." + midRealm
	farUser  = "far"
)

// threeRealms adds the two extra realms and returns a KDC for each.
//
// All three share one store for the reason twoRealms gives: a
// principal's key in the store is its fully qualified name, so the
// realms never collide, and the test then drives three real KDCs
// rather than hand-assembling the tickets two of them would have
// issued.
func threeRealms(
	t *testing.T,
	k *KDC,
) (far, mid *KDC) {
	t.Helper()
	add := func(realm string, c []string, pw string) {
		p := store.NewPrincipal(realm, c)
		if err := k.Store.SetPassword(p, pw,
			1); err != nil {
			t.Fatalf("SetPassword %v: %v", c, err)
		}
		err := k.Store.Save(context.Background(), p)
		if err != nil {
			t.Fatalf("Save %v: %v", c, err)
		}
	}
	add(farRealm, []string{farUser}, "farpassword")
	add(farRealm, []string{tgsName, farRealm}, "fartgt")
	// The two trusts, one hop each. Each is a single principal,
	// and one entry serves both realms that need it because there
	// is one store.
	add(farRealm, []string{tgsName, midRealm}, "far-mid")
	add(midRealm, []string{tgsName, midRealm}, "midtgt")
	add(midRealm, []string{tgsName, testRealm}, "mid-local")
	return realmKDC(k, farRealm), realmKDC(k, midRealm)
}

// realmKDC is another KDC over the same store, serving another realm.
func realmKDC(k *KDC, realm string) *KDC {
	return &KDC{
		Store:     k.Store,
		Realm:     realm,
		ClockSkew: 5 * time.Minute,
		Now:       func() time.Time { return fixedNow },
	}
}

// farTGT runs an AS exchange at the far realm for its user.
func farTGT(t *testing.T, far *KDC) (wire.Ticket, []byte) {
	t.Helper()
	req := asRequest([]string{farUser})
	req.Body.Realm = farRealm
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{tgsName, farRealm},
	}
	rep, kerr := as(t, far, req)
	if kerr != nil {
		t.Fatalf("the far AS refused: %v", kerr)
	}
	return rep.Ticket, openReplyFor(t, rep, farRealm,
		[]string{farUser}, "farpassword")
}

// openReplyFor decrypts an AS-REP with a named principal's own key,
// salted for its own realm.
func openReplyFor(
	t *testing.T,
	rep *wire.ASRep,
	realm string,
	components []string,
	password string,
) []byte {
	t.Helper()
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(password,
		crypto.Salt(realm, components), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the reply: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return enc.Key.KeyValue
}

// asFarUser names the far realm's user in an authenticator.
func asFarUser(a *wire.Authenticator) {
	a.CRealm = farRealm
	a.CName = wire.PrincipalName{
		Type:       wire.NTPrincipal,
		Components: []string{farUser},
	}
}

// hop spends a ticket at one KDC for a ticket-granting service in
// another realm, which is what a client does at each step of a path.
func hop(
	t *testing.T,
	at *KDC,
	tkt wire.Ticket,
	session []byte,
	want string,
) (wire.Ticket, []byte) {
	t.Helper()
	msg, req := tgsRequestAs(t, tkt, session,
		[]string{tgsName, want},
		func(b *wire.KDCReqBody) { b.Realm = at.Realm },
		asFarUser)
	rep, kerr := at.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("%s refused a hop to %s: %v",
			at.Realm, want, kerr)
	}
	enc := openTGSRep(t, rep, session)
	return rep.Ticket, enc.Key.KeyValue
}

// Three realms, two boundaries, and the middle one has to appear in
// the issued ticket's transited field. This is the case the whole of
// internal/transit exists for: with one boundary the field stays
// empty and nothing is exercised at all.
func TestThreeRealmPathRecordsTheMiddleRealm(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	far, mid := threeRealms(t, k)

	tgt, session := farTGT(t, far)
	// The client's own KDC issues the first cross TGT; the middle
	// realm's KDC issues the second. Neither hop records
	// anything: each presented ticket came from the client's own
	// realm.
	cross, session := hop(t, far, tgt, session, midRealm)
	cross, session = hop(t, mid, cross, session, testRealm)

	msg, req := tgsRequestAs(t, cross, session, serviceName,
		nil, asFarUser)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	if got := string(tkt.Transited.Contents); got != midRealm {
		t.Errorf("transited path is %q, want %q",
			got, midRealm)
	}
	if tkt.Transited.Type != wire.TransitedDomainX500Compress {
		t.Errorf("transited type is %d",
			tkt.Transited.Type)
	}
	// The flag is the evidence a service acts on: it says the KDC
	// looked at the path and was satisfied, which is a different
	// claim from the path merely being present.
	if !tkt.Flags.Has(wire.FlagTransitedPolicyChecked) {
		t.Error("the transited-policy-checked flag is clear")
	}
	if tkt.CRealm != farRealm {
		t.Errorf("ticket client realm is %q", tkt.CRealm)
	}
}

// The second hop records nothing, because the ticket it presents came
// from the client's own realm. Asserting it is worth doing: a KDC
// that added a realm on every cross-realm hop would still pass the
// case above, and would then name realms the path never went through.
func TestTheFirstTwoHopsRecordNothing(t *testing.T) {
	k := testKDC(t)
	far, mid := threeRealms(t, k)

	tgt, session := farTGT(t, far)
	cross, session := hop(t, far, tgt, session, midRealm)
	first := decodeTicketWith2(t, cross, "far-mid",
		farRealm, []string{tgsName, midRealm})
	if got := string(first.Transited.Contents); got != "" {
		t.Errorf("the first hop recorded %q", got)
	}

	cross, _ = hop(t, mid, cross, session, testRealm)
	second := decodeTicketWith2(t, cross, "mid-local",
		midRealm, []string{tgsName, testRealm})
	if got := string(second.Transited.Contents); got != "" {
		t.Errorf("the second hop recorded %q", got)
	}
}

// decodeTicketWith2 opens a ticket with a principal's key, salted for
// a named realm. decodeTicketWith assumes this realm's salt, which an
// inter-realm principal does not use.
func decodeTicketWith2(
	t *testing.T,
	tkt wire.Ticket,
	password, realm string,
	components []string,
) wire.EncTicketPart {
	t.Helper()
	e := crypto.EncType(tkt.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(password,
		crypto.Salt(realm, components), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, tkt.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatalf("decrypting the ticket: %v", err)
	}
	out, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatalf("EncTicketPart: %v", err)
	}
	return out
}

// A client with no path configuration of its own asks for the trust
// it wants and gets an intermediate instead. This is the hop the C
// KDC took the first time this project's three-realm fixture was
// driven by hand: asked for krbtgt/<here> from the far realm, which
// holds no such key, it answered with krbtgt/<middle>@<far> and let
// the client ask again from there (find_alternate_tgs,
// do_tgs_req.c:371).
func TestAlternateTGSIsOffered(t *testing.T) {
	k := testKDC(t)
	far, _ := threeRealms(t, k)

	tgt, session := farTGT(t, far)
	// The far realm has no trust with this one, only with the
	// middle realm.
	msg, req := tgsRequestAs(t, tgt, session,
		[]string{tgsName, testRealm},
		func(b *wire.KDCReqBody) { b.Realm = farRealm },
		asFarUser)
	rep, kerr := far.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the far TGS refused: %v", kerr)
	}
	want := tgsName + "/" + midRealm
	if got := rep.Ticket.SName.String(); got != want {
		t.Errorf("the ticket names %q, want %q", got, want)
	}
	// The reply's sealed half has to agree with the ticket, or a
	// client would cache the credential under the name it asked
	// for and present it to the wrong realm.
	enc := openTGSRep(t, rep, session)
	if got := enc.SName.String(); got != want {
		t.Errorf("the reply names %q, want %q", got, want)
	}
}

// A realm with no reachable hop towards it is still unknown. The
// search offers an intermediate, not any key the realm happens to
// hold.
//
// This is driven from the *local* realm rather than the far one, and
// the reason is a finding: the hierarchical walk from a realm always
// begins with that realm's immediate parent, so any realm holding a
// trust with its parent has *something* to offer towards everywhere.
// Asked for krbtgt/ELSEWHERE.TEST, the far realm answers with the
// middle realm's TGT and lets the client discover the dead end
// further along -- and the C KDC was asked and does exactly the same.
// The local realm holds no trust at all along that path, so it is the
// one that can refuse.
func TestAlternateTGSRefusesAnUnreachableRealm(t *testing.T) {
	k := testKDC(t)
	threeRealms(t, k)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session,
		[]string{tgsName, "ELSEWHERE.TEST"}, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("issued a ticket with no hop to offer")
	}
	if kerr.ErrorCode != wire.ErrCodeSPrincipalUnknown {
		t.Errorf("code %d, want S_PRINCIPAL_UNKNOWN",
			kerr.ErrorCode)
	}
}

// A configured path decides the search as much as it decides the
// check: the far realm's hierarchy would find the middle realm
// anyway, so the case worth asserting is one where configuration
// sends it somewhere the names do not.
func TestAlternateTGSFollowsAConfiguredPath(t *testing.T) {
	k := testKDC(t)
	far, _ := threeRealms(t, k)
	// Nothing in the names relates these two, and the path says
	// to go through the middle realm.
	paths, err := transit.ParsePaths(
		farRealm + ">ELSEWHERE.TEST=" + midRealm)
	if err != nil {
		t.Fatal(err)
	}
	far.Paths = paths

	tgt, session := farTGT(t, far)
	msg, req := tgsRequestAs(t, tgt, session,
		[]string{tgsName, "ELSEWHERE.TEST"},
		func(b *wire.KDCReqBody) { b.Realm = farRealm },
		asFarUser)
	rep, kerr := far.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the far TGS refused: %v", kerr)
	}
	want := tgsName + "/" + midRealm
	if got := rep.Ticket.SName.String(); got != want {
		t.Errorf("the ticket names %q, want %q", got, want)
	}
}

// The options that name a ticket the client already holds forbid a
// referral (NO_REFERRAL_OPTION, kdc/kdc_util.h:460): answering one
// with a different server would answer a different question.
func TestNoReferralForATicketTheClientHolds(t *testing.T) {
	k := testKDC(t)
	far, _ := threeRealms(t, k)

	tgt, session := farTGT(t, far)
	msg, req := tgsRequestAs(t, tgt, session,
		[]string{tgsName, testRealm},
		func(b *wire.KDCReqBody) {
			b.Realm = farRealm
			b.Options |= wire.OptRenew
		},
		asFarUser)
	_, kerr := far.TGS(msg, req)
	if kerr == nil {
		t.Fatal("a renewal was answered with a referral")
	}
	if kerr.ErrorCode != wire.ErrCodeSPrincipalUnknown {
		t.Errorf("code %d, want S_PRINCIPAL_UNKNOWN",
			kerr.ErrorCode)
	}
}

// Configuration is consulted for the transited check and not only for
// the referral search. The path here deliberately routes around the
// realm the ticket actually came through, so the same request that
// succeeds on the hierarchy must now be refused -- which is what says
// the KDC reads its Paths at all.
func TestConfiguredPathIsUsedForTheCheck(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	far, mid := threeRealms(t, k)

	tgt, session := farTGT(t, far)
	cross, session := hop(t, far, tgt, session, midRealm)
	cross, session = hop(t, mid, cross, session, testRealm)

	// A path from the far realm to here that goes somewhere else.
	paths, err := transit.ParsePaths(
		farRealm + ">" + testRealm + "=ELSEWHERE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	k.Paths = paths

	msg, req := tgsRequestAs(t, cross, session, serviceName,
		nil, asFarUser)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("a route the path excludes was accepted")
	}
	if kerr.ErrorCode != wire.ErrCodePolicy {
		t.Errorf("code %d, want POLICY", kerr.ErrorCode)
	}

	// And the same request succeeds once the configuration names
	// the realm the ticket really came through, so the refusal
	// above was the path and not something else.
	paths, err = transit.ParsePaths(
		farRealm + ">" + testRealm + "=" + midRealm)
	if err != nil {
		t.Fatal(err)
	}
	k.Paths = paths
	if _, kerr := k.TGS(msg, req); kerr != nil {
		t.Errorf("the configured route was refused: %v", kerr)
	}
}
