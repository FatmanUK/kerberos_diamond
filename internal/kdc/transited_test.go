package kdc

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
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
	mkey, err := store.DeriveMasterKey(testRealm, testMasterPW,
		store.DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	add := func(realm string, c []string, pw string) {
		p := store.NewPrincipal(realm, c)
		if err := p.SetPassword(mkey, pw, 1); err != nil {
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
