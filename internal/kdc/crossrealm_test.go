package kdc

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// foreignRealm is the other realm in the cross-realm tests, and
// remoteName its user.
const (
	foreignRealm   = "FOREIGN.TEST"
	remoteName     = "remote"
	remotePassword = "remotepassword"
	interPassword  = "interrealmpassword"
)

// twoRealms returns a KDC for this realm and one for a foreign realm
// that trusts it, both over the same store.
//
// One database holding two realms is not a cheat: a principal's key
// in the store is its *fully qualified* name, so the two realms'
// entries never collide, and it means the cross-realm test runs two
// real KDCs rather than hand-assembling a ticket one of them would
// have issued. A hand-built ticket would let a bug in the issuing
// half pass unnoticed here, and the reverse.
func twoRealms(t *testing.T, k *KDC) *KDC {
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
	add(foreignRealm, []string{remoteName}, remotePassword)
	add(foreignRealm, []string{tgsName, foreignRealm},
		"foreigntgtpassword")
	// The inter-realm principal: held by the foreign realm, named
	// for this one, and its key is what the two realms share.
	add(foreignRealm, []string{tgsName, testRealm}, interPassword)
	return &KDC{
		Store:     k.Store,
		Realm:     foreignRealm,
		ClockSkew: 5 * time.Minute,
		Now:       func() time.Time { return fixedNow },
	}
}

// crossTGT obtains a genuine cross-realm TGT the way a client does:
// an AS exchange at the foreign KDC, then an ordinary TGS exchange
// there for krbtgt/<this realm>. The second step needs no cross-realm
// code at all, which is the point -- the inter-realm principal is
// just a principal in the foreign realm's own database.
func crossTGT(
	t *testing.T,
	foreign *KDC,
) (wire.Ticket, []byte) {
	t.Helper()
	rep, kerr := as(t, foreign, remoteASRequest())
	if kerr != nil {
		t.Fatalf("the foreign AS refused: %v", kerr)
	}
	session := openRemoteReply(t, rep)

	msg, req := tgsRequestAs(t, rep.Ticket, session,
		[]string{tgsName, testRealm},
		func(b *wire.KDCReqBody) { b.Realm = foreignRealm },
		asRemote)
	out, kerr := foreign.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the foreign TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, out, session)
	return out.Ticket, enc.Key.KeyValue
}

// asRemote names the foreign realm's user in an authenticator, which
// has to agree with the presented ticket's client.
func asRemote(a *wire.Authenticator) {
	a.CRealm = foreignRealm
	a.CName = wire.PrincipalName{
		Type:       wire.NTPrincipal,
		Components: []string{remoteName},
	}
}

// remoteASRequest is asRequest for the foreign realm's user.
func remoteASRequest() wire.ASReq {
	req := asRequest([]string{remoteName})
	req.Body.Realm = foreignRealm
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{tgsName, foreignRealm},
	}
	return req
}

// openRemoteReply decrypts the foreign AS-REP with the remote user's
// own key, salted for the foreign realm.
func openRemoteReply(t *testing.T, rep *wire.ASRep) []byte {
	t.Helper()
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(remotePassword,
		crypto.Salt(foreignRealm, []string{remoteName}), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the foreign reply: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return enc.Key.KeyValue
}

// The whole of a direct cross-realm trust: a user of another realm
// obtains a ticket to a service of this one, and the service's own
// key opens it.
func TestCrossRealmTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	foreign := twoRealms(t, k)
	tgt, session := crossTGT(t, foreign)

	if tgt.Realm != foreignRealm {
		t.Fatalf("the cross TGT's realm is %q", tgt.Realm)
	}
	msg, req := tgsRequestAs(t, tgt, session, serviceName,
		nil, asRemote)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	assertCrossIssued(t, rep)
}

// assertCrossIssued checks the reply is a ticket of this realm for a
// client of the other.
func assertCrossIssued(t *testing.T, rep *wire.TGSRep) {
	t.Helper()
	tkt := openServiceTicket(t, rep)
	if tkt.CRealm != foreignRealm {
		t.Errorf("ticket client realm is %q, want %q",
			tkt.CRealm, foreignRealm)
	}
	if got := tkt.CName.String(); got != remoteName {
		t.Errorf("ticket client is %q, want %q",
			got, remoteName)
	}
	// The ticket itself belongs to *this* realm whatever realm
	// the client came from: it is this realm's service it names.
	if rep.Ticket.Realm != testRealm {
		t.Errorf("issued ticket's realm is %q",
			rep.Ticket.Realm)
	}
	if rep.CRealm != foreignRealm {
		t.Errorf("reply client realm is %q", rep.CRealm)
	}
	// One hop records nothing: the realm that issued the
	// presented ticket is the client's own, so no realm was
	// passed through that the two ends do not already name.
	if len(tkt.Transited.Contents) != 0 {
		t.Errorf("transited path is %q",
			tkt.Transited.Contents)
	}
}

// A foreign KDC may not assert a client of *this* realm. If it could,
// any realm trusted for its own users could mint a ticket naming a
// local principal and every service here would believe it
// (check_tgs_lineage, kdc/tgs_policy.c:249-258).
func TestCrossRealmCannotClaimALocalClient(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	foreign := twoRealms(t, k)

	// The foreign realm issues a cross TGT to a client it names
	// in *this* realm, which is exactly the forgery the check
	// exists for. It takes a hand-built ticket because no honest
	// KDC produces one.
	tgt, session := crossTGT(t, foreign)
	forged := reseal(t, k, tgt, func(e *wire.EncTicketPart) {
		e.CRealm = testRealm
	})

	msg, req := tgsRequestAs(t, forged, session, serviceName,
		nil, func(a *wire.Authenticator) {
			asRemote(a)
			a.CRealm = testRealm
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("a foreign realm named a local client")
	}
	if kerr.ErrorCode != wire.ErrCodePolicy {
		t.Errorf("code %d, want POLICY", kerr.ErrorCode)
	}
}

// A path through a third realm has to be recorded in the transited
// field, and building that record is not implemented, so it is
// refused rather than carried across with the third realm silently
// dropped.
func TestCrossRealmRefusesAThirdRealm(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	foreign := twoRealms(t, k)

	// A client of some third realm, as the foreign KDC would have
	// recorded it after a hop of its own.
	tgt, session := crossTGT(t, foreign)
	relayed := reseal(t, k, tgt, func(e *wire.EncTicketPart) {
		e.CRealm = "THIRD.TEST"
	})

	msg, req := tgsRequestAs(t, relayed, session, serviceName,
		nil, func(a *wire.Authenticator) {
			asRemote(a)
			a.CRealm = "THIRD.TEST"
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted a two-hop path with no transit")
	}
	if kerr.ErrorCode != wire.ErrCodePathNotAccepted {
		t.Errorf("code %d, want PATH_NOT_ACCEPTED",
			kerr.ErrorCode)
	}
}

// reseal reopens a cross-realm TGT with the inter-realm key, applies
// a change, and seals it again -- which is what a malicious or a
// further-along KDC would have sent.
func reseal(
	t *testing.T,
	k *KDC,
	tkt wire.Ticket,
	change func(*wire.EncTicketPart),
) wire.Ticket {
	t.Helper()
	e := crypto.EncType(tkt.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(interPassword,
		crypto.Salt(foreignRealm,
			[]string{tgsName, testRealm}), nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, tkt.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatalf("opening the cross TGT: %v", err)
	}
	part, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatal(err)
	}
	change(&part)
	out, err := wire.MarshalEncTicketPart(part)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(key, out, crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatal(err)
	}
	tkt.EncPart.Cipher = ct
	return tkt
}
