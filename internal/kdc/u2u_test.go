package kdc

import (
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// peerName is the second user in a user-to-user exchange: the one
// being asked for a ticket to, who has no service key anywhere.
var peerName = []string{"peer"}

const peerPassword = "peerpassword"

// addPeer provisions the peer, with DISALLOW_SVR set as a real
// deployment would for a principal that is not a service. That
// attribute is the point: it is what makes an ordinary TGS-REQ for
// this principal fail, so a test that issues under it has proved the
// exemption works rather than merely that nothing refused.
func addPeer(t *testing.T, k *KDC, attrs uint32) {
	t.Helper()
	mkey, err := store.DeriveMasterKey(testRealm, testMasterPW,
		store.DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	addPrincipal(t, k.Store, mkey, peerName, peerPassword, attrs)
}

// peerTGT runs an AS exchange for the peer and returns its TGT with
// the session key inside it, which is what the peer would hand to the
// client out of band.
func peerTGT(
	t *testing.T,
	k *KDC,
) (wire.Ticket, wire.EncryptionKey) {
	t.Helper()
	rep, kerr := as(t, k, asRequest(peerName))
	if kerr != nil {
		t.Fatalf("AS refused the peer: %v", kerr)
	}
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, peerName, peerPassword, e)
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the peer's reply: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return rep.Ticket, enc.Key
}

// u2uRequest builds a user-to-user TGS-REQ: the peer named as the
// server, the peer's TGT as the second ticket.
func u2uRequest(
	t *testing.T,
	tgt wire.Ticket,
	session []byte,
	second []wire.Ticket,
	components []string,
) ([]byte, wire.TGSReq) {
	t.Helper()
	msg, req := tgsRequest(t, tgt, session, components,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptEncTktInSKey
			if err := b.SetTickets(second); err != nil {
				t.Fatal(err)
			}
		})
	return msg, req
}

// The whole mechanism: a ticket to a principal with no service key,
// sealed with the session key out of that principal's own TGT.
func TestU2USealsWithTheSecondTicketsKey(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	tgt, session := getTGT(t, k)
	stkt, stktKey := peerTGT(t, k)

	msg, req := u2uRequest(t, tgt, session,
		[]wire.Ticket{stkt}, peerName)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	tkt := openWith(t, rep.Ticket, stktKey.KeyValue)
	enc := openTGSRep(t, rep, session)
	if string(tkt.Key.KeyValue) != string(enc.Key.KeyValue) {
		t.Error("the two halves carry different session keys")
	}
	if got := tkt.CName.String(); got != "user" {
		t.Errorf("ticket client is %q, want user", got)
	}
	if got := enc.SName.String(); got != "peer" {
		t.Errorf("reply names server %q, want peer", got)
	}
}

// The key version is absent, not the peer's: there is no long-term
// key involved to have a version (do_tgs_req.c:1056-1061). A client
// that read a version here would go looking for a key that was never
// used.
func TestU2UTicketCarriesNoKVNO(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	tgt, session := getTGT(t, k)
	stkt, _ := peerTGT(t, k)

	msg, req := u2uRequest(t, tgt, session,
		[]wire.Ticket{stkt}, peerName)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	if rep.Ticket.EncPart.KVNO != 0 {
		t.Errorf("kvno is %d, want 0",
			rep.Ticket.EncPart.KVNO)
	}
}

// Without the option the same principal is unreachable, which is what
// makes the exemption in svcDenyAll worth having.
func TestDisallowSvrStillRefusesAnOrdinaryRequest(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, peerName, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("a non-service principal issued a ticket")
	}
	if kerr.ErrorCode != wire.ErrCodeMustUseUser2User {
		t.Errorf("code %d, want MUST_USE_USER2USER",
			kerr.ErrorCode)
	}
}

// The option with no second ticket is BADOPTION, and it comes from
// the policy check rather than from reading the request, which is
// what upstream's ordering gives (decrypt_2ndtkt returns success with
// no ticket, do_tgs_req.c:275-277).
func TestU2UWithoutASecondTicket(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	tgt, session := getTGT(t, k)

	msg, req := u2uRequest(t, tgt, session, nil, peerName)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("issued a ticket with no second ticket")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code %d, want BADOPTION", kerr.ErrorCode)
	}
}

// The check that makes the mechanism safe. The second ticket's client
// must be the principal asked for: otherwise anyone holding any TGT
// could have the KDC seal a ticket naming someone else under a key of
// their own choosing.
func TestU2URefusesAMismatchedSecondTicket(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	stkt, _ := peerTGT(t, k)

	// The peer's TGT offered for a ticket to the service.
	msg, req := u2uRequest(t, tgt, session,
		[]wire.Ticket{stkt}, serviceName)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("sealed a ticket under the wrong peer's key")
	}
	if kerr.ErrorCode != wire.ErrCodeServerNoMatch {
		t.Errorf("code %d, want SERVER_NOMATCH",
			kerr.ErrorCode)
	}
}

// A service ticket is not a TGT, and offering one would let the
// service choose whose key seals what.
func TestU2URefusesANonTGTSecondTicket(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	// A real service ticket, obtained the ordinary way.
	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused the setup request: %v", kerr)
	}

	msg, req = u2uRequest(t, tgt, session,
		[]wire.Ticket{rep.Ticket}, peerName)
	_, kerr = k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted a service ticket as the second")
	}
	if kerr.ErrorCode != wire.ErrCodePolicy {
		t.Errorf("code %d, want POLICY", kerr.ErrorCode)
	}
}

// The session key's enctype comes from the second ticket, because
// that is the one enctype the peer is known to support -- it could
// not have read its own TGT otherwise (gen_session_key,
// do_tgs_req.c:330-345). The request here lists aes128 first, which
// an ordinary exchange would take.
func TestU2UPrefersTheSecondTicketsEType(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	tgt, session := getTGT(t, k)
	stkt, stktKey := peerTGT(t, k)

	want := stktKey.KeyType
	msg, req := tgsRequest(t, tgt, session, peerName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptEncTktInSKey
			b.EType = []int32{
				int32(crypto.AES128CTSHMACSHA196),
				want,
			}
			if err := b.SetTickets(
				[]wire.Ticket{stkt}); err != nil {
				t.Fatal(err)
			}
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, rep, session)
	if enc.Key.KeyType != want {
		t.Errorf("session key enctype %d, want %d",
			enc.Key.KeyType, want)
	}
	_ = openWith(t, rep.Ticket, stktKey.KeyValue)
}

// An enctype the request did not list is no preference at all, not an
// error: get_2ndtkt_enctype leaves useenctype at zero and
// gen_session_key falls back to the ordinary selection
// (do_tgs_req.c:320-355).
func TestU2UFallsBackWhenTheETypeIsNotOffered(t *testing.T) {
	k := testKDC(t)
	addPeer(t, k, store.AttrDisallowSvr)
	tgt, session := getTGT(t, k)
	stkt, stktKey := peerTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, peerName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptEncTktInSKey
			b.EType = []int32{
				int32(crypto.AES128CTSHMACSHA196),
			}
			if err := b.SetTickets(
				[]wire.Ticket{stkt}); err != nil {
				t.Fatal(err)
			}
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	// The ticket is still sealed with the second ticket's key
	// whatever the session key's enctype turned out to be.
	_ = openWith(t, rep.Ticket, stktKey.KeyValue)
}

// A constrained-delegation request with **no second ticket** is
// refused, which is the first of check_tgs_s4u2proxy's refusals
// (tgs_policy.c:429-432).
//
// It used to be the whole of this project's S4U2Proxy handling --
// cname-in-addl-tkt was refused outright as unimplemented -- and the
// code is the same now that it is implemented, because the option
// says a second ticket is coming and none did.
func TestS4U2ProxyNeedsASecondTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptCNameInAddlTkt
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("answered an S4U2Proxy request")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code %d, want BADOPTION", kerr.ErrorCode)
	}
}

// openWith decrypts a ticket with a key handed in, which for
// user-to-user is a session key rather than anything a principal
// holds long-term.
func openWith(
	t *testing.T,
	tkt wire.Ticket,
	key []byte,
) wire.EncTicketPart {
	t.Helper()
	p, err := crypto.Profile(crypto.EncType(tkt.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, tkt.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatalf("the handed-in key did not open it: %v", err)
	}
	out, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatalf("EncTicketPart: %v", err)
	}
	return out
}
