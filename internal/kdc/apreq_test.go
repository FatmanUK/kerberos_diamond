package kdc

import (
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// localMasterKey reproduces the fixture's master key, which the
// fixture derives from the same realm and password.
func localMasterKey(t *testing.T) store.MasterKey {
	t.Helper()
	mkey, err := store.DeriveMasterKey(testRealm, testMasterPW,
		store.DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	return mkey
}

// adminService adds one of this realm's administrative principals,
// which the fixture does not carry: nothing before this needed one.
func addAdminService(t *testing.T, k *KDC, instance string) {
	t.Helper()
	addPrincipal(t, k.Store, localMasterKey(t),
		[]string{adminName, instance}, "adminpassword", 0)
}

// adminTicketFromTGT gets a service ticket for an administrative
// principal the way a remote administrator would: a TGT spent at the
// TGS. Such a ticket is deliberately *not* initial.
func adminTicketFromTGT(
	t *testing.T, k *KDC, instance string,
) (wire.Ticket, []byte) {
	t.Helper()
	addAdminService(t, k, instance)
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session,
		[]string{adminName, instance}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the TGS refused: %v", kerr)
	}
	return rep.Ticket, openTGSRep(t, rep, session).Key.KeyValue
}

// adminTicketFromAS gets one the way `kinit -S` would, directly from
// an AS exchange, which is the only way to get a ticket that carries
// TKT_FLG_INITIAL.
func adminTicketFromAS(
	t *testing.T, k *KDC, instance string,
) (wire.Ticket, []byte) {
	t.Helper()
	addAdminService(t, k, instance)
	req := asRequest([]string{"user"})
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{adminName, instance},
	}
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("the AS refused: %v", kerr)
	}
	return rep.Ticket, decodeReply(t, k, rep).Key.KeyValue
}

// adminAuthenticator is what a client sends with an application
// AP-REQ: no checksum, because there is no KDC-REQ-BODY to cover and
// what an application puts there is the application's own business.
func adminAuthenticator(
	mutate func(*wire.Authenticator),
) wire.Authenticator {
	auth := wire.Authenticator{
		CRealm: testRealm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{"user"},
		},
		CUsec: 1234,
		CTime: fixedNow,
	}
	if mutate != nil {
		mutate(&auth)
	}
	return auth
}

// adminAPReq builds the application AP-REQ a client would present,
// with its authenticator under key usage 11.
func adminAPReq(
	t *testing.T,
	tkt wire.Ticket,
	sessionKey []byte,
	mutate func(*wire.Authenticator),
) []byte {
	t.Helper()
	p := aes256(t)
	plain, err := wire.MarshalAuthenticator(
		adminAuthenticator(mutate))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(sessionKey, plain,
		crypto.UsageAPReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	der, err := wire.MarshalAPReq(wire.APReq{
		Ticket: tkt,
		Authenticator: wire.EncryptedData{
			EType:  int32(crypto.AES256CTSHMACSHA196),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The whole point: an AP-REQ nothing in a KDC exchange produced is
// opened, and the principal it names comes back fully qualified --
// which is the form an access control list matches on.
func TestAcceptAPReqNamesTheClient(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, "admin")

	id, kerr := k.AcceptAPReq(
		adminAPReq(t, tkt, session, nil))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := id.Name(); got != "user@"+testRealm {
		t.Errorf("client is %q", got)
	}
	want := adminName + "/admin"
	if got := id.Service.String(); got != want {
		t.Errorf("service is %q, want %q", got, want)
	}
	// A ticket obtained by spending a TGT is not initial, and
	// that is the condition upstream's self-key-change check
	// exists to refuse: it wants the holder to have typed the
	// password again, not merely to hold a ticket.
	if id.Initial {
		t.Error("a TGS-issued ticket reported itself initial")
	}
}

// A ticket straight from an AS exchange is initial, which is what
// `kinit -S kadmin/changepw` produces and what a self key change
// requires (check_self_keychange, server_stubs.c:369-381).
func TestAcceptAPReqReportsAnInitialTicket(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, "changepw")

	id, kerr := k.AcceptAPReq(
		adminAPReq(t, tkt, session, nil))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if !id.Initial {
		t.Error("an AS-issued ticket did not report initial")
	}
}

// The subkey and the sequence number are carried rather than checked,
// because checking the sequence number needs state this package does
// not keep. A caller that cannot see them cannot use them, so the
// assertion is that they arrive.
func TestAcceptAPReqCarriesTheSubkeyAndSequence(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, "admin")

	sub := &wire.EncryptionKey{
		KeyType:  int32(crypto.AES256CTSHMACSHA196),
		KeyValue: make([]byte, 32),
	}
	for i := range sub.KeyValue {
		sub.KeyValue[i] = byte(i)
	}
	id, kerr := k.AcceptAPReq(adminAPReq(t, tkt, session,
		func(a *wire.Authenticator) {
			a.SubKey = sub
			a.SeqNumber = 0x1234
		}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if id.SubKey == nil ||
		string(id.SubKey.KeyValue) != string(sub.KeyValue) {
		t.Errorf("subkey is %v", id.SubKey)
	}
	if id.Seq != 0x1234 {
		t.Errorf("sequence is %d, want 4660", id.Seq)
	}
}

// Every refusal, each by the code a caller acts on. They are separate
// codes on purpose: a client that presented an expired ticket should
// try again, and one that presented a ticket for the wrong service
// should not.
func TestAcceptAPReqRefusals(t *testing.T) {
	for _, c := range []struct {
		why  string
		want int32
		run  func(t *testing.T, k *KDC) []byte
	}{
		{"not an administrative service",
			wire.ErrCodeServerNoMatch, nonAdminAPReq},
		{"the history service",
			wire.ErrCodeServerNoMatch, historyAPReq},
		{"a three-component name",
			wire.ErrCodeServerNoMatch, longNameAPReq},
		{"the wrong session key",
			wire.ErrCodeBadIntegrity, wrongKeyAPReq},
		{"an authenticator naming someone else",
			wire.ErrCodeBadMatch, wrongClientAPReq},
		{"a stale clock",
			wire.ErrCodeSkew, staleAPReq},
		{"a user-to-user ticket",
			wire.ErrCodePolicy, sessionKeyAPReq},
		{"garbage", wire.ErrCodeModified, garbageAPReq},
	} {
		t.Run(c.why, func(t *testing.T) {
			k := testKDC(t)
			_, kerr := k.AcceptAPReq(c.run(t, k))
			if kerr == nil {
				t.Fatal("accepted")
			}
			if kerr.ErrorCode != c.want {
				t.Errorf("code %d, want %d",
					kerr.ErrorCode, c.want)
			}
		})
	}
}

// A ticket for an ordinary service authenticates nobody here. This is
// the check that matters most, because the gate is the only thing
// standing between "holds a ticket to anything in the realm" and "may
// administer the realm" -- which is exactly the hole upstream's own
// comment describes itself as plugging.
func nonAdminAPReq(t *testing.T, k *KDC) []byte {
	svc := []string{"host", "service.kdiamond.test"}
	addPrincipal(t, k.Store, localMasterKey(t), svc,
		"servicepassword", 0)
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, svc, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the TGS refused: %v", kerr)
	}
	return adminAPReq(t, rep.Ticket,
		openTGSRep(t, rep, session).Key.KeyValue, nil)
}

// kadmin/history is the one administrative name excluded, because its
// key is what stored password history is sealed with.
func historyAPReq(t *testing.T, k *KDC) []byte {
	tkt, session := adminTicketFromTGT(t, k, historyName)
	return adminAPReq(t, tkt, session, nil)
}

// Exactly two components, so kadmin/admin/extra is not one.
func longNameAPReq(t *testing.T, k *KDC) []byte {
	addPrincipal(t, k.Store, localMasterKey(t),
		[]string{adminName, "admin", "extra"},
		"adminpassword", 0)
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session,
		[]string{adminName, "admin", "extra"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the TGS refused: %v", kerr)
	}
	return adminAPReq(t, rep.Ticket,
		openTGSRep(t, rep, session).Key.KeyValue, nil)
}

// Holding the ticket is not holding the session key, and the second
// is the proof of possession.
func wrongKeyAPReq(t *testing.T, k *KDC) []byte {
	tkt, session := adminTicketFromTGT(t, k, "admin")
	wrong := make([]byte, len(session))
	copy(wrong, session)
	wrong[0] ^= 0xFF
	return adminAPReq(t, tkt, wrong, nil)
}

// The authenticator's client has to be the ticket's client, or a
// holder of one principal's session key could claim another's name.
func wrongClientAPReq(t *testing.T, k *KDC) []byte {
	tkt, session := adminTicketFromTGT(t, k, "admin")
	return adminAPReq(t, tkt, session,
		func(a *wire.Authenticator) {
			a.CName.Components = []string{"someone-else"}
		})
}

// The skew window is the whole of the freshness check here, so a
// timestamp outside it has to be refused.
func staleAPReq(t *testing.T, k *KDC) []byte {
	tkt, session := adminTicketFromTGT(t, k, "admin")
	return adminAPReq(t, tkt, session,
		func(a *wire.Authenticator) {
			a.CTime = fixedNow.Add(-time.Hour)
		})
}

// AP-OPTIONS use-session-key says the ticket is sealed with a key out
// of a second ticket, which this surface was never given.
func sessionKeyAPReq(t *testing.T, k *KDC) []byte {
	tkt, session := adminTicketFromTGT(t, k, "admin")
	der := adminAPReq(t, tkt, session, nil)
	ap, err := wire.UnmarshalAPReq(der)
	if err != nil {
		t.Fatal(err)
	}
	ap.Options |= wire.APOptUseSessionKey
	out, err := wire.MarshalAPReq(ap)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func garbageAPReq(t *testing.T, k *KDC) []byte {
	return []byte{0x01, 0x02, 0x03}
}

// A ticket whose lifetime has run out is refused, which upstream's
// krb5_rd_req does *not* do: it checks the authenticator's skew and
// the INVALID flag (rd_req_dec.c:631-637) and nothing about the
// validity interval, leaving the GSS layer to store the end time as a
// context lifetime (accept_sec_context.c:346) and the application to
// notice. A surface that provisions principals is not the place to
// leave that to a caller.
func TestAcceptAPReqRefusesAnExpiredTicket(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, "admin")
	der := adminAPReq(t, tkt, session, nil)

	// Move the KDC's clock past the ticket's end, and the
	// client's with it -- an authenticator left behind would be
	// refused for skew before the ticket was ever looked at,
	// which is how the first draft of this test failed.
	later := fixedNow.Add(24 * time.Hour)
	k.Now = func() time.Time { return later }
	_, kerr := k.AcceptAPReq(der)
	if kerr == nil {
		t.Fatal("an expired ticket was accepted")
	}
	if kerr.ErrorCode != wire.ErrCodeTktExpired {
		t.Errorf("code %d, want TKT_EXPIRED", kerr.ErrorCode)
	}
}
