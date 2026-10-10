package kdc

import (
	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/pac"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
	"testing"
)

// serviceTGT gets the *service* its own TGT, which is what an
// S4U2Self request is presented with: a service holding a ticket for
// itself asking for a second ticket to itself, naming somebody else.
func serviceTGT(
	t *testing.T,
	k *KDC,
) (wire.Ticket, []byte) {
	t.Helper()
	rep, kerr := as(t, k, asRequest(serviceName))
	if kerr != nil {
		t.Fatalf("the service could not log in: %v", kerr)
	}
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, serviceName, "servicepassword", e)
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the service's reply: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Ticket, enc.Key.KeyValue
}

// s4uSelfRequest builds an S4U2Self TGS-REQ: the service asks for a
// ticket to itself, naming subject as the client.
//
// The padata is appended *after* the AP-REQ is signed, which is safe
// and worth saying why: the authenticator's checksum is over the
// request **body**, and padata is not in the body.
func s4uSelfRequest(
	t *testing.T,
	tgt wire.Ticket,
	session []byte,
	subject []string,
	mutate func(*wire.S4UUserID),
) ([]byte, wire.TGSReq) {
	t.Helper()
	id := wire.S4UUserID{
		Nonce: 0x5A,
		UserName: &wire.PrincipalName{
			Type: wire.NTPrincipal, Components: subject,
		},
		UserRealm: testRealm,
	}
	if mutate != nil {
		mutate(&id)
	}
	return s4uRequestWith(t, tgt, session,
		x509UserPAData(t, session, id))
}

// x509UserPAData builds a PA-S4U-X509-USER with a correct checksum
// over the user-id field, at key usage 26.
func x509UserPAData(
	t *testing.T,
	session []byte,
	id wire.S4UUserID,
) wire.PAData {
	t.Helper()
	der, err := wire.MarshalS4UUserID(id)
	if err != nil {
		t.Fatal(err)
	}
	p := aes256(t)
	sum, err := p.Checksum(session, der,
		crypto.UsageS4UX509UserRequest)
	if err != nil {
		t.Fatal(err)
	}
	out, err := wire.MarshalPAS4UX509User(wire.PAS4UX509User{
		UserID: id,
		Cksum: wire.Checksum{
			Type:     int32(p.RequiredCksum),
			Checksum: sum,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{
		Type: wire.PATypeS4UX509User, Value: out,
	}
}

// s4uRequestWith attaches arbitrary S4U padata to a request for the
// service's own name.
func s4uRequestWith(
	t *testing.T,
	tgt wire.Ticket,
	session []byte,
	pa ...wire.PAData,
) ([]byte, wire.TGSReq) {
	t.Helper()
	_, req := tgsRequestAs(t, tgt, session, serviceName, nil,
		func(a *wire.Authenticator) {
			a.CName = wire.PrincipalName{
				Type:       wire.NTPrincipal,
				Components: serviceName,
			}
		})
	req.PAData = append(req.PAData, pa...)
	out, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return out, req
}

// The whole of S4U2Self in one case: a service holding its own TGT
// asks for a ticket to itself naming a user it never spoke to, and
// gets one whose client is that user.
//
// **Asserting the cname is the point.** A reply that named the wrong
// client would be a perfectly valid ticket for the wrong person, and
// nothing else about it would look wrong -- which is why the plan's
// verification table names this specifically.
func TestS4USelfIssuesATicketForTheSubject(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.String(); got != "user" {
		t.Errorf("the reply names %q, want \"user\"", got)
	}
	tkt := openServiceTicket(t, rep)
	if got := tkt.CName.String(); got != "user" {
		t.Errorf("the ticket names %q, want \"user\"", got)
	}
	if tkt.CRealm != testRealm {
		t.Errorf("the ticket's crealm is %q", tkt.CRealm)
	}
	// And the authtime is the *service's*, carried from its own
	// TGT, because the subject never authenticated at all.
	if tkt.AuthTime.IsZero() {
		t.Error("the ticket carries no authtime")
	}
}

// The PAC in the issued ticket names the **subject**, not the
// impersonator -- which is the one thing a copied CLIENT_INFO would
// get wrong, because the presented ticket's PAC names the service.
//
// A PAC that disagreed with the ticket around it would be worse than
// no PAC: a service reading it would see the wrong user while the
// ticket said the right one.
func TestS4USelfRebuildsThePACClientInfo(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	srv := wire.PrincipalName{Components: serviceName}
	key := keyOf(t, serviceName, "servicepassword",
		crypto.EncType(rep.Ticket.EncPart.EType))
	tgtKey := keyOf(t, []string{tgsName, testRealm},
		"tgtpassword", crypto.AES256CTSHMACSHA196)
	p, err := pac.VerifyTicket(&tkt, srv, key, tgtKey)
	if err != nil {
		t.Fatalf("the PAC does not verify: %v", err)
	}
	assertClientInfo(t, p, "user", tkt.AuthTime)
}

// The reply echoes the request: the same nonce, the same subject, and
// a checksum of the client's own checksum type.
func TestS4USelfReplyEchoesTheRequest(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	d := findPAData(rep.PAData, wire.PATypeS4UX509User)
	if d == nil {
		t.Fatalf("no S4U padata in the reply: %v", rep.PAData)
	}
	got, err := wire.UnmarshalPAS4UX509User(d.Value)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID.Nonce != req.Body.Nonce {
		t.Errorf("the reply's nonce is %d, want %d",
			got.UserID.Nonce, req.Body.Nonce)
	}
	if got.UserID.UserName == nil ||
		got.UserID.UserName.String() != "user" {
		t.Errorf("the reply names %v", got.UserID.UserName)
	}
	assertReplyChecksum(t, session, got,
		crypto.UsageS4UX509UserRequest)
}

// assertReplyChecksum recomputes the reply's checksum at the usage it
// should have been made with.
func assertReplyChecksum(
	t *testing.T,
	key []byte,
	rep wire.PAS4UX509User,
	usage crypto.Usage,
) {
	t.Helper()
	der, err := wire.MarshalS4UUserID(rep.UserID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := crypto.ProfileForCksum(
		crypto.CksumType(rep.Cksum.Type))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyChecksum(key, der, rep.Cksum.Checksum,
		usage); err != nil {
		t.Errorf("the reply's checksum at usage %d: %v",
			usage, err)
	}
}

// S4U-OPTS-USE-REPLY-KEY-USAGE moves the reply's checksum to usage
// **27**, and the option is echoed back so the client knows which to
// verify at (kdc_util.c:1470-1482).
//
// It is the only bit of the options field that survives: the echo
// masks everything else away, the same way PA-PAC-OPTIONS is masked.
func TestS4USelfReplyKeyUsageOption(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, func(id *wire.S4UUserID) {
			id.Options = wire.S4UOptUseReplyKeyUsage |
				wire.S4UOptCheckLogonHours
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	d := findPAData(rep.PAData, wire.PATypeS4UX509User)
	if d == nil {
		t.Fatal("no S4U padata in the reply")
	}
	got, err := wire.UnmarshalPAS4UX509User(d.Value)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID.Options != wire.S4UOptUseReplyKeyUsage {
		t.Errorf("echoed options %#08x, want %#08x",
			uint32(got.UserID.Options),
			uint32(wire.S4UOptUseReplyKeyUsage))
	}
	assertReplyChecksum(t, session, got,
		crypto.UsageS4UX509UserReply)
}

// The legacy PA-FOR-USER form works and gets **no reply padata at
// all**, which upstream arranges by testing for the newer padata
// specifically before building a reply (do_tgs_req.c:1064-1067).
//
// Its checksum is also a different shape entirely: not over DER, and
// with a little-endian name type -- see wire.S4UForUserChecksumData.
func TestS4USelfAcceptsTheLegacyForUserForm(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uRequestWith(t, tgt, session,
		forUserPAData(t, session, []string{"user"}, nil))
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	if got := tkt.CName.String(); got != "user" {
		t.Errorf("the ticket names %q", got)
	}
	if findPAData(rep.PAData,
		wire.PATypeS4UX509User) != nil {
		t.Error("a legacy request got reply padata")
	}
}

// forUserPAData builds a PA-FOR-USER with a correct checksum.
func forUserPAData(
	t *testing.T,
	session []byte,
	subject []string,
	mutate func(*wire.PAForUser),
) wire.PAData {
	t.Helper()
	fu := wire.PAForUser{
		UserName: wire.PrincipalName{
			Type: wire.NTPrincipal, Components: subject,
		},
		UserRealm:   testRealm,
		AuthPackage: "Kerberos",
	}
	if mutate != nil {
		mutate(&fu)
	}
	p := aes256(t)
	sum, err := p.Checksum(session,
		wire.S4UForUserChecksumData(fu),
		pac.UsageAppDataCksum)
	if err != nil {
		t.Fatal(err)
	}
	fu.Cksum = wire.Checksum{
		Type:     int32(p.RequiredCksum),
		Checksum: sum,
	}
	der, err := wire.MarshalPAForUser(fu)
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{
		Type: wire.PATypeForUser, Value: der,
	}
}
