package kdc

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// refuseS4U runs a request and insists on a particular error code.
func refuseS4U(
	t *testing.T,
	k *KDC,
	msg []byte,
	req wire.TGSReq,
	want int32,
) {
	t.Helper()
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("the request was accepted")
	}
	if kerr.ErrorCode != want {
		t.Errorf("code %d, want %d (%s)",
			kerr.ErrorCode, want, kerr.EText)
	}
}

// **The checksum is the only thing between a service and a ticket
// naming anybody**, so a wrong one has to be refused -- and this is
// the single most important refusal in the step.
//
// It is keyed with the TGT's session key, which only the service and
// the KDC hold, so what the checksum proves is that the service
// really is asking: a third party who saw the padata could not have
// produced it.
func TestS4USelfRefusesABadChecksum(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	_, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	// Flip a bit of the checksum, which lives at the end of the
	// padata value.
	d := findPAData(req.PAData, wire.PATypeS4UX509User)
	d.Value[len(d.Value)-1] ^= 1
	out, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	refuseS4U(t, k, out, req, wire.ErrCodeModified)
}

// The same for the legacy form, whose checksum is a different
// construction over different bytes at a different key usage -- so
// one test cannot stand for both.
func TestS4USelfRefusesABadForUserChecksum(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	pa := forUserPAData(t, session, []string{"user"}, nil)
	pa.Value[len(pa.Value)-1] ^= 1
	msg, req := s4uRequestWith(t, tgt, session, pa)
	refuseS4U(t, k, msg, req, wire.ErrCodeModified)
}

// A nonce that does not match the request's is refused, which is what
// binds the padata to the request it arrived in
// (verify_s4u_x509_user_checksum, kdc_util.c:1360-1361).
//
// Without it a recorded padata element, checksum and all, could be
// replayed into a different request.
func TestS4USelfRefusesAWrongNonce(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, func(id *wire.S4UUserID) {
			id.Nonce = 0x5A + 1
		})
	refuseS4U(t, k, msg, req, wire.ErrCodeModified)
}

// A request must be **for self**: the server named has to be the
// client of the ticket presented (tgs_policy.c:271-276).
//
// Otherwise a service holding its own TGT could get a ticket to any
// service, naming any user -- which is unconstrained delegation and
// is the thing S4U exists to avoid.
func TestS4USelfRefusesARequestForSomebodyElse(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	addPeer(t, k, 0)
	tgt, session := serviceTGT(t, k)
	id := wire.S4UUserID{
		Nonce: 0x5A,
		UserName: &wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{"user"},
		},
		UserRealm: testRealm,
	}
	_, req := tgsRequestAs(t, tgt, session, peerName, nil,
		func(a *wire.Authenticator) {
			a.CName = wire.PrincipalName{
				Type:       wire.NTPrincipal,
				Components: serviceName,
			}
		})
	req.PAData = append(req.PAData,
		x509UserPAData(t, session, id))
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	refuseS4U(t, k, msg, req, wire.ErrCodeBadMatch)
}

// An S4U2Self request stands in for an AS request, so the options
// only a TGS request may carry are refused (tgs_policy.c:278-282).
//
// **This gate is not reachable end to end yet**, and the reason is
// worth writing down rather than leaving the test looking redundant.
// Every option in AS_INVALID_OPTIONS is caught by an earlier check
// for a TGS request: the four NON_TGT_OPTION bits fail
// check_tgs_nontgt, because an S4U2Self request's presented ticket is
// a TGT and the server it names is not; enc-tkt-in-skey needs a
// second ticket to get as far as the policy at all; and
// cname-in-addl-tkt is refused outright here as unimplemented
// S4U2Proxy. E6 makes the last of those reachable.
//
// So the branch is exercised directly. It stays in the port because
// it is upstream's, and because an E6 that implemented
// cname-in-addl-tkt without it would silently accept an S4U2Self
// request carrying it.
func TestS4USelfRefusesASInvalidOptions(t *testing.T) {
	k := testKDC(t)
	s := &tgsState{
		// referral short-circuits the for-self check, which
		// needs a database lookup this case has no use for.
		referral:    true,
		headerRealm: testRealm,
		s4u:         &wire.PAS4UX509User{},
	}
	s.req.Body.Options = wire.OptCNameInAddlTkt
	code, status := k.s4uShape(s)
	if code != wire.ErrCodeBadOption {
		t.Errorf("code %d (%s), want %d", code, status,
			wire.ErrCodeBadOption)
	}
	// And with no invalid option the same state passes the gate,
	// so the case above is not passing for another reason. The
	// realm has to change with it: a referral from a *local* TGT
	// is combination-check territory and refused on its own
	// account, where a cross TGT, a local user and a referral is
	// legal case (2).
	s.req.Body.Options = wire.OptForwardable
	s.headerRealm = "ELSEWHERE.TEST"
	s.s4uClient = &store.Principal{}
	if code, status := k.s4uShape(s); code != 0 {
		t.Errorf("a valid request was refused: %d (%s)",
			code, status)
	}
}

// An unknown subject in this realm is KDC_ERR_C_PRINCIPAL_UNKNOWN
// (kdc_util.c:1604-1607), which tells the service that the user does
// not exist rather than that the request was wrong.
func TestS4USelfRefusesAnUnknownSubject(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"nobody"}, nil)
	refuseS4U(t, k, msg, req,
		wire.ErrCodeCPrincipalUnknown)
}

// A subject in another realm, asked for with a **local** TGT, is
// KDC_ERR_POLICY and upstream annotates the code *"match Windows
// error"* (tgs_policy.c:309-316).
//
// The service should be asking that realm's KDC and following
// referrals back, which is why this is a policy refusal rather than
// an unknown principal: the principal may well exist, elsewhere.
func TestS4USelfRefusesAForeignSubject(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, func(id *wire.S4UUserID) {
			id.UserRealm = "ELSEWHERE.TEST"
		})
	refuseS4U(t, k, msg, req, wire.ErrCodePolicy)
}

// **The header ticket's PAC must be present**, and its absence is
// KDC_ERR_TGT_REVOKED (tgs_policy.c:328-332).
//
// This is the corollary the plan recorded as blocking the whole step:
// a TGT obtained with PA-PAC-REQUEST(false) can never be used for
// S4U2Self, because there is then nothing that says who the
// impersonator is.
func TestS4USelfNeedsAPACInTheHeaderTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	noPAC, err := wire.MarshalPAPACRequest(false)
	if err != nil {
		t.Fatal(err)
	}
	req := asRequest(serviceName)
	req.PAData = append(req.PAData, wire.PAData{
		Type: wire.PAPACRequest, Value: noPAC,
	})
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("the service could not log in: %v", kerr)
	}
	session := serviceReplyKey(t, rep)
	msg, treq := s4uSelfRequest(t, rep.Ticket, session,
		[]string{"user"}, nil)
	refuseS4U(t, k, msg, treq, wire.ErrCodeTGTRevoked)
}

// serviceReplyKey opens an AS reply addressed to the service.
func serviceReplyKey(
	t *testing.T,
	rep *wire.ASRep,
) []byte {
	t.Helper()
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, serviceName, "servicepassword", e)
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatal(err)
	}
	return enc.Key.KeyValue
}

// **An expired password does not stop an impersonation**, and nor
// does REQUIRES_PWCHANGE: both are cleared on the subject's entry
// before policy sees it, "as Windows does, since S4U2Self is not
// password authentication" (kdc_util.c:1611-1615).
//
// It reads as a hole and is not. The subject's password is not
// involved in this exchange at all, so a rule about it has nothing to
// say -- and refusing would mean a user whose password expired could
// not be impersonated by a service they had already authenticated to.
func TestS4USelfIgnoresTheSubjectsPasswordExpiry(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	expirePassword(t, k, []string{"user"})
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.String(); got != "user" {
		t.Errorf("the reply names %q", got)
	}
}

// expirePassword sets a principal's password expiry in the past and
// flags it as needing a change, which an ordinary AS request would
// refuse on.
func expirePassword(
	t *testing.T,
	k *KDC,
	components []string,
) {
	t.Helper()
	name := store.UnparseName(testRealm, components)
	p, err := k.Store.Lookup(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	p.PWExpiration = fixedNow.Add(-time.Hour)
	p.Attributes |= store.AttrRequiresPWChange
	err = k.Store.Save(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
}
