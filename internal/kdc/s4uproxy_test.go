package kdc

import (
	"context"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/ndr"
	"github.com/FatmanUK/diamond_krb/internal/pac"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// targetName is the third service in a constrained delegation: the
// one the impersonator wants to reach.
var targetName = []string{"host", "target.example.org"}

const targetPassword = "targetpassword"

// addTarget provisions it.
func addTarget(t *testing.T, k *KDC) {
	t.Helper()
	mkey, err := store.DeriveMasterKey(testRealm,
		testMasterPW, store.DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	addPrincipal(t, k.Store, mkey, targetName,
		targetPassword, 0)
}

// evidenceTicket is the forwardable service ticket a *user* obtains
// to the service, which is what the service then presents as the
// evidence that the user spoke to it.
//
// Nothing about getting it is special: it is an ordinary TGS exchange
// with KDC_OPT_FORWARDABLE, and the forwardable flag is the user's
// consent to being delegated.
func evidenceTicket(t *testing.T, k *KDC) wire.Ticket {
	t.Helper()
	tgt, session := getTGT(t, k)
	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptForwardable
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("the user could not get a ticket: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	if !tkt.Flags.Has(wire.FlagForwardable) {
		t.Fatal("the evidence ticket is not forwardable")
	}
	return rep.Ticket
}

// proxyRequest builds the constrained-delegation request: the
// service's own TGT as the header ticket, the user's ticket to it as
// the evidence, and a third service as the target.
func proxyRequest(
	t *testing.T,
	tgt wire.Ticket,
	session []byte,
	evidence wire.Ticket,
	target []string,
	pa ...wire.PAData,
) ([]byte, wire.TGSReq) {
	t.Helper()
	_, req := tgsRequestAs(t, tgt, session, target,
		func(b *wire.KDCReqBody) {
			b.Options |= wire.OptCNameInAddlTkt
			if err := b.SetTickets(
				[]wire.Ticket{evidence}); err != nil {
				t.Fatal(err)
			}
		},
		func(a *wire.Authenticator) {
			a.CName = wire.PrincipalName{
				Type:       wire.NTPrincipal,
				Components: serviceName,
			}
		})
	req.PAData = append(req.PAData, pa...)
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg, req
}

// grantDelegation records a traditional grant, which is the thing
// upstream needs LDAP or a test KDB module for.
func grantDelegation(
	t *testing.T,
	k *KDC,
	impersonator, target []string,
) {
	t.Helper()
	err := k.Store.GrantDelegation(context.Background(),
		store.UnparseName(testRealm, impersonator),
		store.UnparseName(testRealm, target))
	if err != nil {
		t.Fatal(err)
	}
}

// The whole of S4U2Proxy in one case: the service presents a user's
// forwardable ticket to itself and gets a ticket to a third service
// naming that user.
//
// **The grant is what makes it work**, and it is the thing upstream
// cannot express with db2 at all: its own test suite needs a test KDB
// module reading JSON out of krb5.conf to reach this case
// (t_s4u.py:32-34). Here it is two rows in a table.
func TestS4UProxyIssuesATicketForTheUser(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	addTarget(t, k)
	evidence := evidenceTicket(t, k)
	grantDelegation(t, k, serviceName, targetName)

	tgt, session := serviceTGT(t, k)
	msg, req := proxyRequest(t, tgt, session, evidence,
		targetName)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.String(); got != "user" {
		t.Errorf("the reply names %q, want \"user\"", got)
	}
	tkt := decodeTicketWith(t, rep.Ticket, targetPassword,
		targetName)
	if got := tkt.CName.String(); got != "user" {
		t.Errorf("the ticket names %q, want \"user\"", got)
	}
}

// Without a grant the request is refused, and the error distinguishes
// "the realm says no" from "the realm has no rule" -- both
// KDC_ERR_BADOPTION on the wire, different in the status, which is
// where an operator looks (tgs_policy.c:567-570).
func TestS4UProxyNeedsAGrant(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	addTarget(t, k)
	evidence := evidenceTicket(t, k)

	tgt, session := serviceTGT(t, k)
	msg, req := proxyRequest(t, tgt, session, evidence,
		targetName)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("an ungranted delegation was allowed")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code %d, want BADOPTION", kerr.ErrorCode)
	}
	// **A table turns "no grant" into a denial**, where upstream
	// against db2 cannot answer at all. The status says which:
	// NOT_ALLOWED_TO_DELEGATE means a relation was consulted and
	// said no, where UNSUPPORTED_S4U2PROXY_REQUEST means none was
	// consulted -- which here happens only for a cross-realm
	// requester that did not announce RBCD, because the
	// traditional relation is skipped for one
	// (tgs_policy.c:556-566).
	if kerr.EText != "NOT_ALLOWED_TO_DELEGATE" {
		t.Errorf("status %q", kerr.EText)
	}
	// And a grant to somewhere *else* is still a denial, which is
	// what says the target is compared and not merely the
	// impersonator.
	grantDelegation(t, k, serviceName, peerName)
	_, kerr = k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("a grant elsewhere authorised this")
	}
	if kerr.EText != "NOT_ALLOWED_TO_DELEGATE" {
		t.Errorf("status %q", kerr.EText)
	}
}

// The resource-based relation authorises the same delegation from the
// other direction, and **only when the client says it understands
// RBCD** (check_s4u2proxy_policy, tgs_policy.c:532-555).
//
// The inversion is administrative rather than technical: a
// traditional grant is made by whoever runs the impersonator, so a
// front end's operator decides which back ends it may reach; a
// resource-based grant is made by whoever runs the resource, so the
// back end decides who may reach it. The second is the one a
// resource's owner can audit.
func TestS4UProxyHonoursRBCD(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	addTarget(t, k)
	evidence := evidenceTicket(t, k)
	err := k.Store.GrantRBCD(context.Background(),
		store.UnparseName(testRealm, targetName),
		store.UnparseName(testRealm, serviceName))
	if err != nil {
		t.Fatal(err)
	}

	tgt, session := serviceTGT(t, k)
	// Without the announcement the resource-based relation is
	// never consulted, so the request is refused.
	msg, req := proxyRequest(t, tgt, session, evidence,
		targetName)
	if _, kerr := k.TGS(msg, req); kerr == nil {
		t.Error("RBCD applied without the client asking")
	}
	// With it, the same request succeeds.
	msg, req = proxyRequest(t, tgt, session, evidence,
		targetName, pacOptions(t, wire.PACOptRBCD)...)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.String(); got != "user" {
		t.Errorf("the ticket names %q", got)
	}
}

// The issued ticket's PAC records the delegation chain, which is the
// one place NDR is unavoidable (update_delegation_info,
// kdc_authdata.c:382-439).
//
// Two names, with opposite realm treatment: the target without its
// realm and the transited service with it. That asymmetry is
// upstream's and is visible in the Active Directory buffers
// internal/ndr is anchored against.
func TestS4UProxyRecordsTheDelegationChain(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	addTarget(t, k)
	evidence := evidenceTicket(t, k)
	grantDelegation(t, k, serviceName, targetName)

	tgt, session := serviceTGT(t, k)
	msg, req := proxyRequest(t, tgt, session, evidence,
		targetName)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := decodeTicketWith(t, rep.Ticket, targetPassword,
		targetName)
	srv := wire.PrincipalName{Components: targetName}
	key := keyOf(t, targetName, targetPassword,
		crypto.EncType(rep.Ticket.EncPart.EType))
	tgtKey := keyOf(t, []string{tgsName, testRealm},
		"tgtpassword", crypto.AES256CTSHMACSHA196)
	p, err := pac.VerifyTicket(&tkt, srv, key, tgtKey)
	if err != nil {
		t.Fatalf("the PAC does not verify: %v", err)
	}
	assertDelegationChain(t, p)
	// And the PAC names the *user*, not the service that asked.
	assertClientInfo(t, p, "user", tkt.AuthTime)
}

// assertDelegationChain reads the PAC's delegation info and checks
// the one hop this request added.
func assertDelegationChain(t *testing.T, p *pac.PAC) {
	t.Helper()
	raw, err := p.Get(pac.TypeDelegationInfo)
	if err != nil {
		t.Fatalf("no delegation info in the PAC: %v", err)
	}
	di, err := ndr.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantTarget := "host/target.example.org"
	if di.ProxyTarget != wantTarget {
		t.Errorf("the target is %q, want %q",
			di.ProxyTarget, wantTarget)
	}
	want := "host/service.example.org@" + testRealm
	if len(di.TransitedServices) != 1 ||
		di.TransitedServices[0] != want {
		t.Errorf("the chain is %v, want [%q]",
			di.TransitedServices, want)
	}
}
