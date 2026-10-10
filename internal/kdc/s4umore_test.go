package kdc

import (
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// **An S4U2Self ticket carries no authentication indicator**, and the
// absence is the assertion (t_authdata.py:239-245 checks for it from
// the outside by requiring '97:' not to appear).
//
// The reason is the whole point of S4U2Self: the subject never
// authenticated here. An indicator says *how* its holder
// authenticated, so a ticket claiming one the subject did not earn
// would be worse than one claiming none -- and a service with
// require_auth would then be satisfied by an impersonation.
func TestS4USelfCarriesNoAuthIndicator(t *testing.T) {
	k := testKDC(t)
	k.SPAKEIndicators = []string{"strong"}
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	ad, err := wire.AuthDataOf(tkt.AuthorizationData)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range withoutPAC(t, ad) {
		if d.Type == wire.ADCAMMAC ||
			d.Type == wire.ADIfRelevant {
			t.Errorf("the ticket carries type %d", d.Type)
		}
	}
}

// The four legal combinations, and the four refusals that are their
// complement (tgs_policy.c:285-324).
//
// They are a table because the C is a table, and because the shape is
// unmemorable: which of local-user, cross-TGT and issuing-a-referral
// may be true together is decided by where the impersonation has to
// be judged, not by anything visible in the request.
func TestTheFourS4USelfCombinations(t *testing.T) {
	for _, c := range s4uCombinations() {
		got, status := s4uCombination(c.local, c.cross,
			c.referral, c.req)
		if got != c.want {
			t.Errorf("%s: %d (%s), want %d",
				c.why, got, status, c.want)
		}
	}
}

type s4uCombinationCase struct {
	why                    string
	local, cross, referral bool
	req                    *wire.PAS4UX509User
	want                   int32
}

// s4uCombinations is the table itself: upstream's four legal shapes
// and the four refusals that are their complement.
func s4uCombinations() []s4uCombinationCase {
	named := &wire.PAS4UX509User{
		UserID: wire.S4UUserID{
			UserName: &wire.PrincipalName{
				Components: []string{"user"},
			},
		},
	}
	certOnly := &wire.PAS4UX509User{}
	return []s4uCombinationCase{
		{"(1) local TGT, local user, local server",
			true, false, false, named, 0},
		{"(2) cross TGT, local user, a referral",
			true, true, true, named, 0},
		{"(3) cross TGT, foreign user, a referral",
			false, true, true, named, 0},
		{"(4) cross TGT, foreign user, local server",
			false, true, false, named, 0},
		{"a referral from a local TGT",
			true, false, true, named,
			wire.ErrCodeSPrincipalUnknown},
		{"a cross TGT for a local user, no referral",
			true, true, false, named,
			wire.ErrCodeCPrincipalUnknown},
		{"a local TGT for a foreign user",
			false, false, false, named,
			wire.ErrCodePolicy},
		{"a foreign certificate-only request",
			false, true, false, certOnly,
			wire.ErrCodePolicy},
	}
}

// A server that asked for no authorization data gets a PAC anyway on
// an S4U2Self request, which upstream does "for consistency with
// Active Directory" because the service probably needs the PAC for a
// later S4U2Proxy (do_tgs_req.c:706-716).
//
// It is the one place a principal's own flag is overridden rather
// than honoured, so it is worth a case of its own.
func TestS4USelfOverridesNoAuthDataRequired(t *testing.T) {
	k := testKDC(t)
	addService(t, k, store.AttrNoAuthDataRequired)
	tgt, session := serviceTGT(t, k)
	msg, req := s4uSelfRequest(t, tgt, session,
		[]string{"user"}, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	tkt := openServiceTicket(t, rep)
	if len(tkt.AuthorizationData.FullBytes) == 0 {
		t.Error("the flag suppressed the S4U2Self PAC")
	}
	// And the ordinary request for the same service still gets
	// nothing, so the override is scoped to S4U2Self.
	omsg, oreq := tgsRequestAs(t, tgt, session, serviceName,
		nil, func(a *wire.Authenticator) {
			a.CName = wire.PrincipalName{
				Type:       wire.NTPrincipal,
				Components: serviceName,
			}
		})
	orep, kerr := k.TGS(omsg, oreq)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	otkt := openServiceTicket(t, orep)
	if len(otkt.AuthorizationData.FullBytes) != 0 {
		t.Errorf("an ordinary request got authdata: % x",
			otkt.AuthorizationData.FullBytes)
	}
}

// s4u2self_forwardable is currently a no-op and the test says so
// rather than leaving the reader to infer it (kdc_util.c:1623-1644).
//
// A server with +ok_to_auth_as_delegate keeps the flag outright. Any
// other server keeps it too **unless it has traditional S4U2Proxy
// delegation targets**, and that relation is E6's table. Upstream
// behaves identically against db2, where
// krb5_db_check_allowed_to_delegate answers KRB5_PLUGIN_OP_NOTSUPP
// and the flag is left alone -- so this agrees with the oracle rather
// than merely being unfinished.
func TestS4USelfForwardableIsStillANoOp(t *testing.T) {
	k := testKDC(t)
	s := &tgsState{s4u: &wire.PAS4UX509User{},
		server: &store.Principal{}}
	const in = wire.FlagForwardable | wire.FlagRenewable
	if got := k.s4uSelfForwardable(s, in); got != in {
		t.Errorf("flags %#08x, want %#08x",
			uint32(got), uint32(in))
	}
	s.server.Attributes = store.AttrOKToAuthAsDelegate
	if got := k.s4uSelfForwardable(s, in); got != in {
		t.Errorf("with ok-to-auth-as-delegate: %#08x",
			uint32(got))
	}
	// And an ordinary request is not touched at all.
	if got := k.s4uSelfForwardable(&tgsState{},
		in); got != in {
		t.Errorf("an ordinary request: %#08x", uint32(got))
	}
}

// A certificate-only request in *this* realm is refused rather than
// guessed, because the lookup it needs is a KDB method with no
// implementation outside upstream's own test module
// (krb5_db_get_s4u_x509_principal, kdc_util.c:1592-1600).
//
// Refusing with C_PRINCIPAL_UNKNOWN is the honest answer: this realm
// cannot say which principal a certificate belongs to.
func TestS4USelfRefusesACertificateOnlyRequest(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := serviceTGT(t, k)
	id := wire.S4UUserID{
		Nonce:       0x5A,
		UserRealm:   testRealm,
		SubjectCert: []byte("a fake certificate"),
	}
	msg, req := s4uRequestWith(t, tgt, session,
		x509UserPAData(t, session, id))
	refuseS4U(t, k, msg, req,
		wire.ErrCodeCPrincipalUnknown)
}

// The newer padata wins when a request carries both, which upstream
// arranges by looking for it first (kdc_util.c:1570-1586).
//
// A request carrying a good PA-S4U-X509-USER and a *broken*
// PA-FOR-USER therefore succeeds, which is the only way to tell the
// precedence from the outside.
func TestS4USelfPrefersTheNewerPadata(t *testing.T) {
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
	broken := forUserPAData(t, session, peerName, nil)
	broken.Value[len(broken.Value)-1] ^= 1
	msg, req := s4uRequestWith(t, tgt, session,
		x509UserPAData(t, session, id), broken)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if got := rep.CName.String(); got != "user" {
		t.Errorf("the reply names %q, want \"user\"", got)
	}
}
