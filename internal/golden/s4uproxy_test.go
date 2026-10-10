package golden

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// **A stock kvno performs a constrained delegation against this
// KDC**, which is the anchor for the step and the last one in the
// plan.
//
// `kvno -P -I user target' does two exchanges in a row: an S4U2Self
// for the user to the service itself, and then an S4U2Proxy
// presenting that ticket as the evidence and asking for a ticket to
// `target'. So this one command exercises E1, E2, E5 and E6 together,
// and the client -- not the test -- opens what comes back.
//
// Three things have to be in place for it, and each is a finding in
// its own right. The service needs a keytab, which `kdiamond ktadd'
// writes. It needs **+ok_to_auth_as_delegate**, because a service
// with a delegation grant otherwise stops getting forwardable
// S4U2Self tickets ([MS-SFU] 3.2.5.1.2) and S4U2Proxy refuses a
// non-forwardable evidence ticket. And the realm needs the grant
// itself, which is the thing a flat-file KDB cannot express at all.
func TestStockKvnoDelegatesAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "s4uproxy", true)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_s4uproxy")
	svc := strings.Join(ServiceName, "/")
	target := strings.Join(DelegationTarget, "/")

	grant(t, bin, url, svc, target)
	loginAsService(t, ctx, o, bin, url, env, "proxykeytab")
	out := delegateWithKvno(t, ctx, o, env, target)
	// kvno prints a line for each of the two tickets it got, and
	// the target's is the one that only a delegation produces.
	if !strings.Contains(out, target) {
		t.Errorf("kvno did not report the target:\n%s", out)
	}
}

// loginAsService writes the service a keytab and logs it in with a
// stock kinit.
//
// **-f**, because an S4U2Self ticket can only be forwardable if the
// TGT it was derived from was, and S4U2Proxy refuses a
// non-forwardable evidence ticket. Upstream's own S4U test does the
// same (t_s4u.py:21-22).
func loginAsService(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	bin, url string,
	env []string,
	tag string,
) {
	t.Helper()
	svc := strings.Join(ServiceName, "/")
	kt := putKeytab(t, ctx, o, bin, url, tag, svc)
	out, err := o.ExecEnv(ctx, env, "", "kinit", "-f", "-k",
		"-t", kt, svc+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -f -k failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)
}

// delegateWithKvno runs the delegation and insists it succeeded.
func delegateWithKvno(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	env []string,
	target string,
) string {
	t.Helper()
	out, err := o.ExecEnv(ctx, env, "", "kvno", "-P", "-I",
		UserName, target+"@"+Realm)
	if err != nil {
		t.Fatalf("kvno -P -I failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)
	if strings.Contains(out, "constrained delegation failed") {
		t.Fatalf("the delegation was refused:\n%s", out)
	}
	return out
}

// The same thing authorised by the **resource-based** relation
// instead, which is the half upstream needs a directory server for.
//
// A stock client announces PA-PAC-OPTIONS RBCD on every S4U2Proxy
// request unconditionally (add_rbcd_padata,
// lib/krb5/krb/s4u_creds.c:1013), so nothing extra is asked of it --
// the realm simply authorises the delegation from the other
// direction, and the client cannot tell which relation said yes.
//
// Note what is *not* needed here: +ok_to_auth_as_delegate. That flag
// exists to restore the forwardable S4U2Self ticket a *traditional*
// grant takes away, and an RBCD-only grant takes nothing away -- so a
// realm that uses resource-based delegation never meets that
// interaction at all. It is a real argument for preferring it, and it
// falls out of the code rather than being asserted.
func TestStockKvnoRBCDAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "s4urbcd", true)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_s4urbcd")
	svc := strings.Join(ServiceName, "/")
	target := strings.Join(DelegationTarget, "/")

	mustRun(t, bin, url, "rbcd", target, svc)
	loginAsService(t, ctx, o, bin, url, env, "rbcdkeytab")
	delegateWithKvno(t, ctx, o, env, target)
}

// And without the grant the same command fails, which is what says
// the grant is what authorised it rather than something else.
func TestStockKvnoDelegationNeedsTheGrant(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "s4unogrant", true)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_s4unogrant")
	svc := strings.Join(ServiceName, "/")
	target := strings.Join(DelegationTarget, "/")

	kt := putKeytab(t, ctx, o, bin, url, "nograntkeytab",
		svc)
	out, err := o.ExecEnv(ctx, env, "", "kinit", "-f", "-k",
		"-t", kt, svc+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -f -k failed: %v\n%s", err, out)
	}
	out, _ = o.ExecEnv(ctx, env, "", "kvno", "-P", "-I",
		UserName, target+"@"+Realm)
	if !strings.Contains(out,
		"constrained delegation failed") {
		t.Errorf("an ungranted delegation succeeded:\n%s",
			out)
	}
}

// grant records the delegation with `kdiamond delegate', as an
// operator would -- so the subcommand is exercised as a *binary* with
// arguments, which is how every other administrative verb in this
// harness is checked.
func grant(
	t *testing.T,
	bin, url, impersonator, target string,
) {
	t.Helper()
	mustRun(t, bin, url, "delegate", impersonator, target)
}

// The refusal, compared against the C.
//
// There is no oracle for a *successful* S4U2Proxy -- db2 has no
// check_allowed_to_delegate method, so upstream's own suite needs a
// test KDB module to reach those cases (t_s4u.py:32-34) -- so what is
// compared is a refusal both sides reach **for the same reason**,
// which took some arranging.
//
// It cannot be the policy refusal: this realm would say "no grant"
// and that realm "I cannot have one", and the target principal does
// not exist there at all, so the oracle would answer
// S_PRINCIPAL_UNKNOWN from the server lookup before the delegation
// was considered. What both reach identically is
// EVIDENCE_TKT_NOT_FORWARDABLE: the evidence ticket here is an
// ordinary service ticket the user obtained *without* asking for a
// forwardable one, and a non-forwardable evidence ticket is refused
// before any policy runs (tgs_policy.c:433-436).
//
// So the target is the service itself, which both realms have, and
// the case compares the one S4U2Proxy refusal a stock realm can give.
// The user's consent is the point of that check: a client that does
// not want to be delegated asks for a non-forwardable ticket and
// cannot be.
func TestS4UProxyRefusalMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := serviceTGTFromTheC(t, ctx, o)
	till := time.Now().UTC().Add(2 * time.Hour).Truncate(
		time.Second)
	evidence := plainServiceTicket(t, ctx, o, till)
	msg := proxyRequest(t, g, till, evidence, ServiceName)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	d := diamond(t, "kd_golden_s4uproxy_refusal",
		func() time.Time { return time.Now().UTC() })
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	c := refusalCode(t, "oracle", cRaw)
	gd := refusalCode(t, "diamond", goRaw)
	if c != gd {
		t.Errorf("codes differ: oracle %d, diamond %d", c, gd)
	}
	if c != wire.ErrCodeBadOption {
		t.Errorf("code %d, want BADOPTION", c)
	}
}

// plainServiceTicket is an ordinary service ticket the *user* gets to
// the service, without asking for a forwardable one -- so it is not
// forwardable and cannot be used as evidence.
func plainServiceTicket(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	till time.Time,
) wire.Ticket {
	t.Helper()
	g, _ := getTGTFromTheC(t, ctx, o)
	raw, err := o.SendRaw(ctx,
		plainTGSRequest(t, g, till))
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	x := openTGS(t, raw, g)
	if x.Tkt.Flags.Has(wire.FlagForwardable) {
		t.Fatal("the evidence ticket is forwardable, so " +
			"this case would compare something else")
	}
	return x.Rep.Ticket
}

// proxyRequest builds the constrained-delegation request: the
// service's TGT as the header ticket and the evidence as the second.
func proxyRequest(
	t *testing.T,
	g tgt,
	till time.Time,
	evidence wire.Ticket,
	target []string,
) []byte {
	t.Helper()
	body := proxyBody(till, target)
	if err := body.SetTickets(
		[]wire.Ticket{evidence}); err != nil {
		t.Fatal(err)
	}
	req := wire.TGSReq{Body: body}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = []wire.PAData{serviceAPReq(t, g, bodyDER)}
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// plainTGSRequest is the harness's ordinary TGS request with
// KDC_OPT_FORWARDABLE left out, which the standard one sets.
//
// It exists for one case and says so: a *non*-forwardable service
// ticket, which is what a client that does not consent to being
// delegated holds.
func plainTGSRequest(
	t *testing.T,
	g tgt,
	till time.Time,
) []byte {
	t.Helper()
	body := wire.KDCReqBody{
		Options: wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  till,
		Nonce: 0x5C,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
	req := wire.TGSReq{Body: body}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = []wire.PAData{tgsAPReq(t, g, bodyDER)}
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// proxyBody is the request body, less the second ticket.
func proxyBody(
	till time.Time,
	target []string,
) wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptForwardable |
			wire.OptCNameInAddlTkt,
		Realm: Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: target,
		},
		Till:  till,
		Nonce: 0x5B,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
}
