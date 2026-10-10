package golden

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/pac"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// S4U2Self, compared against the C.
//
// The service gets its own TGT from the oracle and one S4U2Self
// TGS-REQ then goes to both KDCs. What is compared is the whole
// reply, field by field, as every other differential case is -- and
// the fields that matter here are the ones nothing else exercises:
// **the ticket's cname**, which is now a principal the requester
// never spoke to, and the PA-S4U-X509-USER echoed back in the
// cleartext padata.
//
// Asserting the cname separately on each side first is the standing
// rule applied to the thing that could go wrong most quietly: a reply
// naming the wrong client is a perfectly valid ticket for the wrong
// person, and nothing else about it looks wrong.
func TestS4USelfMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := serviceTGTFromTheC(t, ctx, o)
	till := time.Now().UTC().Add(2 * time.Hour).Truncate(
		time.Second)
	msg := s4uSelfRequest(t, g, till, nil)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openTGS(t, cRaw, g)

	d := diamond(t, "kd_golden_s4u",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openTGS(t, goRaw, g)

	assertImpersonates(t, "oracle", cx)
	assertImpersonates(t, "diamond", gx)
	assertSameS4UReply(t, g, cx, gx)
	reportDiffs(t, cx, gx)
}

// assertImpersonates checks the issued ticket names the subject and
// not the requester, on one side.
func assertImpersonates(
	t *testing.T,
	side string,
	x Exchange,
) {
	t.Helper()
	if got := x.Tkt.CName.String(); got != UserName {
		t.Errorf("%s: the ticket names %q, want %q",
			side, got, UserName)
	}
	if got := x.Rep.CName.String(); got != UserName {
		t.Errorf("%s: the reply names %q, want %q",
			side, got, UserName)
	}
	// And the PAC in it names the subject too, which is the half
	// a copied CLIENT_INFO would get wrong.
	assertPACNames(t, side, x, UserName)
}

// assertPACNames reads the issued ticket's PAC and checks its
// CLIENT_INFO.
func assertPACNames(
	t *testing.T,
	side string,
	x Exchange,
	want string,
) {
	t.Helper()
	p, err := pac.Parse(thePAC(t, side, x))
	if err != nil {
		t.Fatalf("%s: %v", side, err)
	}
	ci, err := p.ClientInfo()
	if err != nil {
		t.Fatalf("%s: %v", side, err)
	}
	if ci.Name != want {
		t.Errorf("%s: the PAC names %q, want %q",
			side, ci.Name, want)
	}
}

// assertSameS4UReply compares the PA-S4U-X509-USER each side echoed,
// and insists both sent one.
//
// The structure is deterministic -- the nonce and the name are the
// client's own and the options are masked -- so the two sides must
// agree on all of it. The checksum is over that structure with a key
// both hold, so it has to agree too, which makes this an octet
// comparison rather than a field-by-field one.
func assertSameS4UReply(t *testing.T, g tgt, cx, gx Exchange) {
	t.Helper()
	c := s4uReplyOf(t, "oracle", cx)
	d := s4uReplyOf(t, "diamond", gx)
	if string(c.Value) != string(d.Value) {
		t.Errorf("the S4U replies differ\n oracle:  % X\n"+
			"diamond: % X", c.Value, d.Value)
	}
	rep, err := wire.UnmarshalPAS4UX509User(d.Value)
	if err != nil {
		t.Fatal(err)
	}
	if rep.UserID.UserName == nil ||
		rep.UserID.UserName.String() != UserName {
		t.Errorf("the echo names %v", rep.UserID.UserName)
	}
	// The checksum is verifiable with the TGT's session key,
	// which is what tells a client the reply came from a KDC.
	der, err := wire.MarshalS4UUserID(rep.UserID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := crypto.ProfileForCksum(
		crypto.CksumType(rep.Cksum.Type))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyChecksum(g.session, der,
		rep.Cksum.Checksum,
		crypto.UsageS4UX509UserRequest); err != nil {
		t.Errorf("the echo's checksum: %v", err)
	}
}

// s4uReplyOf finds the echo in a reply's cleartext padata, insisting
// it is there -- two KDCs that both omitted it would agree.
func s4uReplyOf(
	t *testing.T,
	side string,
	x Exchange,
) wire.PAData {
	t.Helper()
	for _, d := range x.Rep.PAData {
		if d.Type == wire.PATypeS4UX509User {
			return d
		}
	}
	t.Fatalf("%s: no S4U padata in the reply: %v",
		side, x.Rep.PAData)
	return wire.PAData{}
}

// serviceTGTFromTheC gets the *service* its own TGT, which is what an
// S4U2Self request is presented with.
func serviceTGTFromTheC(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
) tgt {
	t.Helper()
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, ServiceName[0], till)
	req.Body.CName = &wire.PrincipalName{
		Type: wire.NTPrincipal, Components: ServiceName,
	}
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	return tgtOf(open(t, raw, ServicePassword, ServiceName))
}

// s4uSelfRequest builds the S4U2Self TGS-REQ both KDCs answer: the
// service asking for a ticket to itself, naming the user.
func s4uSelfRequest(
	t *testing.T,
	g tgt,
	till time.Time,
	mutate func(*wire.S4UUserID),
) []byte {
	t.Helper()
	body := wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: ServiceName,
		},
		Till:  till,
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
	id := wire.S4UUserID{
		Nonce: body.Nonce,
		UserName: &wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{UserName},
		},
		UserRealm: Realm,
	}
	if mutate != nil {
		mutate(&id)
	}
	return signS4URequest(t, g, body,
		goldenX509UserPAData(t, g, id))
}

// signS4URequest encodes the body, signs it into an AP-REQ whose
// authenticator names the *service*, and appends the S4U padata.
func signS4URequest(
	t *testing.T,
	g tgt,
	body wire.KDCReqBody,
	pa wire.PAData,
) []byte {
	t.Helper()
	req := wire.TGSReq{Body: body}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = []wire.PAData{
		serviceAPReq(t, g, bodyDER), pa,
	}
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// serviceAPReq is tgsAPReq with an authenticator naming a
// *two-component* principal, which the service is and which
// sealAuthenticator's single-component form cannot express.
func serviceAPReq(
	t *testing.T,
	g tgt,
	bodyDER []byte,
) wire.PAData {
	t.Helper()
	p, err := crypto.Profile(g.sessionEType)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := p.Checksum(g.session, bodyDER,
		crypto.UsageTGSReqAuthCksum)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := wire.MarshalAuthenticator(wire.Authenticator{
		CRealm: Realm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: ServiceName,
		},
		Cksum: &wire.Checksum{
			Type:     int32(p.RequiredCksum),
			Checksum: sum,
		},
		CUsec: 1234,
		CTime: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return apReqPAData(t, p, g, plain)
}

// apReqPAData seals an authenticator and wraps the AP-REQ as padata.
func apReqPAData(
	t *testing.T,
	p *crypto.EncProfile,
	g tgt,
	plain []byte,
) wire.PAData {
	t.Helper()
	ct, err := p.Encrypt(g.session, plain,
		crypto.UsageTGSReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	apreq, err := wire.MarshalAPReq(wire.APReq{
		Ticket: g.ticket,
		Authenticator: wire.EncryptedData{
			EType:  int32(p.EncType),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{Type: wire.PATGSReq, Value: apreq}
}

// goldenX509UserPAData builds a PA-S4U-X509-USER with a correct
// checksum over the user-id field at key usage 26.
func goldenX509UserPAData(
	t *testing.T,
	g tgt,
	id wire.S4UUserID,
) wire.PAData {
	t.Helper()
	der, err := wire.MarshalS4UUserID(id)
	if err != nil {
		t.Fatal(err)
	}
	p, err := crypto.Profile(g.sessionEType)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := p.Checksum(g.session, der,
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

// A **stock kvno** performs the impersonation, which is the anchor
// the plan's verification table names for this step.
//
// The sequence is a whole realm's worth of this project working at
// once: `kdiamond ktadd' writes the service a keytab with a freshly
// random key, a stock `kinit -k' reads that keytab and gets the
// service a TGT with a PAC in it, and a stock `kvno -I' then presents
// that TGT with S4U2Self padata and gets a ticket naming somebody
// else. Every one of E1, E2 and E5 has to be right for the last step
// to produce anything, and the client -- not this test -- is what
// checks the reply: kvno opens the ticket and prints its key version.
//
// `-I' rather than `-U': -U parses its argument as an enterprise
// name, and the subject here is an ordinary principal
// (clients/kvno/kvno.c:129-137).
func TestStockKvnoImpersonatesAgainstTheGoKDC(t *testing.T) {
	o := oracle(t)
	bin := buildKdiamond(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 60*time.Second)
	defer cancel()

	env := pointAtDiamond(t, ctx, o, "s4u", true)
	url := searchPath(os.Getenv(TestDatabaseURL),
		"kd_golden_e2e_s4u")
	svc := strings.Join(ServiceName, "/")

	kt := putKeytab(t, ctx, o, bin, url, "s4ukeytab", svc)
	out, err := o.ExecEnv(ctx, env, "", "kinit", "-k",
		"-t", kt, svc+"@"+Realm)
	if err != nil {
		t.Fatalf("kinit -k failed: %v\n%s", err, out)
	}
	assertWentToTheShim(t, out)

	out, err = o.ExecEnv(ctx, env, "", "kvno", "-I",
		UserName, svc+"@"+Realm)
	if err != nil {
		t.Fatalf("kvno -I failed: %v\n%s", err, out)
	}
	// The trace has to show the exchange reaching the shim, or a
	// ticket already in the cache would satisfy kvno without the
	// Go KDC answering anything.
	assertWentToTheShim(t, out)
	// And kvno prints the *impersonated* name beside the service,
	// which is the client's own report that the ticket it got
	// names somebody it never authenticated as.
	if !strings.Contains(out, UserName+"@"+Realm) {
		t.Errorf("kvno did not report the subject:\n%s", out)
	}
	if !strings.Contains(out, "kvno = ") {
		t.Errorf("kvno did not report a key version:\n%s",
			out)
	}
}
