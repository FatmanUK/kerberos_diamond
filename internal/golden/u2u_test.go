package golden

import (
	"context"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// tgtFor runs an AS exchange against the C KDC for a named principal
// and keeps what a client keeps. It is getTGTFromTheC with the
// principal as a parameter, which the peer's TGT needs.
func tgtFor(
	t *testing.T,
	ctx context.Context,
	o *Oracle,
	name, password string,
) tgt {
	t.Helper()
	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	msg, err := wire.MarshalASReq(asRequest(t, name, till))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC for %s: %v", name, err)
	}
	return tgtOf(open(t, raw, password, []string{name}))
}

// u2uRequestFor builds the user-to-user TGS-REQ both implementations
// answer: the peer named as the server, the peer's own TGT carried as
// the request's second ticket.
func u2uRequestFor(
	t *testing.T,
	g tgt,
	second wire.Ticket,
	till time.Time,
) []byte {
	t.Helper()
	body := wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK |
			wire.OptEncTktInSKey,
		Realm: Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{PeerName},
		},
		Till:  till,
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
	if err := body.SetTickets(
		[]wire.Ticket{second}); err != nil {
		t.Fatal(err)
	}
	return signTGSReq(t, g, body)
}

// signTGSReq encodes a body, checksums it, and encodes the request
// around the resulting PA-TGS-REQ.
func signTGSReq(
	t *testing.T,
	g tgt,
	body wire.KDCReqBody,
) []byte {
	t.Helper()
	req := wire.TGSReq{PAData: []wire.PAData{
		{Type: wire.PAReqEncPARep},
	}, Body: body}
	draft, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = append(req.PAData, tgsAPReq(t, g, bodyDER))
	msg, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// openU2U decodes a user-to-user reply. The ticket is opened with the
// *second ticket's session key*, which is the whole point of the
// mechanism: the peer holds no long-term key, so there is nothing
// else the ticket could have been sealed with.
func openU2U(
	t *testing.T,
	raw []byte,
	g tgt,
	sealing []byte,
) Exchange {
	t.Helper()
	rep := decodeTGSRep(t, raw)
	enc := decryptPart(t, rep.EncPart, g.session,
		crypto.UsageTGSRepEncPartSessKey)
	tkt := decryptPart(t, rep.Ticket.EncPart, sealing,
		crypto.UsageKDCRepTicket)
	return Exchange{
		Rep: rep,
		Enc: decodeEncPart(t, enc),
		Tkt: decodeTktPart(t, tkt),
	}
}

// TestU2UMatchesTheC is the differential test for user-to-user.
//
// Two TGTs come from the C KDC -- the client's and the peer's -- and
// the same encoded request is put to both implementations. That the
// harness can decrypt the issued ticket at all is the assertion that
// matters: the key it uses is the session key out of the peer's TGT,
// and a KDC that sealed with anything else would produce something
// this cannot open.
func TestU2UMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := tgtFor(t, ctx, o, UserName, UserPassword)
	peer := tgtFor(t, ctx, o, PeerName, PeerPassword)
	till := time.Now().UTC().Add(2 * time.Hour).Truncate(
		time.Second)
	msg := u2uRequestFor(t, g, peer.ticket, till)

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := openU2U(t, cRaw, g, peer.session)

	d := diamond(t, "kd_golden_u2u",
		pinned(cx.Enc.EffectiveStartTime()))
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := openU2U(t, goRaw, g, peer.session)

	assertU2U(t, "oracle", cx, peer)
	assertU2U(t, "diamond", gx, peer)
	reportDiffs(t, cx, gx)
}

// assertU2U checks the exchange issued a usable ticket rather than
// merely agreeing with the other side.
func assertU2U(
	t *testing.T,
	side string,
	x Exchange,
	peer tgt,
) {
	t.Helper()
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Errorf("%s: reply carries no session key", side)
	}
	if got := x.Enc.SName.String(); got != PeerName {
		t.Errorf("%s: reply names server %q, want %q",
			side, got, PeerName)
	}
	if x.Tkt.CName.String() != UserName {
		t.Errorf("%s: ticket client is %q", side, x.Tkt.CName)
	}
	// There is no long-term key to have a version, so the ticket
	// names none (do_tgs_req.c:1056-1061).
	if x.Rep.Ticket.EncPart.KVNO != 0 {
		t.Errorf("%s: ticket kvno is %d, want absent",
			side, x.Rep.Ticket.EncPart.KVNO)
	}
	// The session key's enctype is the peer's TGT's, not the
	// request's first choice: it is the one enctype the peer is
	// known to support (gen_session_key, do_tgs_req.c:330-345).
	if x.Enc.Key.KeyType != int32(peer.sessionEType) {
		t.Errorf("%s: session key enctype %d, want %d",
			side, x.Enc.Key.KeyType, peer.sessionEType)
	}
	if !x.Enc.EndTime.After(x.Enc.AuthTime) {
		t.Errorf("%s: endtime %v is not after authtime %v",
			side, x.Enc.EndTime, x.Enc.AuthTime)
	}
}

// Without the option the peer is unreachable, and that is what makes
// the exemption in check_tgs_svc_deny_all worth having. Both sides
// must refuse, and with the same hint -- the error code is what tells
// a client to go and ask the peer for its TGT.
func TestOrdinaryRequestForThePeerIsRefused(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	g := tgtFor(t, ctx, o, UserName, UserPassword)
	msg := signTGSReq(t, g, peerBody())

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	d := diamond(t, "kd_golden_u2u_denied", nil)
	goRaw, err := d.KDC.Handle(msg)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	cCode := refusalCode(t, "oracle", cRaw)
	goCode := refusalCode(t, "diamond", goRaw)
	if cCode != wire.ErrCodeMustUseUser2User {
		t.Errorf("the C refused with %d, want %d", cCode,
			wire.ErrCodeMustUseUser2User)
	}
	if goCode != cCode {
		t.Errorf("codes differ: C %d, Go %d", cCode, goCode)
	}
}

// peerBody is an ordinary request for a ticket to the peer -- no
// user-to-user option, which is the point.
func peerBody() wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{PeerName},
		},
		Till:  in(2 * time.Hour),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
}

// refusalCode insists a reply is a KRB-ERROR and returns its code. A
// case that expects a refusal has to say so, and this is where it
// says it: a reply that turned out to be a ticket is a failure here,
// not a pass.
func refusalCode(t *testing.T, side string, raw []byte) int32 {
	t.Helper()
	kerr, err := wire.UnmarshalKRBError(raw)
	if err != nil {
		t.Fatalf("%s: expected a KRB-ERROR: %v", side, err)
	}
	return kerr.ErrorCode
}
