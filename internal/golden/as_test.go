package golden

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// requestedLife is how long a ticket the harness asks for. It is well
// inside kadmin's one-day default max_life, so the end time is the
// requested till on both sides rather than a cap -- which keeps the
// comparison about what the KDC decided and not about which default
// bit first.
const requestedLife = 8 * time.Hour

// asRequest builds the AS-REQ both implementations answer.
//
// Exactly the same encoded bytes go to both, which is the only way to
// be sure a difference is in the answer rather than in the question.
//
// It carries PA-PAC-REQUEST(false), and that is a deliberate
// narrowing of what is compared. A stock MIT KDC puts a signed
// Windows PAC in every AS ticket unless the client declines one
// (kdc/kdc_authdata.c:479-493, include_pac_p at
// kdc/kdc_preauth.c:1581-1609), and this project issues none --
// MS-PAC is NDR-encoded Windows interop with two keyed checksums in
// it and is nowhere near the AS slice. Declining it is something an
// unmodified client is entitled to do, so the harness does that
// rather than reconfiguring the C KDC or exempting the field: the
// comparison then covers the whole structure with no holes in it, and
// the gap is recorded in BOOTSTRAP.md §3.3 rather than hidden in a
// skipped field.
func asRequest(t *testing.T, name string, till time.Time) wire.ASReq {
	t.Helper()
	noPAC, err := wire.MarshalPAPACRequest(false)
	if err != nil {
		t.Fatal(err)
	}
	return wire.ASReq{PAData: []wire.PAData{
		{Type: wire.PAPACRequest, Value: noPAC},
	}, Body: wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptProxiable |
			wire.OptRenewableOK,
		CName: &wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{name},
		},
		Realm: Realm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{"krbtgt", Realm},
		},
		Till:  till,
		Nonce: 0x2A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}}
}

// open decrypts a reply and its ticket into an Exchange.
//
// Both halves are opened, not just the one the client can read: the
// EncTicketPart's flags and times are most of what the AS exchange
// actually decides, so skipping it would leave the interesting part
// of the comparison untested.
func open(
	t *testing.T,
	raw []byte,
	userPassword string,
	components []string,
) Exchange {
	t.Helper()
	rep := decodeReply(t, raw)
	enc := decryptEnc(t, rep, userPassword, components)
	tkt := decryptTicket(t, rep)
	return Exchange{Rep: rep, Enc: enc, Tkt: tkt}
}

// decodeReply insists the reply is an AS-REP.
//
// This is the guard against the hazard the whole harness exists
// under: a case where *both* implementations fail identically passes
// while testing nothing. Two KDCs both answering C_PRINCIPAL_UNKNOWN
// agree perfectly. Every case here asserts the exchange succeeded,
// and the KRB-ERROR is decoded only so the failure message says which
// refusal it was.
func decodeReply(t *testing.T, raw []byte) wire.ASRep {
	t.Helper()
	rep, err := wire.UnmarshalASRep(raw)
	if err == nil {
		return rep
	}
	if kerr, e := wire.UnmarshalKRBError(raw); e == nil {
		t.Fatalf("expected an AS-REP, got %v (e-text %q)",
			kerr.Error(), kerr.EText)
	}
	t.Fatalf("reply is no AS-REP and no KRB-ERROR: %v", err)
	return wire.ASRep{}
}

func decryptEnc(
	t *testing.T,
	rep wire.ASRep,
	password string,
	components []string,
) wire.EncKDCRepPart {
	t.Helper()
	plain := decrypt(t, rep.EncPart, password, components,
		crypto.UsageASRepEncPart)
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return enc
}

func decryptTicket(
	t *testing.T,
	rep wire.ASRep,
) wire.EncTicketPart {
	t.Helper()
	plain := decrypt(t, rep.Ticket.EncPart, TgtPassword,
		[]string{"krbtgt", Realm}, crypto.UsageKDCRepTicket)
	tkt, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatalf("EncTicketPart: %v", err)
	}
	return tkt
}

// decrypt opens one EncryptedData with the key a principal's password
// derives, using that principal's own default salt.
func decrypt(
	t *testing.T,
	ed wire.EncryptedData,
	password string,
	components []string,
	usage crypto.Usage,
) []byte {
	t.Helper()
	p, err := crypto.Profile(crypto.EncType(ed.EType))
	if err != nil {
		t.Fatalf("enctype %d: %v", ed.EType, err)
	}
	key, err := p.StringToKey(password,
		crypto.Salt(Realm, components), nil)
	if err != nil {
		t.Fatalf("StringToKey: %v", err)
	}
	plain, err := p.Decrypt(key, ed.Cipher, usage)
	if err != nil {
		t.Fatalf("decrypting under %s: %v",
			strings.Join(components, "/"), err)
	}
	return plain
}

// pinned is a clock that always reads the same moment.
func pinned(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// diamond starts a Go KDC on the given clock.
//
// The differential cases pin it to the C KDC's authtime, and that is
// what makes the end times comparable: both sides are asked for the
// same absolute till, so with the same authtime the offset from
// authtime to endtime is identical. Without it the two differ by
// however long the first exchange took. The end-to-end cases use a
// live clock, because a real client checks the reply against its own.
func diamond(
	t *testing.T,
	schema string,
	now func() time.Time,
) *Diamond {
	t.Helper()
	d, err := StartDiamond(context.Background(), schema, now)
	if err != nil {
		t.Skipf("no Go KDC: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// TestASExchangeMatchesTheC is the differential test.
//
// One encoded AS-REQ, answered by the C KDC over TCP and by the Go
// KDC in process, decrypted on both sides and compared field by
// field.
func TestASExchangeMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, UserName, till)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cx := open(t, cRaw, UserPassword, []string{UserName})

	d := diamond(t, "kd_golden_as", pinned(cx.Enc.AuthTime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	gx := open(t, goRaw, UserPassword, []string{UserName})

	assertSucceeded(t, cx)
	assertSucceeded(t, gx)
	assertTimeRelationships(t, "oracle", cx)
	assertTimeRelationships(t, "diamond", gx)
	reportDiffs(t, cx, gx)
}

// reportDiffs names every field the two sides disagree about, and
// prints both renderings when any of them do -- a failure naming one
// field is useless without the surrounding context.
func reportDiffs(t *testing.T, oracle, diamond Exchange) {
	t.Helper()
	a, b := Normalize(oracle, Realm), Normalize(diamond, Realm)
	diffs := Compare(a, b)
	for _, d := range diffs {
		t.Errorf("%v", d)
	}
	if len(diffs) > 0 {
		t.Logf("oracle:\n%s", a)
		t.Logf("diamond:\n%s", b)
	}
}

// assertSucceeded checks the exchange produced a usable ticket rather
// than merely a message that parsed.
//
// Without this, a case where both sides returned something empty but
// identical would pass. The fields chosen are the ones a client
// cannot do without: a session key, a server name, and an end time
// after the authtime.
func assertSucceeded(t *testing.T, x Exchange) {
	t.Helper()
	if len(x.Enc.Key.KeyValue) == 0 {
		t.Error("reply carries no session key")
	}
	if len(x.Tkt.Key.KeyValue) == 0 {
		t.Error("ticket carries no session key")
	}
	if x.Enc.SName.String() != "krbtgt/"+Realm {
		t.Errorf("reply names server %q", x.Enc.SName)
	}
	if !x.Enc.EndTime.After(x.Enc.AuthTime) {
		t.Errorf("endtime %v is not after authtime %v",
			x.Enc.EndTime, x.Enc.AuthTime)
	}
	if !x.Enc.Flags.Has(wire.FlagInitial) {
		t.Error("ticket is not marked initial")
	}
}

// assertTimeRelationships checks the invariants that normalising
// absolute times would otherwise hide.
//
// Rebasing every timestamp on the authtime makes the two sides
// comparable, but it also makes a clamping bug normalise into a
// passing test -- so the relationships are asserted on each side
// separately, before the comparison.
func assertTimeRelationships(
	t *testing.T,
	side string,
	x Exchange,
) {
	t.Helper()
	// starttime is absent exactly when it equals authtime: the
	// KDC drops it then (do_as_req.c:706-711) and the decoder's
	// default puts it back.
	if !x.Enc.StartTime.IsZero() &&
		x.Enc.StartTime.Equal(x.Enc.AuthTime) {
		t.Errorf("%s: starttime equals authtime and was "+
			"still sent", side)
	}
	if !x.Enc.EffectiveStartTime().Equal(x.Enc.AuthTime) {
		t.Errorf("%s: effective starttime %v, authtime %v",
			side, x.Enc.EffectiveStartTime(),
			x.Enc.AuthTime)
	}
	// renew-till travels only when the renewable flag is set, so
	// one without the other means the encoder and the policy
	// disagree.
	renewable := x.Enc.Flags.Has(wire.FlagRenewable)
	if !renewable && !x.Enc.RenewTill.IsZero() {
		t.Errorf("%s: renew-till sent without the flag", side)
	}
	if !x.Tkt.AuthTime.Equal(x.Enc.AuthTime) {
		t.Errorf("%s: ticket authtime %v, reply %v", side,
			x.Tkt.AuthTime, x.Enc.AuthTime)
	}
	if !x.Tkt.EndTime.Equal(x.Enc.EndTime) {
		t.Errorf("%s: ticket endtime %v, reply %v", side,
			x.Tkt.EndTime, x.Enc.EndTime)
	}
}

// TestPreauthRefusalMatchesTheC compares the *first* round trip of
// the preauth handshake, which is a KRB-ERROR on both sides.
//
// This is the one case where a matching failure is the point, so it
// is not driven through the success guard above. What it asserts
// instead is that both sides refused for the same reason and offered
// the same mechanism -- a client has to be able to act on the hint,
// and a transcript that merely agreed on "no" would prove nothing.
func TestPreauthRefusalMatchesTheC(t *testing.T) {
	o := oracle(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 30*time.Second)
	defer cancel()

	till := time.Now().UTC().Add(requestedLife).Truncate(
		time.Second)
	req := asRequest(t, PreauthName, till)
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}

	cRaw, err := o.SendRaw(ctx, msg)
	if err != nil {
		t.Fatalf("asking the C KDC: %v", err)
	}
	cErr := refusal(t, cRaw)

	d := diamond(t, "kd_golden_preauth", pinned(cErr.STime))
	goRaw, err := d.AS(req)
	if err != nil {
		t.Fatalf("asking the Go KDC: %v", err)
	}
	goErr := refusal(t, goRaw)

	if cErr.ErrorCode != wire.ErrCodePreauthRequired {
		t.Fatalf("the C KDC answered %d, want %d",
			cErr.ErrorCode, wire.ErrCodePreauthRequired)
	}
	if goErr.ErrorCode != cErr.ErrorCode {
		t.Errorf("error code: oracle %d, diamond %d",
			cErr.ErrorCode, goErr.ErrorCode)
	}
	compareHints(t, cErr, goErr)
}

// refusal insists the reply is a KRB-ERROR and not a ticket.
func refusal(t *testing.T, raw []byte) wire.KRBError {
	t.Helper()
	e, err := wire.UnmarshalKRBError(raw)
	if err != nil {
		t.Fatalf("expected a KRB-ERROR: %v", err)
	}
	return e
}

// compareHints checks both sides offered PA-ETYPE-INFO2 with the same
// enctype and salt, which is what a client needs to answer the
// refusal.
//
// The hint lists are not compared wholesale: the C's leads with an
// empty PA-FX-FAST to advertise FAST (kdc/kdc_preauth.c:380), which
// this project does not implement and deliberately does not claim. So
// the comparison is of the ETYPE-INFO2 the client actually acts on.
func compareHints(t *testing.T, cErr, goErr wire.KRBError) {
	t.Helper()
	c := etypeInfo2(t, "oracle", cErr)
	g := etypeInfo2(t, "diamond", goErr)
	if c.EType != g.EType {
		t.Errorf("hinted etype: oracle %d, diamond %d",
			c.EType, g.EType)
	}
	if c.Salt == nil || g.Salt == nil {
		t.Fatalf("a hint carried no salt: %v, %v",
			c.Salt, g.Salt)
	}
	if *c.Salt != *g.Salt {
		t.Errorf("hinted salt: oracle %q, diamond %q",
			*c.Salt, *g.Salt)
	}
	if len(c.S2KParams) != len(g.S2KParams) {
		t.Errorf("s2kparams: oracle % X, diamond % X",
			c.S2KParams, g.S2KParams)
	}
}

// etypeInfo2 pulls the first ETYPE-INFO2 entry out of a refusal's
// e-data.
func etypeInfo2(
	t *testing.T,
	side string,
	e wire.KRBError,
) wire.ETypeInfo2Entry {
	t.Helper()
	hints, err := wire.UnmarshalPADataSeq(e.EData)
	if err != nil {
		t.Fatalf("%s: e-data: %v", side, err)
	}
	for _, h := range hints {
		if h.Type != wire.PAETypeInfo2 {
			continue
		}
		entries, err := wire.UnmarshalETypeInfo2(h.Value)
		if err != nil {
			t.Fatalf("%s: PA-ETYPE-INFO2: %v", side, err)
		}
		if len(entries) == 0 {
			t.Fatalf("%s: empty PA-ETYPE-INFO2", side)
		}
		return entries[0]
	}
	t.Fatalf("%s: no PA-ETYPE-INFO2 in the refusal", side)
	return wire.ETypeInfo2Entry{}
}
