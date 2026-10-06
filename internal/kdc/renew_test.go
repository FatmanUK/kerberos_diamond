package kdc

import (
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// krbtgtName is the service a TGT is for, and therefore the one a
// renewal or a validation of a TGT names.
func krbtgtName() []string {
	return []string{"krbtgt", testRealm}
}

// renewableTGT obtains a TGT that can actually be renewed.
//
// Both the client and the krbtgt need a renewable lifetime first:
// kadmin's default is zero and kdc_get_ticket_renewtime takes a plain
// min against it (kdc/kdc_util.c:1744), so without this every renewal
// would be refused for the uninteresting reason.
func renewableTGT(
	t *testing.T,
	k *KDC,
	renewLife time.Duration,
) (wire.Ticket, []byte, wire.EncKDCRepPart) {
	t.Helper()
	setRenewableLife(t, k, renewLife)
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptRenewable
	req.Body.RTime = fixedNow.Add(renewLife)
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if !enc.Flags.Has(wire.FlagRenewable) {
		t.Fatal("the TGT is not renewable")
	}
	return rep.Ticket, enc.Key.KeyValue, enc
}

// reissueRequest builds a TGS-REQ that renews or validates a ticket.
//
// A real client sends the presented ticket's own flags alongside the
// renew option -- kdcopt |= old_creds.ticket_flags &
// KDC_TKT_COMMON_MASK (lib/krb5/krb/val_renew.c:61) -- and that is
// not cosmetic: the mask carries RENEWABLE, which is the only thing
// that lets kdc_get_ticket_renewtime grant a renew time at all. A
// test that sent bare KDC_OPT_RENEW would get a ticket that could
// never be renewed again and would not notice. now is the client's
// own clock, which has to agree with the KDC's or the authenticator
// is refused for skew before any of this is reached.
func reissueRequest(
	t *testing.T,
	tkt wire.Ticket,
	sessionKey []byte,
	opts wire.Flags,
	carry wire.Flags,
	now time.Time,
	mutate func(*wire.KDCReqBody),
) ([]byte, wire.TGSReq) {
	t.Helper()
	body := wire.KDCReqBody{
		Options: opts | (carry & kdcTktCommonMask),
		Realm:   testRealm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: krbtgtName(),
		},
		Till:  fixedNow.Add(8 * time.Hour),
		Nonce: 0x7E,
		EType: []int32{int32(crypto.AES256CTSHMACSHA196)},
	}
	if mutate != nil {
		mutate(&body)
	}
	req := wire.TGSReq{Body: body}
	msg := signRequest(t, &req, tkt, sessionKey,
		func(a *wire.Authenticator) { a.CTime = now })
	return msg, req
}

// kdcTktCommonMask is KDC_TKT_COMMON_MASK (krb5.hin:1659): the ticket
// flags a client re-requests when renewing or validating. It is
// forwardable, proxiable, may-postdate and renewable.
const kdcTktCommonMask = wire.FlagForwardable |
	wire.FlagProxiable | wire.FlagMayPostdate | wire.FlagRenewable

// openTGTReply opens a reissued TGT's reply half with the session key
// of the ticket that was presented.
func openTGTReply(
	t *testing.T,
	rep *wire.TGSRep,
	sessionKey []byte,
) wire.EncKDCRepPart {
	t.Helper()
	return openTGSRep(t, rep, sessionKey)
}

// A renewal reissues the same ticket: same client, same server, same
// authtime, a fresh start time and a session key of its own.
func TestRenewReissuesTheTicket(t *testing.T) {
	k := testKDC(t)
	tgt, session, before := renewableTGT(t, k, 7*24*time.Hour)

	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		before.Flags, fixedNow, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("renewal refused: %v", kerr)
	}
	after := openTGTReply(t, rep, session)

	if got := after.SName.String(); got !=
		"krbtgt/"+testRealm {
		t.Errorf("renewed ticket names %q", got)
	}
	if !after.AuthTime.Equal(before.AuthTime) {
		t.Errorf("authtime changed from %v to %v",
			before.AuthTime, after.AuthTime)
	}
	if rep.CName.String() != "user" {
		t.Errorf("renewed for %q", rep.CName)
	}
	// A new session key, or renewing would hand back a credential
	// no fresher than the one it replaced.
	if string(after.Key.KeyValue) == string(session) {
		t.Error("the renewed ticket reuses the session key")
	}
}

// Renewing gives the ticket the *same lifetime it had*, starting now,
// clamped to the renew-till it already carried
// (do_tgs_req.c:832-836). So renewal moves the window rather than
// widening it, and the renew-till is a wall the client cannot push.
func TestRenewKeepsTheLifetimeAndHonoursRenewTill(t *testing.T) {
	k := testKDC(t)
	tgt, session, before := renewableTGT(t, k, 7*24*time.Hour)
	life := before.EndTime.Sub(before.EffectiveStartTime())

	// Ask for a till far beyond the renew-till; it must be
	// ignored in favour of the original lifetime.
	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		before.Flags, fixedNow, func(b *wire.KDCReqBody) {
			b.Till = before.RenewTill.Add(100 * time.Hour)
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("renewal refused: %v", kerr)
	}
	after := openTGTReply(t, rep, session)

	got := after.EndTime.Sub(after.EffectiveStartTime())
	if got != life {
		t.Errorf("lifetime changed from %v to %v", life, got)
	}
	if after.EndTime.After(before.RenewTill) {
		t.Errorf("endtime %v is past renew-till %v",
			after.EndTime, before.RenewTill)
	}
}

// A renewed ticket stays renewable, which is what makes repeated
// renewal possible -- and it works only because the client re-sends
// RENEWABLE in the option mask.
func TestRenewedTicketStaysRenewable(t *testing.T) {
	k := testKDC(t)
	tgt, session, before := renewableTGT(t, k, 7*24*time.Hour)

	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		before.Flags, fixedNow, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("renewal refused: %v", kerr)
	}
	after := openTGTReply(t, rep, session)
	if !after.Flags.Has(wire.FlagRenewable) {
		t.Fatal("the renewed ticket is not renewable")
	}
	if !after.RenewTill.Equal(before.RenewTill) {
		t.Errorf("renew-till moved from %v to %v",
			before.RenewTill, after.RenewTill)
	}
}

// Without RENEWABLE in the request's options,
// kdc_get_ticket_renewtime grants nothing and the flag must be
// cleared -- even though it arrived set, copied wholesale from the
// presented ticket. A KDC that only ever ORed the flag in would hand
// back a ticket claiming to be renewable with no renew-till to renew
// against.
func TestRenewWithoutTheFlagClearsIt(t *testing.T) {
	k := testKDC(t)
	tgt, session, _ := renewableTGT(t, k, 7*24*time.Hour)

	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		0, fixedNow, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("renewal refused: %v", kerr)
	}
	after := openTGTReply(t, rep, session)
	if after.Flags.Has(wire.FlagRenewable) {
		t.Error("renewable survived with no renew time")
	}
	if !after.RenewTill.IsZero() {
		t.Errorf("renew-till is %v, want none",
			after.RenewTill)
	}
}

// A ticket that is not renewable cannot be renewed, and the refusal
// is BADOPTION rather than anything about time (tgsflagrules,
// kdc/tgs_policy.c:75-76).
func TestRenewNeedsARenewableTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		0, fixedNow, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("renewed a non-renewable ticket")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeBadOption)
	}
}

// Past the renew-till there is nothing left to renew, and that
// refusal is TKT_EXPIRED (check_tgs_times, kdc/tgs_policy.c:236-241).
func TestRenewPastRenewTill(t *testing.T) {
	k := testKDC(t)
	tgt, session, before := renewableTGT(t, k, 2*time.Hour)

	// Move the KDC's clock past the renew-till. The ticket's own
	// end time is checked when the AP-REQ is read, so the clock
	// has to stay inside that -- which is why the renewable life
	// here is shorter than the ticket life rather than longer.
	at := before.RenewTill.Add(time.Minute)
	k.Now = pinnedClock(at)
	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		before.Flags, at, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("renewed past the renew-till")
	}
	if kerr.ErrorCode != wire.ErrCodeTktExpired {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeTktExpired)
	}
}

// pinnedClock is a clock reading one fixed moment.
func pinnedClock(at time.Time) Clock {
	return func() time.Time { return at }
}

// A renewal naming a different server than the ticket is refused.
//
// Upstream would issue a ticket *named* for the presented ticket's
// server but *sealed* with the requested one's key -- undecryptable
// by the principal it names. This refuses instead, which is the one
// deliberate divergence in the reissue path.
func TestRenewRejectsAMismatchedServer(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session, before := renewableTGT(t, k, 7*24*time.Hour)

	msg, req := reissueRequest(t, tgt, session, wire.OptRenew,
		before.Flags, fixedNow, func(b *wire.KDCReqBody) {
			b.SName = &wire.PrincipalName{
				Type:       wire.NTSrvHst,
				Components: serviceName,
			}
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("renewed into a ticket for another service")
	}
	if kerr.ErrorCode != wire.ErrCodeServerNoMatch {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeServerNoMatch)
	}
}

// postdatedTGT obtains a ticket that is not yet valid, which is what
// validation exists to turn on.
func postdatedTGT(
	t *testing.T,
	k *KDC,
	start time.Time,
) (wire.Ticket, []byte, wire.EncKDCRepPart) {
	t.Helper()
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptAllowPostdate | wire.OptPostdated
	req.Body.From = start
	req.Body.Till = start.Add(4 * time.Hour)
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if !enc.Flags.Has(wire.FlagInvalid) {
		t.Fatal("the postdated ticket is not marked invalid")
	}
	return rep.Ticket, enc.Key.KeyValue, enc
}

// Validation clears INVALID and preserves every time unchanged
// (do_tgs_req.c:820-824), which is the whole of what it does: the
// ticket was already issued for a window, and validating only says
// the window has arrived.
func TestValidateClearsInvalidAndKeepsTheTimes(t *testing.T) {
	k := testKDC(t)
	start := fixedNow.Add(time.Hour)
	tgt, session, before := postdatedTGT(t, k, start)

	// The clock has to be inside the ticket's window, or
	// check_tgs_times refuses it as not yet valid.
	at := start.Add(time.Minute)
	k.Now = pinnedClock(at)
	msg, req := reissueRequest(t, tgt, session, wire.OptValidate,
		before.Flags, at, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("validation refused: %v", kerr)
	}
	after := openTGTReply(t, rep, session)

	if after.Flags.Has(wire.FlagInvalid) {
		t.Error("the validated ticket is still invalid")
	}
	if !after.AuthTime.Equal(before.AuthTime) {
		t.Errorf("authtime changed to %v", after.AuthTime)
	}
	if !after.EndTime.Equal(before.EndTime) {
		t.Errorf("endtime changed to %v", after.EndTime)
	}
	// The starttime survives, and this is the assertion that the
	// early return in compute_ticket_times exists for: the
	// starttime-equals-authtime rule never runs for a validation,
	// so a postdated ticket keeps the field that says when it
	// became usable.
	if !after.StartTime.Equal(before.StartTime) {
		t.Errorf("starttime changed from %v to %v",
			before.StartTime, after.StartTime)
	}
	if after.StartTime.IsZero() {
		t.Error("the starttime was dropped")
	}
}

// Validating before the start time is refused as not yet valid, which
// is the check that makes postdating mean anything.
func TestValidateBeforeTheStartTime(t *testing.T) {
	k := testKDC(t)
	start := fixedNow.Add(time.Hour)
	tgt, session, before := postdatedTGT(t, k, start)

	msg, req := reissueRequest(t, tgt, session, wire.OptValidate,
		before.Flags, fixedNow, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("validated a ticket before its start time")
	}
	if kerr.ErrorCode != wire.ErrCodeTktNYV {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeTktNYV)
	}
}

// Validating a ticket that is already valid is refused: the option
// requires the INVALID flag (tgsflagrules, kdc/tgs_policy.c:72-73).
func TestValidateNeedsAnInvalidTicket(t *testing.T) {
	k := testKDC(t)
	tgt, session := getTGT(t, k)

	msg, req := reissueRequest(t, tgt, session, wire.OptValidate,
		0, fixedNow, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("validated an already-valid ticket")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeBadOption)
	}
}

// An INVALID ticket cannot be used for anything *but* validation,
// which is what keeps a postdated ticket inert until its time comes
// (check_tgs_opts, kdc/tgs_policy.c:99-103).
func TestInvalidTicketCannotBuyAServiceTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	start := fixedNow.Add(time.Hour)
	tgt, session, _ := postdatedTGT(t, k, start)

	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("spent an invalid ticket")
	}
	if kerr.ErrorCode != wire.ErrCodeTktNYV {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeTktNYV)
	}
}
