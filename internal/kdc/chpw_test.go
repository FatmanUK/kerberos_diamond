package kdc

import (
	"context"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/acl"
	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// changePWRequest builds the frame a client sends: six octets of
// header, an AP-REQ for kadmin/changepw, and a KRB-PRIV carrying the
// new password.
func changePWRequest(
	t *testing.T,
	tkt wire.Ticket,
	session []byte,
	version uint16,
	data []byte,
) []byte {
	t.Helper()
	frame, err := wire.MarshalChangePWFrame(wire.ChangePWFrame{
		Version: version,
		APReq:   adminAPReq(t, tkt, session, nil),
		Rest:    changePWPriv(t, session, data),
	})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// changePWPriv seals the client's half.
func changePWPriv(
	t *testing.T, session, data []byte,
) []byte {
	t.Helper()
	p := aes256(t)
	part, err := wire.MarshalEncKRBPrivPart(
		wire.EncKRBPrivPart{
			UserData: data,
			// The initiator's directional address, which
			// is what a client with no address of its own
			// sends (changepw.c:150).
			SAddress:  wire.DirectionalInit(),
			SeqNumber: 1,
		})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(session, part,
		crypto.UsageKRBPrivEncPart)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := wire.MarshalKRBPriv(wire.KRBPriv{
		EncPart: wire.EncryptedData{
			EType:  int32(crypto.AES256CTSHMACSHA196),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// changePWResult reads a reply the way a client does: out of the
// KRB-PRIV when there is an AP-REP, and out of the KRB-ERROR's e-data
// when there is not.
func changePWResult(
	t *testing.T, reply, session []byte,
) (uint16, string) {
	t.Helper()
	f, err := wire.UnmarshalChangePWFrame(reply)
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	if f.Version != wire.ChangePWVersion1 {
		t.Errorf("reply version is %#x, want 1", f.Version)
	}
	if len(f.APReq) == 0 {
		kerr, err := wire.UnmarshalKRBError(f.Rest)
		if err != nil {
			t.Fatalf("decoding the KRB-ERROR: %v", err)
		}
		code, text, err := wire.UnmarshalChangePWResult(
			kerr.EData)
		if err != nil {
			t.Fatal(err)
		}
		return code, text
	}
	return changePWSealed(t, f, session)
}

// changePWSealed opens an authenticated reply, which also checks the
// AP-REP: a client that could not open it would report a transport
// failure rather than the result.
func changePWSealed(
	t *testing.T, f wire.ChangePWFrame, session []byte,
) (uint16, string) {
	t.Helper()
	p := aes256(t)
	rep, err := wire.UnmarshalAPRep(f.APReq)
	if err != nil {
		t.Fatalf("decoding the AP-REP: %v", err)
	}
	plain, err := p.Decrypt(session, rep.EncPart.Cipher,
		crypto.UsageAPRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the AP-REP: %v", err)
	}
	if _, err := wire.UnmarshalEncAPRepPart(plain); err != nil {
		t.Fatalf("decoding the AP-REP part: %v", err)
	}
	return changePWPrivResult(t, f, session)
}

// changePWPrivResult opens only the sealed result, which a case where
// the two halves of the reply use different keys needs on its own.
func changePWPrivResult(
	t *testing.T, f wire.ChangePWFrame, key []byte,
) (uint16, string) {
	t.Helper()
	p := aes256(t)
	priv, err := wire.UnmarshalKRBPriv(f.Rest)
	if err != nil {
		t.Fatalf("decoding the KRB-PRIV: %v", err)
	}
	clear, err := p.Decrypt(key, priv.EncPart.Cipher,
		crypto.UsageKRBPrivEncPart)
	if err != nil {
		t.Fatalf("decrypting the KRB-PRIV: %v", err)
	}
	part, err := wire.UnmarshalEncKRBPrivPart(clear)
	if err != nil {
		t.Fatalf("decoding the KRB-PRIV part: %v", err)
	}
	code, text, err := wire.UnmarshalChangePWResult(
		part.UserData)
	if err != nil {
		t.Fatal(err)
	}
	return code, text
}

// The whole point: after a change, the new password gets a ticket and
// the old one does not. Nothing short of an AS exchange under the new
// key proves the change reached the database in the form a client
// derives.
func TestChangePWChangesThePassword(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, changepwName)
	const newPW = "a-brand-new-password"

	reply := k.ChangePW(changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, []byte(newPW)))
	code, text := changePWResult(t, reply, session)
	if code != wire.KPasswdSuccess {
		t.Fatalf("code %d: %s", code, text)
	}
	assertPasswordWorks(t, k, newPW)
	assertPasswordFails(t, k, userPassword)
}

// The RFC 3244 form with no target is the same self change, and a
// reply to it is still version 1 -- which reads as a bug in
// upstream's reply writer and is not: the reply format never differed
// between the two versions (schpw.c:364).
func TestChangePWSetPasswordForSelf(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, changepwName)
	const newPW = "another-new-password"

	data, err := wire.MarshalChangePasswdData(
		wire.ChangePasswdData{NewPassword: []byte(newPW)})
	if err != nil {
		t.Fatal(err)
	}
	reply := k.ChangePW(changePWRequest(t, tkt, session,
		wire.ChangePWVersionSet, data))
	code, text := changePWResult(t, reply, session)
	if code != wire.KPasswdSuccess {
		t.Fatalf("code %d: %s", code, text)
	}
	assertPasswordWorks(t, k, newPW)
}

// Setting somebody else's password is an administrative act and goes
// through the same authorisation as kadmin's own cpw. There is
// nothing to consult yet, so it is refused -- a surface that let any
// authenticated principal re-key any other would be worse than one
// that does not do it at all.
func TestChangePWRefusesAnotherPrincipal(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, changepwName)

	data, err := wire.MarshalChangePasswdData(
		wire.ChangePasswdData{
			NewPassword: []byte("x"),
			TargName: &wire.PrincipalName{
				Type:       wire.NTPrincipal,
				Components: []string{"preauth"},
			},
			TargRealm: testRealm,
		})
	if err != nil {
		t.Fatal(err)
	}
	reply := k.ChangePW(changePWRequest(t, tkt, session,
		wire.ChangePWVersionSet, data))
	code, _ := changePWResult(t, reply, session)
	if code != wire.KPasswdAccessDenied {
		t.Errorf("code %d, want ACCESSDENIED", code)
	}
	// And the other principal's password is untouched.
	assertPasswordWorks(t, k, userPassword)
}

// A self change needs an initial ticket, which is upstream's own
// requirement (schpw_util_wrapper, kadmin/server/misc.c:24-32). A
// ticket obtained from a TGT proves only that the holder had a TGT,
// which a stolen credential cache also proves.
func TestChangePWNeedsAnInitialTicket(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromTGT(t, k, changepwName)

	reply := k.ChangePW(changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, []byte("nope")))
	code, _ := changePWResult(t, reply, session)
	if code != wire.KPasswdInitialNeeded {
		t.Errorf("code %d, want INITIAL_FLAG_NEEDED", code)
	}
	assertPasswordWorks(t, k, userPassword)
}

// Every other refusal, each by the code a client prints.
func TestChangePWRefusals(t *testing.T) {
	for _, c := range []struct {
		why  string
		want uint16
		run  func(t *testing.T, k *KDC) ([]byte, []byte)
	}{
		{"an unknown version", wire.KPasswdBadVersion,
			badVersionRequest},
		{"a ticket for the wrong service",
			wire.KPasswdAuthError, wrongServiceRequest},
		{"an empty password", wire.KPasswdSoftError,
			emptyPasswordRequest},
	} {
		t.Run(c.why, func(t *testing.T) {
			k := testKDC(t)
			frame, session := c.run(t, k)
			code, text := changePWResult(t,
				k.ChangePW(frame), session)
			if code != c.want {
				t.Errorf("code %d (%s), want %d",
					code, text, c.want)
			}
		})
	}
}

func badVersionRequest(
	t *testing.T, k *KDC,
) ([]byte, []byte) {
	tkt, session := adminTicketFromAS(t, k, changepwName)
	return changePWRequest(t, tkt, session, 0x0099,
		[]byte("x")), session
}

// kadmin/admin authenticates to the administrative surface but not to
// this one: upstream names kadmin/changepw explicitly when reading
// the AP-REQ (schpw.c:118-130), so a ticket for any other
// administrative instance does not reach it.
func wrongServiceRequest(
	t *testing.T, k *KDC,
) ([]byte, []byte) {
	tkt, session := adminTicketFromAS(t, k, "admin")
	return changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, []byte("x")), session
}

func emptyPasswordRequest(
	t *testing.T, k *KDC,
) ([]byte, []byte) {
	tkt, session := adminTicketFromAS(t, k, changepwName)
	return changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, nil), session
}

// A frame nothing can be authenticated out of comes back as a
// KRB-ERROR with no AP-REP, the result still readable in its e-data
// (schpw.c:311-349). A client reads it from either place, and this is
// the path where there is no key to seal with.
func TestChangePWMalformedFrameIsAKRBError(t *testing.T) {
	k := testKDC(t)
	reply := k.ChangePW([]byte{0x00, 0x03, 0x00, 0x01})

	f, err := wire.UnmarshalChangePWFrame(reply)
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	if len(f.APReq) != 0 {
		t.Errorf("an unauthenticated reply carried an AP-REP")
	}
	kerr, err := wire.UnmarshalKRBError(f.Rest)
	if err != nil {
		t.Fatalf("decoding the KRB-ERROR: %v", err)
	}
	want := adminName + "/" + changepwName
	if got := kerr.SName.String(); got != want {
		t.Errorf("the error is from %q, want %q", got, want)
	}
	code, _, err := wire.UnmarshalChangePWResult(kerr.EData)
	if err != nil {
		t.Fatal(err)
	}
	if code != wire.KPasswdMalformed {
		t.Errorf("code %d, want MALFORMED", code)
	}
}

// A change bumps the key version, which is what lets a service with a
// keytab be re-keyed without every holder of an old ticket being
// locked out at once -- except that this project replaces the whole
// key list rather than keeping the old version, so for now the bump
// is bookkeeping. The assertion is here so that the day keepold
// lands, the number it starts from is pinned.
func TestChangePWBumpsTheKVNO(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, changepwName)

	reply := k.ChangePW(changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, []byte("yet-another-one")))
	if code, text := changePWResult(t, reply,
		session); code != wire.KPasswdSuccess {
		t.Fatalf("code %d: %s", code, text)
	}
	p, err := k.Store.Lookup(ctxFor(t), "user@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.HighestKVNO(); got != 2 {
		t.Errorf("kvno is %d, want 2", got)
	}
}

// The password-change frame reaches the service through the same
// entry point a KDC request does, because they share one transport.
// Handle has to tell them apart, and the only thing it has to go on
// is that a Kerberos message opens with an application tag and this
// does not.
func TestHandleDispatchesAPasswordChange(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, changepwName)

	reply, err := k.Handle(changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, []byte("through-handle")))
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if code, text := changePWResult(t, reply,
		session); code != wire.KPasswdSuccess {
		t.Fatalf("code %d: %s", code, text)
	}
	assertPasswordWorks(t, k, "through-handle")
}

// ctxFor is a context for a test's own database calls.
func ctxFor(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

// assertPasswordWorks runs an AS exchange and opens the reply with
// the key a client derives from the password, which is the only thing
// that proves the stored key is the one a client computes.
func assertPasswordWorks(t *testing.T, k *KDC, password string) {
	t.Helper()
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	key := clientKey(t, []string{"user"}, password,
		crypto.EncType(rep.EncPart.EType))
	p, err := crypto.Profile(crypto.EncType(rep.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart); err != nil {
		t.Errorf("the reply does not open with %q: %v",
			password, err)
	}
}

// assertPasswordFails is the other half, and it is the half that says
// the change replaced the key rather than adding to it.
func assertPasswordFails(t *testing.T, k *KDC, password string) {
	t.Helper()
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	key := clientKey(t, []string{"user"}, password,
		crypto.EncType(rep.EncPart.EType))
	p, err := crypto.Profile(crypto.EncType(rep.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart); err == nil {
		t.Errorf("the reply still opens with %q", password)
	}
}

// The reply's two halves are sealed with *different* keys when the
// client sends a subkey, and this is the regression test for getting
// that wrong -- which a stock kpasswd caught and nothing else would
// have.
//
// krb5_mk_rep encrypts the AP-REP with the ticket's session key
// whatever subkey arrived (mk_rep.c:120) and echoes that subkey back
// in the AP-REP's own subkey field (:106). The echo is what makes the
// client read the KRB-PRIV after it with the subkey
// (rd_rep.c:113-121), so leaving it out produces a reply the client
// reports as "Decrypt integrity check failed" while the server
// believes it answered correctly.
func TestChangePWReplyKeysAndTheSubkeyEcho(t *testing.T) {
	k := testKDC(t)
	tkt, session := adminTicketFromAS(t, k, changepwName)
	sub := testSubkey()

	frame, err := wire.MarshalChangePWFrame(
		wire.ChangePWFrame{
			Version: wire.ChangePWVersion1,
			APReq: adminAPReq(t, tkt, session,
				func(a *wire.Authenticator) {
					a.SubKey = sub
					a.SeqNumber = 0x4321
				}),
			// The client seals its own half with the
			// subkey, which is what the server's
			// recv_subkey becomes (rd_req_dec.c:730-738).
			Rest: changePWPriv(t, sub.KeyValue,
				[]byte("subkeyed-password")),
		})
	if err != nil {
		t.Fatal(err)
	}
	f := replyFrame(t, k.ChangePW(frame))
	rep := assertAPRepEcho(t, f, session, sub)
	// And the KRB-PRIV is sealed with the subkey, which the echo
	// is what told the client to expect.
	code, _ := changePWPrivResult(t, f, sub.KeyValue)
	if code != wire.KPasswdSuccess {
		t.Errorf("code %d", code)
	}
	assertPrivSeqMatches(t, f, sub.KeyValue, rep.SeqNumber)
	assertPasswordWorks(t, k, "subkeyed-password")
}

// testSubkey is a fixed subkey, so a failure names a field rather
// than a random value.
func testSubkey() *wire.EncryptionKey {
	v := make([]byte, 32)
	for i := range v {
		v[i] = byte(0xA0 + i)
	}
	return &wire.EncryptionKey{
		KeyType:  int32(crypto.AES256CTSHMACSHA196),
		KeyValue: v,
	}
}

func replyFrame(t *testing.T, reply []byte) wire.ChangePWFrame {
	t.Helper()
	f, err := wire.UnmarshalChangePWFrame(reply)
	if err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	if len(f.APReq) == 0 {
		t.Fatalf("the reply carried no AP-REP")
	}
	return f
}

// assertAPRepEcho opens the AP-REP with the *session* key and checks
// the three things a client checks: the clock it sent back exactly,
// and the subkey it will read the rest with.
func assertAPRepEcho(
	t *testing.T,
	f wire.ChangePWFrame,
	session []byte,
	sub *wire.EncryptionKey,
) wire.EncAPRepPart {
	t.Helper()
	p := aes256(t)
	rep, err := wire.UnmarshalAPRep(f.APReq)
	if err != nil {
		t.Fatalf("decoding the AP-REP: %v", err)
	}
	// With the subkey, not the session key, it must *fail*.
	if _, err := p.Decrypt(sub.KeyValue, rep.EncPart.Cipher,
		crypto.UsageAPRepEncPart); err == nil {
		t.Error("the AP-REP opened with the subkey")
	}
	plain, err := p.Decrypt(session, rep.EncPart.Cipher,
		crypto.UsageAPRepEncPart)
	if err != nil {
		t.Fatalf("the AP-REP did not open with the "+
			"session key: %v", err)
	}
	part, err := wire.UnmarshalEncAPRepPart(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !part.CTime.Equal(fixedNow) || part.CUsec != 1234 {
		t.Errorf("the clock was not echoed: %v %d",
			part.CTime, part.CUsec)
	}
	if part.SubKey == nil ||
		string(part.SubKey.KeyValue) != string(sub.KeyValue) {
		t.Errorf("the subkey was not echoed: %v", part.SubKey)
	}
	return part
}

// assertPrivSeqMatches checks the one value that has to appear in
// both halves: the AP-REP's sequence number becomes the client's
// remote_seq_number (rd_rep.c:132) and the KRB-PRIV's is then checked
// against it (rd_priv.c:128-133).
func assertPrivSeqMatches(
	t *testing.T,
	f wire.ChangePWFrame,
	key []byte,
	want uint32,
) {
	t.Helper()
	p := aes256(t)
	priv, err := wire.UnmarshalKRBPriv(f.Rest)
	if err != nil {
		t.Fatal(err)
	}
	clear, err := p.Decrypt(key, priv.EncPart.Cipher,
		crypto.UsageKRBPrivEncPart)
	if err != nil {
		t.Fatal(err)
	}
	part, err := wire.UnmarshalEncKRBPrivPart(clear)
	if err != nil {
		t.Fatal(err)
	}
	if part.SeqNumber != want {
		t.Errorf("the KRB-PRIV says %d and the AP-REP %d",
			part.SeqNumber, want)
	}
	if want == 0 {
		t.Error("no sequence number in the reply")
	}
}

// A successful change clears the bit that demanded it, which upstream
// does in the same place (svr_principal.c:1298).
//
// Leaving it set is invisible from the server's side and fatal from
// the client's: kinit notices the expiry, gets a ticket for the
// password service because the policy excuses it, changes the
// password, retries the login -- and is told the password has expired
// again, because it has. A stock kinit is what found it, and this is
// the in-process case so it stays found.
func TestChangePWClearsTheChangeRequirement(t *testing.T) {
	k := testKDC(t)
	ctx := ctxFor(t)
	user, err := k.Store.Lookup(ctx, "user@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
	user.Attributes |= store.AttrRequiresPWChange
	if err := k.Store.Save(ctx, user); err != nil {
		t.Fatal(err)
	}
	tkt, session := changepwTicketForExpired(t, k)
	reply := k.ChangePW(changePWRequest(t, tkt, session,
		wire.ChangePWVersion1, []byte("cleared-the-bit")))
	if code, text := changePWResult(t, reply,
		session); code != wire.KPasswdSuccess {
		t.Fatalf("code %d: %s", code, text)
	}
	after, err := k.Store.Lookup(ctx, "user@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
	if after.Attributes&store.AttrRequiresPWChange != 0 {
		t.Error("the change requirement is still set")
	}
	// And an ordinary login works again, which is the thing the
	// client was trying to do all along.
	if _, kerr := as(t, k, asRequest(
		[]string{"user"})); kerr != nil {
		t.Errorf("an ordinary login is still refused: %v",
			kerr)
	}
}

// changepwTicketForExpired gets the one ticket a principal whose
// password must change is still allowed: the service has to carry
// PWCHANGE_SERVICE or the exemption that lets an expired password
// reach it never applies.
func changepwTicketForExpired(
	t *testing.T, k *KDC,
) (wire.Ticket, []byte) {
	t.Helper()
	addPrincipal(t, k.Store, localMasterKey(t),
		[]string{adminName, changepwName}, "adminpassword",
		store.AttrPWChangeService)
	req := asRequest([]string{"user"})
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: []string{adminName, changepwName},
	}
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("the AS refused a changepw ticket: %v", kerr)
	}
	return rep.Ticket, decodeReply(t, k, rep).Key.KeyValue
}

// An administrator with the c privilege can now set somebody else's
// password, which is the RFC 3244 form the access-control list
// unblocked.
//
// The ticket is for kadmin/changepw like every other request to this
// service -- upstream names that principal explicitly when reading
// the AP-REQ (schpw.c:118-130) -- and what distinguishes an
// administrator is the list, not the service. No initial ticket is
// needed either: an administrator is not proving who they are to the
// password service, they are proving they are an administrator.
func TestSetPasswordForAnotherPrincipal(t *testing.T) {
	k := testKDC(t)
	k.AdminACL = testACL(t, "user@"+testRealm+" c")
	tkt, session := adminTicketFromTGT(t, k, changepwName)

	reply := k.ChangePW(setPasswordFor(t, tkt, session,
		"preauth", "set-from-outside"))
	code, text := changePWResult(t, reply, session)
	if code != wire.KPasswdSuccess {
		t.Fatalf("code %d: %s", code, text)
	}
	assertPrincipalPassword(t, k, "preauth",
		"set-from-outside")
}

// Without the privilege it is refused, and the principal is left
// alone -- which is the half that matters, because a surface that let
// any authenticated principal re-key any other would be worse than
// one that did not do it at all.
func TestSetPasswordWithoutThePrivilege(t *testing.T) {
	k := testKDC(t)
	k.AdminACL = testACL(t, "user@"+testRealm+" i")
	tkt, session := adminTicketFromTGT(t, k, changepwName)

	reply := k.ChangePW(setPasswordFor(t, tkt, session,
		"preauth", "should-not-take"))
	code, _ := changePWResult(t, reply, session)
	if code != wire.KPasswdAccessDenied {
		t.Errorf("code %d, want ACCESSDENIED", code)
	}
	assertPrincipalPassword(t, k, "preauth", userPassword)
}

// And an ACL entry naming a different client does not help.
func TestSetPasswordForSomebodyElsesEntry(t *testing.T) {
	k := testKDC(t)
	k.AdminACL = testACL(t, "somebody@"+testRealm+" c")
	tkt, session := adminTicketFromTGT(t, k, changepwName)

	reply := k.ChangePW(setPasswordFor(t, tkt, session,
		"preauth", "should-not-take"))
	code, _ := changePWResult(t, reply, session)
	if code != wire.KPasswdAccessDenied {
		t.Errorf("code %d, want ACCESSDENIED", code)
	}
}

// testACL parses one, with the attribute table installed the way
// internal/config installs it.
func testACL(t *testing.T, spec string) acl.ACL {
	t.Helper()
	acl.SetAttrFunc(store.AttrMask)
	a, err := acl.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// setPasswordFor builds an RFC 3244 frame naming a target.
func setPasswordFor(
	t *testing.T,
	tkt wire.Ticket,
	session []byte,
	target, password string,
) []byte {
	t.Helper()
	data, err := wire.MarshalChangePasswdData(
		wire.ChangePasswdData{
			NewPassword: []byte(password),
			TargName: &wire.PrincipalName{
				Type:       wire.NTPrincipal,
				Components: []string{target},
			},
			TargRealm: testRealm,
		})
	if err != nil {
		t.Fatal(err)
	}
	return changePWRequest(t, tkt, session,
		wire.ChangePWVersionSet, data)
}

// assertPrincipalPassword checks a principal's stored key is what the
// password derives, which is the only thing that proves a change
// reached the database in the form a client computes.
func assertPrincipalPassword(
	t *testing.T, k *KDC, name, password string,
) {
	t.Helper()
	p, err := k.Store.Lookup(ctxFor(t), name+"@"+testRealm)
	if err != nil {
		t.Fatal(err)
	}
	start := 0
	row, key, err := k.Store.Key(p, &start,
		int32(crypto.AES256CTSHMACSHA196),
		store.AnySaltType, store.HighestKVNO)
	if err != nil {
		t.Fatal(err)
	}
	prof, err := crypto.Profile(crypto.EncType(row.EType))
	if err != nil {
		t.Fatal(err)
	}
	want, err := prof.StringToKey(password,
		crypto.Salt(testRealm, []string{name}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != string(want) {
		t.Errorf("%s's key is not %q's", name, password)
	}
}
