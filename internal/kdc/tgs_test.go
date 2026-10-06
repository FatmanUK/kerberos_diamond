package kdc

import (
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// serviceName is the principal a TGS-REQ asks for a ticket to.
var serviceName = []string{"host", "service.example.org"}

// getTGT runs a real AS exchange and opens the reply, so that a TGS
// test starts from a ticket this KDC actually issued rather than from
// one assembled by hand. A hand-built TGT would let a bug in the AS
// path pass unnoticed here, and the reverse.
func getTGT(t *testing.T, k *KDC) (wire.Ticket, []byte) {
	t.Helper()
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	return rep.Ticket, enc.Key.KeyValue
}

// addService provisions the service the TGS tests ask for.
func addService(t *testing.T, k *KDC, attrs uint32) {
	t.Helper()
	mkey, err := store.DeriveMasterKey(testRealm, testMasterPW,
		store.DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	addPrincipal(t, k.Store, mkey, serviceName,
		"servicepassword", attrs)
}

// tgsBody is the request body every TGS case starts from.
func tgsBody(components []string) wire.KDCReqBody {
	return wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptRenewableOK,
		Realm:   testRealm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvHst,
			Components: components,
		},
		Till:  fixedNow.Add(4 * time.Hour),
		Nonce: 0x5A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}
}

// signRequest attaches the PA-TGS-REQ and returns the encoded
// message.
//
// The body is encoded once to be checksummed and the request is then
// encoded around it, which works only because both encodings come
// from this package and therefore agree. That is exactly the
// assumption upstream declines to make: it checksums the bytes it
// received and only falls back to a re-encoding if that fails
// (kdc/kdc_util.c:246-258).
func signRequest(
	t *testing.T,
	req *wire.TGSReq,
	tgt wire.Ticket,
	sessionKey []byte,
	mutate func(*wire.Authenticator),
) []byte {
	t.Helper()
	draft, err := wire.MarshalTGSReq(*req)
	if err != nil {
		t.Fatal(err)
	}
	bodyDER, err := wire.ReqBodyBytes(draft)
	if err != nil {
		t.Fatal(err)
	}
	req.PAData = []wire.PAData{
		apReqPAData(t, tgt, sessionKey, bodyDER, mutate),
	}
	msg, err := wire.MarshalTGSReq(*req)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// tgsRequest builds a complete TGS-REQ for a service.
func tgsRequest(
	t *testing.T,
	tgt wire.Ticket,
	sessionKey []byte,
	components []string,
	mutate func(*wire.KDCReqBody),
) ([]byte, wire.TGSReq) {
	t.Helper()
	return tgsRequestAs(t, tgt, sessionKey, components,
		mutate, nil)
}

// tgsRequestAs is tgsRequest with the authenticator open to change
// too, which a cross-realm case needs: the authenticator names the
// client, and a client of another realm is not the fixture's own.
func tgsRequestAs(
	t *testing.T,
	tgt wire.Ticket,
	sessionKey []byte,
	components []string,
	body func(*wire.KDCReqBody),
	auth func(*wire.Authenticator),
) ([]byte, wire.TGSReq) {
	t.Helper()
	b := tgsBody(components)
	if body != nil {
		body(&b)
	}
	req := wire.TGSReq{Body: b}
	return signRequest(t, &req, tgt, sessionKey, auth), req
}

// aes256 is the profile every test here keys with.
func aes256(t *testing.T) *crypto.EncProfile {
	t.Helper()
	p, err := crypto.Profile(crypto.AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// authenticatorFor builds the authenticator a client would send, with
// its checksum over the request body.
func authenticatorFor(
	t *testing.T,
	p *crypto.EncProfile,
	sessionKey, bodyDER []byte,
	mutate func(*wire.Authenticator),
) wire.Authenticator {
	t.Helper()
	sum, err := p.Checksum(sessionKey, bodyDER,
		crypto.UsageTGSReqAuthCksum)
	if err != nil {
		t.Fatal(err)
	}
	auth := wire.Authenticator{
		CRealm: testRealm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{"user"},
		},
		Cksum: &wire.Checksum{
			Type:     int32(p.RequiredCksum),
			Checksum: sum,
		},
		CUsec: 1234,
		CTime: fixedNow,
	}
	if mutate != nil {
		mutate(&auth)
	}
	return auth
}

// apReqPAData builds the PA-TGS-REQ: an AP-REQ whose authenticator is
// encrypted under the presented ticket's session key.
func apReqPAData(
	t *testing.T,
	tgt wire.Ticket,
	sessionKey, bodyDER []byte,
	mutate func(*wire.Authenticator),
) wire.PAData {
	t.Helper()
	p := aes256(t)
	auth := authenticatorFor(t, p, sessionKey, bodyDER, mutate)
	plain, err := wire.MarshalAuthenticator(auth)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(sessionKey, plain,
		crypto.UsageTGSReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	apreq, err := wire.MarshalAPReq(wire.APReq{
		Ticket: tgt,
		Authenticator: wire.EncryptedData{
			EType:  int32(crypto.AES256CTSHMACSHA196),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire.PAData{Type: wire.PATGSReq, Value: apreq}
}

// openTGSRep decrypts a TGS-REP's enc-part with the TGT's session
// key.
func openTGSRep(
	t *testing.T,
	rep *wire.TGSRep,
	sessionKey []byte,
) wire.EncKDCRepPart {
	t.Helper()
	p, err := crypto.Profile(crypto.EncType(rep.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(sessionKey, rep.EncPart.Cipher,
		crypto.UsageTGSRepEncPartSessKey)
	if err != nil {
		t.Fatalf("decrypting the TGS-REP: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return enc
}

// openServiceTicket decrypts the issued ticket with the service's own
// key, as the service itself would.
func openServiceTicket(
	t *testing.T,
	rep *wire.TGSRep,
) wire.EncTicketPart {
	t.Helper()
	return decodeTicketWith(t, rep.Ticket, "servicepassword",
		serviceName)
}

// decodeTicketWith opens a ticket with a named principal's key.
func decodeTicketWith(
	t *testing.T,
	tkt wire.Ticket,
	password string,
	components []string,
) wire.EncTicketPart {
	t.Helper()
	e := crypto.EncType(tkt.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, components, password, e)
	plain, err := p.Decrypt(key, tkt.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatalf("decrypting the ticket: %v", err)
	}
	out, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatalf("EncTicketPart: %v", err)
	}
	return out
}

// headerOf opens the TGT, so a test can compare the issued ticket
// against the one it was derived from.
func headerOf(t *testing.T, tgt wire.Ticket) wire.EncTicketPart {
	t.Helper()
	return decodeTicketWith(t, tgt, "tgtpassword",
		[]string{"krbtgt", testRealm})
}

// The whole exchange: a TGT issued by the AS path is spent for a
// service ticket, and the service's own key opens it.
func TestTGSIssuesAServiceTicket(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, rep, session)
	tkt := openServiceTicket(t, rep)

	want := "host/service.example.org"
	if got := enc.SName.String(); got != want {
		t.Errorf("reply names server %q", got)
	}
	if enc.Nonce != 0x5A {
		t.Errorf("nonce is %d, want 90", enc.Nonce)
	}
	if string(tkt.Key.KeyValue) != string(enc.Key.KeyValue) {
		t.Error("the two halves carry different session keys")
	}
	// The client is whoever the TGT named, not anything in the
	// request: a TGS-REQ has no cname field at all.
	if got := tkt.CName.String(); got != "user" {
		t.Errorf("ticket client is %q", got)
	}
	if rep.CName.String() != "user" {
		t.Errorf("reply client is %q", rep.CName)
	}
}

// The authtime is carried over from the TGT rather than set to now:
// it records when the client last used a password, which spending a
// ticket does not change (do_tgs_req.c:826-827).
func TestTGSPreservesTheAuthTime(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	header := headerOf(t, tgt)

	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, rep, session)
	if !enc.AuthTime.Equal(header.AuthTime) {
		t.Errorf("authtime is %v, want the TGT's %v",
			enc.AuthTime, header.AuthTime)
	}
}

// A service ticket is not INITIAL -- it came from another ticket, not
// from a password -- but it does inherit PRE-AUTHENT, which is what
// lets a service require preauth and still be reachable.
func TestTGSTicketFlags(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, rep, session)
	if enc.Flags.Has(wire.FlagInitial) {
		t.Error("a derived ticket is marked initial")
	}
	if !enc.Flags.Has(wire.FlagForwardable) {
		t.Error("forwardable not carried through")
	}
	if !enc.Flags.Has(wire.FlagEncPARep) {
		t.Error("enc-pa-rep not set")
	}
}

// A request cannot ask for a flag the presented ticket does not have.
// The TGT here is not proxiable, so the issued ticket must not be
// either, however the request is dressed up.
func TestTGSCannotExceedTheTGTsFlags(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)

	// An AS request without OptProxiable yields a TGT without the
	// flag, which is the precondition this test needs.
	plain := asRequest([]string{"user"})
	plain.Body.Options = wire.OptForwardable
	rep, kerr := as(t, k, plain)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	asEnc := decodeReply(t, k, rep)
	if asEnc.Flags.Has(wire.FlagProxiable) {
		t.Fatal("the TGT is proxiable; this proves nothing")
	}

	msg, req := tgsRequest(t, rep.Ticket, asEnc.Key.KeyValue,
		serviceName, func(b *wire.KDCReqBody) {
			b.Options |= wire.OptProxiable
		})
	tgs, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, tgs, asEnc.Key.KeyValue)
	if enc.Flags.Has(wire.FlagProxiable) {
		t.Error("granted proxiable from a non-proxiable TGT")
	}
}

// The new ticket cannot outlive the one it was derived from. Asking
// for a till beyond the TGT's end time gets the TGT's end time.
func TestTGSEndTimeIsCappedByTheTGT(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)
	header := headerOf(t, tgt)

	msg, req := tgsRequest(t, tgt, session, serviceName,
		func(b *wire.KDCReqBody) {
			b.Till = header.EndTime.Add(100 * time.Hour)
		})
	rep, kerr := k.TGS(msg, req)
	if kerr != nil {
		t.Fatalf("TGS refused: %v", kerr)
	}
	enc := openTGSRep(t, rep, session)
	if enc.EndTime.After(header.EndTime) {
		t.Errorf("endtime %v outlives the TGT's %v",
			enc.EndTime, header.EndTime)
	}
}

// The body checksum is what stops the request being rewritten in
// flight. Altering the body after the authenticator was built must be
// refused.
func TestTGSRejectsATamperedBody(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	// The nonce lives in the body, so changing it in the decoded
	// request and re-encoding leaves the authenticator's checksum
	// covering the old bytes.
	req.Body.Nonce = 0x5B
	tampered, err := wire.MarshalTGSReq(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(tampered) != len(msg) {
		t.Fatal("the tampered request changed length")
	}
	if _, kerr := k.TGS(tampered, req); kerr == nil {
		t.Fatal("accepted a request whose body was altered")
	}
}

// An authenticator that does not decrypt under the ticket's session
// key is what a stolen ticket produces, and it must be refused.
func TestTGSRejectsAWrongSessionKey(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	wrong := append([]byte(nil), session...)
	wrong[0] ^= 0xFF
	msg, req := tgsRequest(t, tgt, wrong, serviceName, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted an authenticator under a wrong key")
	}
	if kerr.ErrorCode != wire.ErrCodeBadIntegrity {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeBadIntegrity)
	}
}

// An authenticator with no checksum is refused with INAPP_CKSUM. The
// field is optional in the ASN.1 and mandatory here, which is a KDC
// rule and not a codec one (kdc_util.c:242-245).
func TestTGSRequiresAChecksum(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	req := wire.TGSReq{Body: tgsBody(serviceName)}
	msg := signRequest(t, &req, tgt, session,
		func(a *wire.Authenticator) { a.Cksum = nil })
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted an authenticator with no checksum")
	}
	if kerr.ErrorCode != wire.ErrCodeInappCksum {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeInappCksum)
	}
}

// A clock far outside the skew is refused, and specifically as a skew
// error: a client can act on that by resynchronising.
func TestTGSRejectsASkewedAuthenticator(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	req := wire.TGSReq{Body: tgsBody(serviceName)}
	msg := signRequest(t, &req, tgt, session,
		func(a *wire.Authenticator) {
			a.CTime = fixedNow.Add(-time.Hour)
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted an hour-old authenticator")
	}
	if kerr.ErrorCode != wire.ErrCodeSkew {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeSkew)
	}
}

// An authenticator naming a different client from the ticket is
// refused with BADMATCH. Without that check, anyone holding one
// ticket's session key could claim to be someone else.
func TestTGSRejectsAMismatchedClient(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	req := wire.TGSReq{Body: tgsBody(serviceName)}
	msg := signRequest(t, &req, tgt, session,
		func(a *wire.Authenticator) {
			a.CName.Components = []string{"someone-else"}
		})
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("accepted a mismatched client name")
	}
	if kerr.ErrorCode != wire.ErrCodeBadMatch {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeBadMatch)
	}
}

// A service with +requires_preauth is reachable only because
// PRE-AUTHENT travels from the TGT. The plain user's TGT lacks it, so
// the service must refuse.
func TestTGSServiceRequiringPreauth(t *testing.T) {
	k := testKDC(t)
	addService(t, k, store.AttrRequiresPreAuth)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session, serviceName, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("reached a preauth service from a plain TGT")
	}
	// Upstream answers this with the *generic* error rather than
	// anything specific (check_tgs_svc_reqd_flags,
	// kdc/tgs_policy.c:179-185): a service's requirement is not
	// something to describe to a caller that failed it.
	if kerr.ErrorCode != wire.ErrCodeGeneric {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeGeneric)
	}
}

// A ticket for a service this realm does not have is refused with
// S_PRINCIPAL_UNKNOWN, as in the AS case.
func TestTGSUnknownService(t *testing.T) {
	k := testKDC(t)
	tgt, session := getTGT(t, k)

	msg, req := tgsRequest(t, tgt, session,
		[]string{"host", "nowhere.example.org"}, nil)
	_, kerr := k.TGS(msg, req)
	if kerr == nil {
		t.Fatal("issued a ticket for an unknown service")
	}
	if kerr.ErrorCode != wire.ErrCodeSPrincipalUnknown {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeSPrincipalUnknown)
	}
}

// Handle dispatches on the application tag, so one byte decides
// whether a message is read as an AS-REQ or a TGS-REQ. This drives
// the exchange through Handle rather than calling TGS directly.
func TestHandleDispatchesTGS(t *testing.T) {
	k := testKDC(t)
	addService(t, k, 0)
	tgt, session := getTGT(t, k)

	msg, _ := tgsRequest(t, tgt, session, serviceName, nil)
	raw, err := k.Handle(msg)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	rep, err := wire.UnmarshalTGSRep(raw)
	if err != nil {
		t.Fatalf("the reply is not a TGS-REP: %v", err)
	}
	want := "host/service.example.org"
	if got := rep.Ticket.SName.String(); got != want {
		t.Errorf("ticket names %q", got)
	}
}
