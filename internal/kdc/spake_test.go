package kdc

import (
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/spake"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// spakeKDC is a test KDC with SPAKE switched on.
//
// It has to be switched on explicitly, because the default is off and
// that default is upstream's: DEFAULT_GROUPS_KDC is the empty string
// (groups.c:59-60), so a stock realm offers no SPAKE until configured
// to.
func spakeKDC(t *testing.T) *KDC {
	t.Helper()
	k := testKDC(t)
	k.SPAKEGroups = []int32{spake.GroupEdwards25519}
	return k
}

// spakeRequest is an AS-REQ carrying one PA-SPAKE value.
func spakeRequest(
	t *testing.T,
	value []byte,
	cookie *wire.PAData,
) wire.ASReq {
	t.Helper()
	req := asRequest([]string{"preauth"})
	req.PAData = []wire.PAData{
		{Type: spake.PAType, Value: value},
	}
	if cookie != nil {
		req.PAData = append(req.PAData, *cookie)
	}
	return req
}

// supportMessage is what a client opens with.
func supportMessage(t *testing.T) []byte {
	t.Helper()
	der, err := spake.MarshalMessage(spake.Message{
		Type: spake.MsgSupport,
		Support: &spake.Support{
			Groups: []int32{spake.GroupEdwards25519},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A support message earns a challenge and a cookie, and the error
// code is **not** a failure: KDC_ERR_MORE_PREAUTH_DATA_REQUIRED is
// the one code that means "keep going", and upstream turns the
// successful construction of a challenge into it on purpose
// (send_challenge, spake_kdc.c:290-292).
func TestASupportMessageEarnsAChallenge(t *testing.T) {
	k := spakeKDC(t)
	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("a ticket was issued from a support message")
	}
	if kerr.ErrorCode != wire.ErrCodeMorePreauthData {
		t.Fatalf("code %d, want MORE_PREAUTH_DATA_REQUIRED",
			kerr.ErrorCode)
	}
	ch, cookie := spakeChallengeOf(t, kerr)
	if ch.Group != spake.GroupEdwards25519 {
		t.Errorf("group is %d", ch.Group)
	}
	if len(ch.PubKey) != spake.ElemLen {
		t.Errorf("pubkey is %d octets", len(ch.PubKey))
	}
	if len(ch.Factors) != 1 ||
		ch.Factors[0].Type != spake.SFNone {
		t.Errorf("factors are %v", ch.Factors)
	}
	// The cookie is a real MIT1 one now, not the three constant
	// octets: SPAKE is the first mechanism here that has state to
	// put in it.
	if len(cookie.Value) <= 8 ||
		string(cookie.Value[:4]) != "MIT1" {
		t.Errorf("cookie is % x", cookie.Value)
	}
}

// spakeChallengeOf pulls the challenge and the cookie out of a
// refusal's e-data.
func spakeChallengeOf(
	t *testing.T,
	kerr *wire.KRBError,
) (*spake.Challenge, wire.PAData) {
	t.Helper()
	pas, err := wire.UnmarshalPADataSeq(kerr.EData)
	if err != nil {
		t.Fatalf("e-data: %v", err)
	}
	sp := findPAData(pas, spake.PAType)
	cookie := findPAData(pas, wire.PAFXCookie)
	if sp == nil || cookie == nil {
		t.Fatalf("e-data is %+v", pas)
	}
	m, err := spake.UnmarshalMessage(sp.Value)
	if err != nil {
		t.Fatalf("the challenge: %v", err)
	}
	if m.Type != spake.MsgChallenge || m.Challenge == nil {
		t.Fatalf("got message type %d", m.Type)
	}
	return m.Challenge, *cookie
}

// The whole exchange, driven from the client's side: support,
// challenge, response, ticket.
//
// This is the test that matters, because every step of the derivation
// has to agree for the last one to work. The client derives the
// multiplier from its own password, masks with N where the KDC masked
// with M, computes the same shared element, extends the same
// transcript hash, derives the same K'[1] to seal its factor with and
// the same K'[0] -- and the reply only opens with K'[0], so the
// ticket coming back and decrypting is the assertion.
func TestTheWholeSPAKEExchange(t *testing.T) {
	k := spakeKDC(t)
	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("no challenge")
	}
	ch, cookie := spakeChallengeOf(t, kerr)

	final := spakeRequest(t, nil, &cookie)
	resp, k0 := clientResponse(t, k, ch, bodyOf(t, final))
	rep, kerr := as(t, k, spakeRequest(t, resp, &cookie))
	if kerr != nil {
		t.Fatalf("the response was refused: %v (%s)",
			kerr.ErrorCode, kerr.EText)
	}
	assertOpensWith(t, rep, k0)
	// And the ticket records that the client proved knowledge of
	// its key.
	tkt := decodeTicket(t, k, rep)
	if !tkt.Flags.Has(wire.FlagPreAuthent) {
		t.Error("the ticket is not marked pre-authenticated")
	}
}

// clientResponse plays the client's half and returns the response
// message with the reply key it expects.
func clientResponse(
	t *testing.T,
	k *KDC,
	ch *spake.Challenge,
	body []byte,
) ([]byte, []byte) {
	t.Helper()
	e := crypto.AES256CTSHMACSHA196
	ikey := clientKey(t, []string{"preauth"}, userPassword, e)
	w, err := spake.DeriveW(ikey, e, ch.Group)
	if err != nil {
		t.Fatal(err)
	}
	// The client masks with N, which is useM false.
	priv, pub, err := spake.Keygen(w, false)
	if err != nil {
		t.Fatal(err)
	}
	element, err := spake.Result(priv, w, ch.PubKey, true)
	if err != nil {
		t.Fatal(err)
	}
	return buildResponse(t, ch, ikey, e, w, element, pub,
		body)
}

// buildResponse seals the client's factor and derives the keys.
//
// The transcript hash has to be rebuilt exactly as the KDC built it
// -- the support message as sent, the challenge as received, then
// this side's element -- which is why the support message is
// re-encoded here rather than remembered: it is deterministic, and
// the KDC hashed the octets it received.
func buildResponse(
	t *testing.T,
	ch *spake.Challenge,
	ikey []byte,
	e crypto.EncType,
	w, element, pub, body []byte,
) ([]byte, []byte) {
	t.Helper()
	chDER, err := spake.MarshalMessage(spake.Message{
		Type: spake.MsgChallenge, Challenge: ch,
	})
	if err != nil {
		t.Fatal(err)
	}
	thash := spake.UpdateThash(nil, supportMessage(t), chDER)
	thash = spake.UpdateThash(thash, pub, nil)
	k1, err := spake.DeriveKey(ikey, e, ch.Group, w, element,
		thash, body, 1)
	if err != nil {
		t.Fatal(err)
	}
	k0, err := spake.DeriveKey(ikey, e, ch.Group, w, element,
		thash, body, 0)
	if err != nil {
		t.Fatal(err)
	}
	return sealResponse(t, e, k1, pub), k0
}

// bodyOf is the encoded request body the derivation hashes.
//
// It has to be the body of the **request the response travels in**,
// not of any request: DeriveKey hashes it, so a key derived against
// one body does not open a reply to another. That is the binding
// working, and it is what the service-ticket case below trips over if
// the test is careless.
func bodyOf(t *testing.T, req wire.ASReq) []byte {
	t.Helper()
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := wire.ReqBodyBytes(msg)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// sealResponse encodes and seals the response message.
func sealResponse(
	t *testing.T,
	e crypto.EncType,
	k1, pub []byte,
) []byte {
	t.Helper()
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := spake.MarshalFactor(spake.Factor{
		Type: spake.SFNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(k1, factor, spake.UsageSPAKE)
	if err != nil {
		t.Fatal(err)
	}
	der, err := spake.MarshalMessage(spake.Message{
		Type: spake.MsgResponse,
		Response: &spake.Response{
			PubKey: pub,
			Factor: wire.EncryptedData{
				EType:  int32(e),
				Cipher: ct,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// assertOpensWith insists the reply's enc-part opens with a key.
func assertOpensWith(
	t *testing.T,
	rep *wire.ASRep,
	key []byte,
) {
	t.Helper()
	p, err := crypto.Profile(
		crypto.EncType(rep.EncPart.EType))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("the reply did not open with K'[0]: %v",
			err)
	}
	if _, err := wire.UnmarshalEncKDCRepPart(
		plain); err != nil {
		t.Fatal(err)
	}
}

// A wrong password is a failed decryption of the factor field and
// nothing more informative than that.
//
// It is the whole point of the exchange: K'[1] depends on the shared
// element, which depends on the multiplier, which depends on the
// client's long-term key. A client that guessed wrong derives a
// different K'[1], the integrity check fails, and upstream translates
// that into KDC_ERR_PREAUTH_FAILED rather than reporting corruption
// (spake_kdc.c:428-431) -- so an attacker learns only that the guess
// was wrong, which they knew.
func TestAWrongPasswordFailsTheFactor(t *testing.T) {
	k := spakeKDC(t)
	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("no challenge")
	}
	ch, cookie := spakeChallengeOf(t, kerr)

	// The same exchange with a different password.
	e := crypto.AES256CTSHMACSHA196
	wrong := clientKey(t, []string{"preauth"},
		"not-the-password", e)
	w, err := spake.DeriveW(wrong, e, ch.Group)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := spake.Keygen(w, false)
	if err != nil {
		t.Fatal(err)
	}
	element, err := spake.Result(priv, w, ch.PubKey, true)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := buildResponse(t, ch, wrong, e, w, element, pub,
		bodyOf(t, spakeRequest(t, nil, &cookie)))
	_, kerr = as(t, k, spakeRequest(t, resp, &cookie))
	if kerr == nil {
		t.Fatal("a wrong password was accepted")
	}
	if kerr.ErrorCode != wire.ErrCodePreauthFailed {
		t.Errorf("code %d, want PREAUTH_FAILED",
			kerr.ErrorCode)
	}
}

// A response with no cookie behind it is refused: the KDC's private
// scalar is in the cookie, so without one there is nothing to compute
// against. This is the crash-only rule showing through -- there is no
// session to fall back on.
func TestAResponseWithNoCookieIsRefused(t *testing.T) {
	k := spakeKDC(t)
	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("no challenge")
	}
	ch, _ := spakeChallengeOf(t, kerr)
	resp, _ := clientResponse(t, k, ch,
		bodyOf(t, spakeRequest(t, nil, nil)))
	_, kerr = as(t, k, spakeRequest(t, resp, nil))
	if kerr == nil {
		t.Fatal("accepted")
	}
	if kerr.ErrorCode != wire.ErrCodePreauthFailed {
		t.Errorf("code %d", kerr.ErrorCode)
	}
}

// A cookie made for one principal does not work for another, because
// the client's name is in the key derivation (derive_cookie_key,
// fast_util.c:508-532). Without that, a cookie handed to one
// principal could be replayed by any other.
func TestACookieIsBoundToItsPrincipal(t *testing.T) {
	k := spakeKDC(t)
	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("no challenge")
	}
	_, cookie := spakeChallengeOf(t, kerr)
	// The same cookie presented by `user' rather than `preauth'.
	req := asRequest([]string{"user"})
	req.PAData = []wire.PAData{
		{Type: spake.PAType, Value: supportMessage(t)},
		cookie,
	}
	// A support message is answered with a fresh challenge
	// whatever the cookie says, so the cookie's unreadability has
	// to be checked where it is read: on a response.
	pas, err := wire.UnmarshalPADataSeq(kerr.EData)
	if err != nil {
		t.Fatal(err)
	}
	_ = pas
	s := &asState{req: req, cname: *req.Body.CName}
	if _, _, err := k.readCookie(s); err == nil {
		t.Error("another principal read the cookie")
	}
}

// refusedCase is a PA-SPAKE value the KDC will not act on.
type refusedCase struct {
	why   string
	value func(*testing.T) []byte
}

// refusedMessages is every PA-SPAKE value this KDC turns away.
//
// Two of the four message types are refused by kind rather than by
// content: a challenge is a message the *KDC* sends, and an EncData
// is a second-factor round which upstream also refuses outright
// (verify_encdata, spake_kdc.c:481-498 is a comment and a refusal).
func refusedMessages() []refusedCase {
	return []refusedCase{
		{"not a message at all",
			func(*testing.T) []byte {
				return []byte{0x30, 0x00}
			}},
		{"a challenge, which the KDC sends", challengeMsg},
		{"a second-factor round nobody implements",
			encDataMsg},
		{"no common group", otherGroupsMsg},
	}
}

// challengeMsg is a challenge sent the wrong way.
func challengeMsg(t *testing.T) []byte {
	t.Helper()
	return mustMessage(t, spake.Message{
		Type: spake.MsgChallenge,
		Challenge: &spake.Challenge{
			Group:  spake.GroupEdwards25519,
			PubKey: make([]byte, spake.ElemLen),
		},
	})
}

// encDataMsg is a second-factor round.
func encDataMsg(t *testing.T) []byte {
	t.Helper()
	return mustMessage(t, spake.Message{
		Type: spake.MsgEncData,
		EncData: &wire.EncryptedData{
			EType:  int32(crypto.AES256CTSHMACSHA196),
			Cipher: []byte("x"),
		},
	})
}

// otherGroupsMsg offers only groups this realm does not have.
func otherGroupsMsg(t *testing.T) []byte {
	t.Helper()
	return mustMessage(t, spake.Message{
		Type: spake.MsgSupport,
		Support: &spake.Support{
			Groups: []int32{2, 3, 4},
		},
	})
}

// mustMessage encodes or fails.
func mustMessage(t *testing.T, m spake.Message) []byte {
	t.Helper()
	der, err := spake.MarshalMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Every one of them is KDC_ERR_PREAUTH_FAILED and nothing more
// informative, which is the only refusal this mechanism gives.
func TestTheSPAKEMessagesTheKDCRefuses(t *testing.T) {
	k := spakeKDC(t)
	for _, c := range refusedMessages() {
		t.Run(c.why, func(t *testing.T) {
			_, kerr := as(t, k,
				spakeRequest(t, c.value(t), nil))
			if kerr == nil {
				t.Fatal("accepted")
			}
			if kerr.ErrorCode !=
				wire.ErrCodePreauthFailed {
				t.Errorf("code %d", kerr.ErrorCode)
			}
		})
	}
}

// A successful exchange asserts whatever indicators the realm
// configured, which is what lets a service insist on SPAKE through
// require_auth.
//
// Empty is upstream's default and means SPAKE still strengthens the
// reply key and still says nothing about it in the ticket -- so a
// realm that wants services to be able to demand SPAKE has to name an
// indicator and then set require_auth on those services.
func TestSPAKEAssertsItsIndicators(t *testing.T) {
	k := spakeKDC(t)
	k.SPAKEIndicators = []string{"strong"}
	addService(t, k, 0)
	setStringAttr(t, k, serviceName, requireAuthAttr,
		"strong")

	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("no challenge")
	}
	ch, cookie := spakeChallengeOf(t, kerr)
	req := serviceSpakeRequest(t, nil, &cookie)
	resp, _ := clientResponse(t, k, ch, bodyOf(t, req))
	req = serviceSpakeRequest(t, resp, &cookie)
	if _, kerr := as(t, k, req); kerr != nil {
		t.Fatalf("a service demanding the indicator "+
			"refused: %v (%s)", kerr.ErrorCode,
			kerr.EText)
	}
	// And without the indicator configured, the same service
	// refuses.
	k.SPAKEIndicators = nil
	_, kerr = as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("no challenge")
	}
	ch, cookie = spakeChallengeOf(t, kerr)
	req = serviceSpakeRequest(t, nil, &cookie)
	resp, _ = clientResponse(t, k, ch, bodyOf(t, req))
	req = serviceSpakeRequest(t, resp, &cookie)
	if _, kerr := as(t, k, req); kerr == nil {
		t.Error("the service accepted without the indicator")
	}
}

// serviceSpakeRequest is spakeRequest asking for a service ticket
// rather than a TGT, which the indicator case needs: require_auth
// lives on a service and is checked against the server of the
// request.
func serviceSpakeRequest(
	t *testing.T,
	value []byte,
	cookie *wire.PAData,
) wire.ASReq {
	t.Helper()
	req := spakeRequest(t, value, cookie)
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvHst,
		Components: serviceName,
	}
	return req
}

// A realm configured for SPAKE advertises it, between the factor and
// the cookie, and the value is empty.
//
// Empty says the mechanism is available and nothing more: upstream's
// spake_edata returns an empty padata whenever no optimistic
// challenge is configured (spake_kdc.c:316-323), and this KDC
// configures none -- an optimistic challenge saves a round trip by
// guessing the group before the client has said what it has, and
// guessing wrong costs two.
func TestAConfiguredRealmAdvertisesSPAKE(t *testing.T) {
	k := spakeKDC(t)
	_, kerr := as(t, k, asRequest([]string{"preauth"}))
	if kerr == nil {
		t.Fatal("issued a ticket without preauth")
	}
	hints, err := wire.UnmarshalPADataSeq(kerr.EData)
	if err != nil {
		t.Fatal(err)
	}
	// SPAKE comes **before** the factor, which is the order the
	// modules are registered in (kdc_preauth.c:134-141) and which
	// matters because a client takes the first mechanism it
	// understands.
	want := []int32{
		wire.PAFXFast, wire.PAETypeInfo2, spake.PAType,
		wire.PAEncTimestamp, wire.PAFXCookie,
	}
	if len(hints) != len(want) {
		t.Fatalf("got %d hints: %+v", len(hints), hints)
	}
	for i, w := range want {
		if hints[i].Type != w {
			t.Errorf("hint %d is %d, want %d", i,
				hints[i].Type, w)
		}
	}
	sp := findPAData(hints, spake.PAType)
	if sp == nil || len(sp.Value) != 0 {
		t.Errorf("the advertisement carries %v", sp)
	}
}

// And a realm that offers none ignores a PA-SPAKE value that arrives
// anyway, falling through to the ordinary factors rather than
// engaging a mechanism it does not have.
func TestAnUnconfiguredRealmIgnoresSPAKE(t *testing.T) {
	k := testKDC(t)
	_, kerr := as(t, k,
		spakeRequest(t, supportMessage(t), nil))
	if kerr == nil {
		t.Fatal("issued a ticket")
	}
	// PREAUTH_REQUIRED, not MORE_PREAUTH_DATA_REQUIRED: the value
	// was ignored and the ordinary refusal followed.
	if kerr.ErrorCode != wire.ErrCodePreauthRequired {
		t.Errorf("code %d, want PREAUTH_REQUIRED",
			kerr.ErrorCode)
	}
}
