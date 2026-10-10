package golden

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FatmanUK/diamond_krb/internal/acl"
	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"github.com/FatmanUK/diamond_krb/internal/kadm5"
	"github.com/FatmanUK/diamond_krb/internal/spnego"
	"github.com/FatmanUK/diamond_krb/internal/store"
	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// adminTicket gets a service ticket for kadmin/admin the way `kinit
// -S kadmin/admin' would -- straight out of an AS exchange, which is
// the only way to get one carrying TKT_FLG_INITIAL.
func adminTicket(
	t *testing.T,
	d *Diamond,
	client string,
) (wire.Ticket, []byte) {
	t.Helper()
	req := asRequest(t, client,
		time.Now().UTC().Add(time.Hour))
	req.Body.SName = &wire.PrincipalName{
		Type:       wire.NTSrvInst,
		Components: AdminName,
	}
	raw, err := d.AS(req)
	if err != nil {
		t.Fatal(err)
	}
	rep := decodeReply(t, raw)
	enc := decryptEnc(t, rep, UserPassword,
		[]string{client})
	return rep.Ticket, enc.Key.KeyValue
}

// adminToken builds the SPNEGO token a client would put in an
// Authorization header: a NegTokenInit offering Kerberos, wrapping an
// RFC 4121 AP-REQ for kadmin/admin.
//
// Mutual authentication and an 0x8003 checksum are both set, because
// that is what a real GSS initiator sends and what B7a's capture
// shows.
func adminToken(
	t *testing.T,
	d *Diamond,
	client string,
) string {
	t.Helper()
	tkt, session := adminTicket(t, d, client)
	return encodeToken(t, gssToken(t, tkt, session, client))
}

// gssToken is the NegTokenInit itself.
func gssToken(
	t *testing.T,
	tkt wire.Ticket,
	session []byte,
	client string,
) []byte {
	t.Helper()
	der := adminAPReq(t, tkt, session, client)
	return spnego.NegTokenInit{
		MechTypes: []spnego.OID{spnego.MechKrb5},
		MechToken: spnego.MechToken{
			Mech:  spnego.MechKrb5,
			TokID: spnego.TokIDAPReq,
			Body:  der,
		}.Marshal(),
	}.Marshal()
}

// encodeToken is RFC 4559's encoding: standard base64, padded.
func encodeToken(t *testing.T, token []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(token)
}

// adminAPReq builds and seals the AP-REQ.
func adminAPReq(
	t *testing.T,
	tkt wire.Ticket,
	session []byte,
	client string,
) []byte {
	t.Helper()
	cksum := &spnego.Checksum{
		Flags: spnego.FlagMutual | spnego.FlagInteg,
	}
	now := time.Now().UTC()
	auth := wire.Authenticator{
		CRealm: Realm,
		CName: wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: []string{client},
		},
		CTime: now.Truncate(time.Second),
		CUsec: int32(now.Nanosecond() / 1000),
		Cksum: &wire.Checksum{
			Type:     spnego.CksumTypeGSSCB,
			Checksum: cksum.Marshal(),
		},
	}
	return sealAPReq(t, tkt, session, auth)
}

// sealAPReq encrypts an authenticator at key usage 11 and encodes the
// AP-REQ around it.
func sealAPReq(
	t *testing.T,
	tkt wire.Ticket,
	session []byte,
	auth wire.Authenticator,
) []byte {
	t.Helper()
	p, err := crypto.Profile(crypto.AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := wire.MarshalAuthenticator(auth)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.Encrypt(session, plain, crypto.UsageAPReqAuth)
	if err != nil {
		t.Fatal(err)
	}
	der, err := wire.MarshalAPReq(wire.APReq{
		Options: wire.APOptMutualRequired,
		Ticket:  tkt,
		Authenticator: wire.EncryptedData{
			EType:  int32(crypto.AES256CTSHMACSHA196),
			Cipher: ct,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// kadm5Server stands the administrative surface up over a provisioned
// realm.
func kadm5Server(
	t *testing.T,
	d *Diamond,
	aclSpec string,
) *httptest.Server {
	t.Helper()
	// The attribute table has to be installed before an ACL with
	// restrictions will parse, which internal/config does for the
	// real process (parseTables) and which a test standing the
	// surface up directly has to do for itself. acl depends on
	// nothing, so the table reaches it as a function rather than
	// an import.
	acl.SetAttrFunc(store.AttrMask)
	a, err := acl.Parse(aclSpec)
	if err != nil {
		t.Fatalf("the ACL %q: %v", aclSpec, err)
	}
	mux := http.NewServeMux()
	mux.Handle(kadm5.Prefix, &kadm5.Server{
		KDC:   d.KDC,
		Store: d.Store,
		ACL:   a,
		Realm: Realm,
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// call makes one request, with a token unless tok is empty.
func call(
	t *testing.T,
	s *httptest.Server,
	verb, tok string,
	body any,
) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(
			body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(http.MethodPost,
		s.URL+kadm5.Prefix+verb, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Negotiate "+tok)
	}
	res, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

// The RFC 4559 handshake, which is the whole reason the surface is
// shaped this way: a client sends nothing, is told to negotiate, and
// retries with a token.
//
// `curl --negotiate -u :' does exactly this, and a surface that
// skipped the challenge would be unreachable by it -- curl does not
// send a Negotiate header until it has been asked for one.
func TestTheNegotiateChallenge(t *testing.T) {
	d := diamond(t, "kd_kadm5_challenge", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")

	res, body := call(t, s, "getprinc", "", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	if got := res.Header.Get("WWW-Authenticate"); got !=
		"Negotiate" {
		t.Errorf("challenge is %q", got)
	}
	if body["error"] == nil {
		t.Error("no reason was given")
	}
	// And then with a token it works.
	res, body = call(t, s, "getprinc",
		adminToken(t, d, UserName),
		map[string]string{"principal": UserName})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v", res.StatusCode, body)
	}
	if body["principal"] != UserName+"@"+Realm {
		t.Errorf("got %v", body["principal"])
	}
	// The AP-REP comes back in the same header, which is how a
	// client with mutual authentication on checks the server.
	got := res.Header.Get("WWW-Authenticate")
	if len(got) < len("Negotiate ") {
		t.Fatalf("no reply token: %q", got)
	}
	assertAPRepHeader(t, got)
}

// assertAPRepHeader checks the reply token really is an AP-REP.
func assertAPRepHeader(t *testing.T, header string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(
		header[len("Negotiate "):])
	if err != nil {
		t.Fatalf("the reply token is not base64: %v", err)
	}
	r, err := spnego.UnmarshalNegTokenResp(raw)
	if err != nil {
		t.Fatalf("the reply token: %v", err)
	}
	if r.State != spnego.AcceptComplete {
		t.Errorf("negState %d", r.State)
	}
	tok, err := spnego.ParseMechToken(r.ResponseToken)
	if err != nil {
		t.Fatalf("the responseToken: %v", err)
	}
	if tok.TokID != spnego.TokIDAPRep {
		t.Errorf("token id %#x", tok.TokID)
	}
}

// An authenticated client the ACL does not permit gets **403 and not
// 401**, and the distinction is the point: a client told 401 should
// try to authenticate differently and one told 403 should not,
// because it authenticated perfectly well and simply may not do this.
// Conflating them puts a client in a retry loop against an ACL.
func TestTheACLRefusesWithoutAskingAgain(t *testing.T) {
	d := diamond(t, "kd_kadm5_acl", time.Now().UTC)
	// An ACL naming somebody else entirely.
	s := kadm5Server(t, d, "nobody@"+Realm+" *")

	res, _ := call(t, s, "getprinc",
		adminToken(t, d, UserName),
		map[string]string{"principal": PreauthName})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", res.StatusCode)
	}
	// The AP-REP still comes back, because the client *did*
	// authenticate and RFC 4559 puts the final token on whatever
	// response completes the handshake. What must not come back
	// is a bare `Negotiate' challenge, which is an invitation to
	// try again.
	if got := res.Header.Get("WWW-Authenticate"); got ==
		"Negotiate" {
		t.Errorf("a refusal asked to negotiate again")
	}
}

// But a principal may read **itself** with no ACL line at all, which
// is upstream's self module (auth_self.c:40-46) and which B3 already
// relies on for password changes.
func TestAPrincipalMayAlwaysReadItself(t *testing.T) {
	d := diamond(t, "kd_kadm5_self", time.Now().UTC)
	s := kadm5Server(t, d, "")

	tok := adminToken(t, d, UserName)
	res, body := call(t, s, "getprinc", tok,
		map[string]string{"principal": UserName})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v", res.StatusCode, body)
	}
	// And still not anybody else.
	res, _ = call(t, s, "getprinc",
		adminToken(t, d, UserName),
		map[string]string{"principal": PreauthName})
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", res.StatusCode)
	}
}

// A replayed Authorization header is refused, and the body says so
// rather than saying "authentication failed": an administrator
// debugging one needs to know which of expired, replayed and unknown
// it was.
//
// This is the case the whole replay table exists for, and TLS does
// not cover it: the second request arrives over a perfectly good new
// connection.
func TestAReplayedHeaderIsRefused(t *testing.T) {
	d := diamond(t, "kd_kadm5_replay", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")

	tok := adminToken(t, d, UserName)
	arg := map[string]string{"principal": UserName}
	if res, body := call(t, s, "getprinc", tok, arg); res.
		StatusCode != http.StatusOK {
		t.Fatalf("the first call: %d %v", res.StatusCode,
			body)
	}
	res, body := call(t, s, "getprinc", tok, arg)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", res.StatusCode)
	}
	if got, _ := body["error"].(string); got !=
		"the request was replayed" {
		t.Errorf("reason is %q", got)
	}
}

// Every read operation, through the surface, with an ACL that permits
// them.
func TestTheReadOperations(t *testing.T) {
	d := diamond(t, "kd_kadm5_read", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	for _, c := range []struct {
		verb string
		arg  any
		key  string
	}{
		{"getprinc", map[string]string{
			"principal": UserName}, "principal"},
		{"get_principal", map[string]string{
			"principal": UserName}, "principal"},
		{"listprincs", nil, "principals"},
		{"getstrs", map[string]string{
			"principal": UserName}, "strings"},
		{"getpols", nil, "policies"},
		{"getprivs", nil, "privs"},
	} {
		t.Run(c.verb, func(t *testing.T) {
			res, body := call(t, s, c.verb,
				adminToken(t, d, UserName), c.arg)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d: %v",
					res.StatusCode, body)
			}
			if _, ok := body[c.key]; !ok {
				t.Errorf("no %q in %v", c.key, body)
			}
		})
	}
}

// getprinc reports the lockout state resolved against the policy,
// which kadmin cannot do: upstream's lockout rules live in each
// database back end rather than in the administrative server, so
// kadm5_get_principal hands back a raw counter and leaves the
// operator to apply the policy by hand. One back end means one place
// for the rules and so an answer worth reporting.
func TestGetPrincReportsTheResolvedLockout(t *testing.T) {
	d := diamond(t, "kd_kadm5_lock", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	res, body := call(t, s, "getprinc",
		adminToken(t, d, UserName),
		map[string]string{"principal": UserName})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v", res.StatusCode, body)
	}
	if _, ok := body["locked"]; !ok {
		t.Errorf("no lockout state in %v", body)
	}
}

// The refusals that are not about authentication at all.
func TestTheSurfaceRefusesNonsense(t *testing.T) {
	d := diamond(t, "kd_kadm5_nonsense", time.Now().UTC)
	s := kadm5Server(t, d, "*@"+Realm+" *")
	tok := adminToken(t, d, UserName)

	// An unknown verb is answered before authentication, because
	// it is not a secret.
	if res, _ := call(t, s, "frobnicate", "", nil); res.
		StatusCode != http.StatusNotFound {
		t.Errorf("unknown verb: %d", res.StatusCode)
	}
	// A GET is not accepted, and the Allow header says so.
	res, err := s.Client().Get(s.URL + kadm5.Prefix +
		"getprinc")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", res.StatusCode)
	}
	if res.Header.Get("Allow") != http.MethodPost {
		t.Errorf("Allow is %q", res.Header.Get("Allow"))
	}
	// A principal that is not there is 404 and not 500.
	res2, _ := call(t, s, "getprinc", tok,
		map[string]string{"principal": "nobody"})
	if res2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown principal: %d", res2.StatusCode)
	}
}
