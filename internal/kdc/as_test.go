package kdc

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	testRealm    = "KDIAMOND.TEST"
	testMasterPW = "masterpassword"
	userPassword = "userpassword"
)

// fixedNow is the clock every test here runs on, so that a failure
// names a field rather than a timing difference.
var fixedNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// testKDC builds a KDC over a scratch schema with user, preauth and
// krbtgt principals in it.
func testKDC(t *testing.T) *KDC {
	t.Helper()
	base := os.Getenv("KD_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KD_TEST_DATABASE_URL is unset")
	}
	schema := "kd_kdc_" + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return '_'
	}, t.Name())

	s, mkey := openScratch(t, base, schema)
	addFixtures(t, s, mkey)
	return &KDC{
		Store:     s,
		Realm:     testRealm,
		ClockSkew: 5 * time.Minute,
		Now:       func() time.Time { return fixedNow },
	}
}

// openScratch opens a Store in a schema of its own and drops the
// schema afterwards. The schema goes in the connection string and
// never a SET search_path, for the reason internal/store's tests
// assert.
func openScratch(
	t *testing.T,
	base, schema string,
) (*store.Store, store.MasterKey) {
	t.Helper()
	admin := rawDB(t, base)
	exec(t, admin, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	exec(t, admin, "CREATE SCHEMA "+schema)

	mkey, err := store.DeriveMasterKey(testRealm, testMasterPW,
		store.DefaultMasterKeyType)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	s, err := store.Open(withSchema(t, base, schema), mkey)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		exec(t, admin, "DROP SCHEMA "+schema+" CASCADE")
	})
	return s, mkey
}

// addFixtures provisions the three principals every test here uses: a
// plain one, one that requires preauth, and the krbtgt every AS-REQ
// asks for.
func addFixtures(
	t *testing.T,
	s *store.Store,
	mkey store.MasterKey,
) {
	t.Helper()
	addPrincipal(t, s, mkey, []string{"user"}, userPassword, 0)
	addPrincipal(t, s, mkey, []string{"preauth"}, userPassword,
		store.AttrRequiresPreAuth)
	addPrincipal(t, s, mkey,
		[]string{"krbtgt", testRealm}, "tgtpassword", 0)
}

func addPrincipal(
	t *testing.T,
	s *store.Store,
	mkey store.MasterKey,
	components []string,
	password string,
	attrs uint32,
) {
	t.Helper()
	p := store.NewPrincipal(testRealm, components)
	p.Attributes = attrs
	if err := p.SetPassword(mkey, password, 1); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := s.Save(context.Background(), p); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func rawDB(t *testing.T, u string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(u), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// One connection creates and drops a schema, and `go test
	// ./...` runs enough packages at once that an unbounded pool
	// here was part of what exhausted Postgres' client limit.
	sql, err := db.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	sql.SetMaxOpenConns(2)
	sql.SetMaxIdleConns(1)
	t.Cleanup(func() { sql.Close() })
	return db
}

func exec(t *testing.T, db *gorm.DB, sql string) {
	t.Helper()
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func withSchema(t *testing.T, base, schema string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("KD_TEST_DATABASE_URL: %v", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// asRequest builds a plausible AS-REQ for a principal.
func asRequest(components []string) wire.ASReq {
	return wire.ASReq{Body: wire.KDCReqBody{
		Options: wire.OptForwardable | wire.OptProxiable |
			wire.OptRenewableOK,
		CName: &wire.PrincipalName{
			Type:       wire.NTPrincipal,
			Components: components,
		},
		Realm: testRealm,
		SName: &wire.PrincipalName{
			Type:       wire.NTSrvInst,
			Components: []string{"krbtgt", testRealm},
		},
		Till:  fixedNow.Add(10 * time.Hour),
		Nonce: 0x2A,
		EType: []int32{
			int32(crypto.AES256CTSHMACSHA196),
			int32(crypto.AES128CTSHMACSHA196),
		},
	}}
}

// as marshals a request and answers it, which is what a real caller
// does: the reply checksum is over the encoded bytes, so handing the
// KDC only the decoded structure would skip it.
func as(
	t *testing.T,
	k *KDC,
	req wire.ASReq,
) (*wire.ASRep, *wire.KRBError) {
	t.Helper()
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		t.Fatal(err)
	}
	return k.AS(msg, req)
}

// clientKey derives what a client would hold for a principal.
func clientKey(
	t *testing.T,
	components []string,
	password string,
	e crypto.EncType,
) []byte {
	t.Helper()
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key, err := p.StringToKey(password,
		crypto.Salt(testRealm, components), nil)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The whole point: a client's own long-term key must open the reply.
// Nothing short of decrypting it proves the KDC and the client agree
// about the salt, the enctype, the key usage and the layout all at
// once.
func TestASReplyOpensWithTheClientKey(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	key := clientKey(t, []string{"user"}, userPassword,
		crypto.AES256CTSHMACSHA196)
	p, err := crypto.Profile(crypto.AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the reply: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	if enc.Nonce != 0x2A {
		t.Errorf("nonce is %d, want 42", enc.Nonce)
	}
	if enc.SRealm != testRealm {
		t.Errorf("srealm is %q", enc.SRealm)
	}
	if got := enc.SName.String(); got != "krbtgt/"+testRealm {
		t.Errorf("sname is %q", got)
	}
	if len(enc.LastReq) != 1 || enc.LastReq[0].Type != 0 {
		t.Errorf("last-req is %+v", enc.LastReq)
	}
}

// The ticket is sealed under the *server's* key, with key usage 2,
// and what is inside it must agree with the reply the client can
// read. A KDC that put different times or a different session key in
// the two halves would issue a ticket no service could reconcile.
func TestTicketAgreesWithTheReply(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	tkt := decodeTicket(t, k, rep)

	if tkt.Flags != enc.Flags {
		t.Errorf("ticket flags %08X, reply %08X",
			uint32(tkt.Flags), uint32(enc.Flags))
	}
	if string(tkt.Key.KeyValue) != string(enc.Key.KeyValue) {
		t.Error("the two halves carry different session keys")
	}
	if !tkt.AuthTime.Equal(enc.AuthTime) {
		t.Errorf("authtime %v vs %v",
			tkt.AuthTime, enc.AuthTime)
	}
	if !tkt.EndTime.Equal(enc.EndTime) {
		t.Errorf("endtime %v vs %v", tkt.EndTime, enc.EndTime)
	}
	if tkt.CRealm != testRealm {
		t.Errorf("ticket crealm is %q", tkt.CRealm)
	}
}

// An AS ticket is always INITIAL, because it was issued from a
// password and not from another ticket, and always carries
// ENC-PA-REP, which get_ticket_flags sets unconditionally
// (kdc/kdc_util.c:823).
func TestASTicketFlags(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	for _, f := range []struct {
		name string
		flag wire.Flags
	}{
		{"Initial", wire.FlagInitial},
		{"EncPARep", wire.FlagEncPARep},
		{"Forwardable", wire.FlagForwardable},
		{"Proxiable", wire.FlagProxiable},
	} {
		if !enc.Flags.Has(f.flag) {
			t.Errorf("%s not set", f.name)
		}
	}
	// Nothing proved knowledge of a key, so PRE-AUTHENT must not
	// be set: a service relies on that bit to tell the two apart.
	if enc.Flags.Has(wire.FlagPreAuthent) {
		t.Error("PreAuthent set without preauth")
	}
	if enc.Flags.Has(wire.FlagInvalid) {
		t.Error("Invalid set on a non-postdated ticket")
	}
}

// starttime is dropped when it equals authtime, which is the KDC's
// rule and not the codec's (do_as_req.c:706-711). It must come back
// as authtime through EffectiveStartTime, and the end time must
// respect the requested till.
func TestASTimes(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if !enc.AuthTime.Equal(fixedNow) {
		t.Errorf("authtime is %v, want %v",
			enc.AuthTime, fixedNow)
	}
	if !enc.StartTime.IsZero() {
		t.Errorf("starttime is %v, want none",
			enc.StartTime)
	}
	if !enc.EffectiveStartTime().Equal(enc.AuthTime) {
		t.Error("effective starttime is not authtime")
	}
	if !enc.EndTime.Equal(req.Body.Till) {
		t.Errorf("endtime is %v, want %v",
			enc.EndTime, req.Body.Till)
	}
}

// renewable-ok asks politely and gets nothing unless the renew time
// would exceed the end time. Here till equals the end time, so the
// truncated renew time does not exceed it and no renewable ticket is
// issued -- the case kdc_get_ticket_renewtime:1750-1753 exists for.
func TestRenewableOKDeclinesWhenItWouldNotHelp(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if enc.Flags.Has(wire.FlagRenewable) {
		t.Error("issued a renewable ticket for renewable-ok")
	}
	if !enc.RenewTill.IsZero() {
		t.Errorf("renew-till is %v, want none",
			enc.RenewTill)
	}
}

// Asking for renewable outright gets a renewable ticket, and the flag
// and the field travel together -- the field is on the wire only
// because the flag is.
//
// Both principals have to allow a renewable life first, which is what
// the test after this one is about.
func TestRenewableIssuesARenewableTicket(t *testing.T) {
	k := testKDC(t)
	setRenewableLife(t, k, 7*24*time.Hour)
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptRenewable
	req.Body.RTime = fixedNow.Add(3 * 24 * time.Hour)
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if !enc.Flags.Has(wire.FlagRenewable) {
		t.Fatal("not renewable")
	}
	if !enc.RenewTill.Equal(req.Body.RTime) {
		t.Errorf("renew-till is %v, want %v",
			enc.RenewTill, req.Body.RTime)
	}
}

// With kadmin's defaults a renewable request gets a renewable ticket
// whose renew-till is its own start time, and that is upstream's
// behaviour rather than a bug here.
//
// kadmin creates principals with max_renewable_life *zero*
// (lib/kadm5/alt_prof.c:577-578) and kdc_get_ticket_renewtime takes a
// plain min against it (kdc/kdc_util.c:1744), so the requested renew
// time is truncated to starttime + 0. It is why "kinit -r 7d" against
// a fresh MIT realm appears to do nothing. A Go KDC that read the
// zero as "no limit" would hand out week-long renewable tickets where
// the C hands out none.
func TestRenewableLifeDefaultsToZero(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptRenewable
	req.Body.RTime = fixedNow.Add(7 * 24 * time.Hour)
	rep, kerr := as(t, k, req)
	if kerr != nil {
		t.Fatalf("AS refused: %v", kerr)
	}
	enc := decodeReply(t, k, rep)
	if !enc.Flags.Has(wire.FlagRenewable) {
		t.Error("renewable flag not set")
	}
	if !enc.RenewTill.Equal(enc.AuthTime) {
		t.Errorf("renew-till is %v, want the start time %v",
			enc.RenewTill, enc.AuthTime)
	}
}

// setRenewableLife grants every principal a renewable life, as an
// operator would with modprinc -maxrenewlife.
func setRenewableLife(t *testing.T, k *KDC, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	for _, cs := range [][]string{
		{"user"}, {"preauth"}, {"krbtgt", testRealm},
	} {
		name := store.UnparseName(testRealm, cs)
		p, err := k.Store.Lookup(ctx, name)
		if err != nil {
			t.Fatalf("Lookup %s: %v", name, err)
		}
		p.MaxRenewableLife = int32(d / time.Second)
		if err := k.Store.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", name, err)
		}
	}
}

func TestUnknownClientAndServer(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"nobody"})
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("issued a ticket to an unknown client")
	}
	if kerr.ErrorCode != wire.ErrCodeCPrincipalUnknown {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeCPrincipalUnknown)
	}

	req = asRequest([]string{"user"})
	req.Body.SName = &wire.PrincipalName{
		Components: []string{"nosuch", "service"},
	}
	_, kerr = as(t, k, req)
	if kerr == nil {
		t.Fatal("issued a ticket for an unknown service")
	}
	if kerr.ErrorCode != wire.ErrCodeSPrincipalUnknown {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeSPrincipalUnknown)
	}
}

// An AS-REQ carrying a TGS-only option is refused with BADOPTION, and
// this is the first check validate_as_request makes.
func TestTGSOnlyOptionsAreRefused(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	req.Body.Options |= wire.OptRenew
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("accepted a TGS-only option")
	}
	if kerr.ErrorCode != wire.ErrCodeBadOption {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeBadOption)
	}
}

// A request naming no enctype the client has a key for gets
// ETYPE_NOSUPP, not a ticket encrypted under something the client
// cannot read.
func TestNoUsableClientKey(t *testing.T) {
	k := testKDC(t)
	req := asRequest([]string{"user"})
	req.Body.EType = []int32{23} // rc4-hmac
	_, kerr := as(t, k, req)
	if kerr == nil {
		t.Fatal("found a key for an unsupported enctype")
	}
	if kerr.ErrorCode != wire.ErrCodeETypeNoSupp {
		t.Errorf("code is %d, want %d", kerr.ErrorCode,
			wire.ErrCodeETypeNoSupp)
	}
}

// decodeReply opens the reply's enc-part with the client's key.
func decodeReply(
	t *testing.T,
	k *KDC,
	rep *wire.ASRep,
) wire.EncKDCRepPart {
	t.Helper()
	e := crypto.EncType(rep.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, rep.CName.Components, userPassword, e)
	plain, err := p.Decrypt(key, rep.EncPart.Cipher,
		crypto.UsageASRepEncPart)
	if err != nil {
		t.Fatalf("decrypting the reply: %v", err)
	}
	enc, err := wire.UnmarshalEncKDCRepPart(plain)
	if err != nil {
		t.Fatalf("EncKDCRepPart: %v", err)
	}
	return enc
}

// decodeTicket opens the ticket with the krbtgt's key, as a service
// would.
func decodeTicket(
	t *testing.T,
	k *KDC,
	rep *wire.ASRep,
) wire.EncTicketPart {
	t.Helper()
	e := crypto.EncType(rep.Ticket.EncPart.EType)
	p, err := crypto.Profile(e)
	if err != nil {
		t.Fatal(err)
	}
	key := clientKey(t, []string{"krbtgt", testRealm},
		"tgtpassword", e)
	plain, err := p.Decrypt(key, rep.Ticket.EncPart.Cipher,
		crypto.UsageKDCRepTicket)
	if err != nil {
		t.Fatalf("decrypting the ticket: %v", err)
	}
	tkt, err := wire.UnmarshalEncTicketPart(plain)
	if err != nil {
		t.Fatalf("EncTicketPart: %v", err)
	}
	return tkt
}

// A request naming a realm this KDC does not serve is refused, and
// the refusal is what keeps the issued ticket's client realm honest.
//
// Upstream takes the ticket's client realm from the *database entry*
// and not from the request, and does it whether or not
// KDC_OPT_CANONICALIZE was asked for -- "The realm is always
// canonicalized" (do_as_req.c:680-686) -- because its KDB layer can
// hand back an entry whose realm differs from the one asked for. This
// KDC cannot reach that state: the realm must match exactly
// (principals, asreq.go), the lookup is made with the KDC's own
// realm, and the reply carries the KDC's own realm, so the three can
// never disagree.
//
// So this asserts the gate rather than the canonicalisation, because
// the gate is what makes the canonicalisation unnecessary. A change
// that matched realms case-insensitively -- which looks like a
// kindness -- would pass every other test here and start issuing
// tickets whose crealm came from the request. That is the divergence,
// not the fix.
func TestAnotherRealmIsRefusedAtTheAS(t *testing.T) {
	k := testKDC(t)
	for _, realm := range []string{
		strings.ToLower(testRealm),
		testRealm + ".",
		"ELSEWHERE.TEST",
		"",
	} {
		t.Run(realm, func(t *testing.T) {
			req := asRequest([]string{"user"})
			req.Body.Realm = realm
			_, kerr := as(t, k, req)
			if kerr == nil {
				t.Fatalf("accepted realm %q", realm)
			}
			if kerr.ErrorCode !=
				wire.ErrCodeCPrincipalUnknown {
				t.Errorf("code %d for %q",
					kerr.ErrorCode, realm)
			}
		})
	}
}

// And the realm the reply carries is the KDC's own configuration,
// which is the other half of the same fact.
func TestTheReplyCarriesTheKDCsOwnRealm(t *testing.T) {
	k := testKDC(t)
	rep, kerr := as(t, k, asRequest([]string{"user"}))
	if kerr != nil {
		t.Fatalf("refused: %v", kerr)
	}
	if rep.CRealm != k.Realm {
		t.Errorf("crealm is %q, want %q", rep.CRealm,
			k.Realm)
	}
	if rep.Ticket.Realm != k.Realm {
		t.Errorf("the ticket's realm is %q",
			rep.Ticket.Realm)
	}
}
