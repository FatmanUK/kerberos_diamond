package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	testRealm    = "KDIAMOND.TEST"
	testMasterPW = "masterpassword"
)

// testStore opens a Store in a scratch schema of its own and drops
// the schema afterwards.
//
// The schema goes in the *connection string*, never a SET search_path
// statement. GORM pools connections and a SET reaches exactly one of
// them, so the next query in the same test can land on a connection
// still pointed at public -- which looks like flaky isolation and is
// not. assertSchemaIsolated below is what catches that if it ever
// comes back.
func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	base := os.Getenv("KD_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("KD_TEST_DATABASE_URL is unset")
	}
	schema := scratchSchema(t)
	admin := openRaw(t, base)
	exec(t, admin, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	exec(t, admin, "CREATE SCHEMA "+schema)

	mkey, err := DeriveMasterKey(
		testRealm, testMasterPW, DefaultMasterKeyType)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	s, err := Open(withSearchPath(t, base, schema), mkey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		exec(t, admin, "DROP SCHEMA "+schema+" CASCADE")
	})
	return s, schema
}

// scratchSchema names a schema after the test, so a failure says
// which test left it behind.
func scratchSchema(t *testing.T) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '_'
	}, t.Name())
	return "kd_test_" + name
}

// withSearchPath adds the scratch schema to the connection string.
func withSearchPath(t *testing.T, base, schema string) string {
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

func openRaw(t *testing.T, url string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

func exec(t *testing.T, db *gorm.DB, sql string) {
	t.Helper()
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// assertSchemaIsolated proves the tables landed in the scratch schema
// and not in public. Without it, a broken search_path shows up as a
// test that passes until two run at once.
func assertSchemaIsolated(t *testing.T, s *Store, schema string) {
	t.Helper()
	var got []string
	err := s.db.Raw(
		"SELECT table_schema FROM information_schema.tables "+
			"WHERE table_name = ? ORDER BY table_schema",
		"principals").Scan(&got).Error
	if err != nil {
		t.Fatalf("information_schema: %v", err)
	}
	found := false
	for _, sch := range got {
		if sch == schema {
			found = true
		}
		if sch == "public" {
			t.Error("principals was created in public")
		}
	}
	if !found {
		t.Fatalf("principals is in %v, not %q", got, schema)
	}
}

// principal builds a saved principal with a password set.
func principal(
	t *testing.T,
	s *Store,
	name, password string,
) *Principal {
	t.Helper()
	p := &Principal{
		Name:     name,
		Realm:    testRealm,
		NameType: 1,
	}
	if err := s.SetPassword(p, password, 1); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if err := s.Save(context.Background(), p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return p
}

func TestMigrateLandsInTheScratchSchema(t *testing.T) {
	s, schema := testStore(t)
	assertSchemaIsolated(t, s, schema)
}

func TestSaveAndLookup(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "user@" + testRealm
	principal(t, s, name, "userpassword")

	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Realm != testRealm {
		t.Errorf("realm is %q", got.Realm)
	}
	want := len(DefaultSupportedEnctypes())
	if len(got.Keys) != want {
		t.Fatalf("got %d keys, want %d",
			len(got.Keys), want)
	}
	if _, err := s.Lookup(ctx, "nobody@"+testRealm); err == nil {
		t.Error("looked up a principal that is not there")
	}
}

// A principal named the way a message names it must find the same
// row, which is the whole reason UnparseName exists.
func TestLookupWireFindsTheSameRow(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := UnparseName(testRealm, []string{"krbtgt", testRealm})
	principal(t, s, name, "tgtpassword")

	got, err := s.LookupWire(
		ctx, testRealm, []string{"krbtgt", testRealm})
	if err != nil {
		t.Fatalf("LookupWire: %v", err)
	}
	if got.Name != name {
		t.Errorf("found %q, want %q", got.Name, name)
	}
}

// The stored key must decrypt to exactly what string-to-key produces
// for the principal's own salt. A wrong salt is invisible here and
// surfaces as "password incorrect" from a real client, which is why
// this compares against the salt rather than against itself.
func TestStoredKeyMatchesStringToKey(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "user@" + testRealm
	principal(t, s, name, "userpassword")

	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	start := 0
	row, key, err := s.Key(p, &start,
		int32(crypto.AES256CTSHMACSHA196),
		AnySaltType, HighestKVNO)
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if row.KVNO != 1 {
		t.Errorf("kvno is %d, want 1", row.KVNO)
	}
	prof, err := crypto.Profile(crypto.AES256CTSHMACSHA196)
	if err != nil {
		t.Fatal(err)
	}
	want, err := prof.StringToKey("userpassword",
		crypto.Salt(testRealm, []string{"user"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%X", key) != fmt.Sprintf("%X", want) {
		t.Errorf("\n got %X\nwant %X", key, want)
	}
}

// Keys must come back sorted by kvno descending, because SelectKey
// breaks out of its scan on the first row below the version it wants.
// An ascending order makes HighestKVNO find the lowest.
func TestKeysComeBackHighestKVNOFirst(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "rolled@" + testRealm

	p := &Principal{Name: name, Realm: testRealm, NameType: 1}
	if err := s.SetPassword(p, "old", 1); err != nil {
		t.Fatal(err)
	}
	old := p.Keys
	if err := s.SetPassword(p, "new", 3); err != nil {
		t.Fatal(err)
	}
	// Save kvno 1 after kvno 3 so insertion order is wrong.
	p.Keys = append(p.Keys, old...)
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for i := 1; i < len(got.Keys); i++ {
		if got.Keys[i-1].KVNO < got.Keys[i].KVNO {
			t.Fatalf("kvnos out of order: %d then %d",
				got.Keys[i-1].KVNO, got.Keys[i].KVNO)
		}
	}
	start := 0
	row, _, err := s.Key(got, &start, AnyEType,
		AnySaltType, HighestKVNO)
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if row.KVNO != 3 {
		t.Errorf("highest kvno is %d, want 3", row.KVNO)
	}
}

// Saving replaces a principal's keys rather than adding to them. A
// merge would leave the old kvno behind, and SelectKey would find it
// and hand it out.
func TestSaveReplacesKeysRatherThanAdding(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "replaced@" + testRealm
	p := principal(t, s, name, "first")

	if err := s.SetPassword(p, "second", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	want := len(DefaultSupportedEnctypes())
	if len(got.Keys) != want {
		t.Fatalf("got %d keys, want %d",
			len(got.Keys), want)
	}
	for _, k := range got.Keys {
		if k.KVNO != 2 {
			t.Errorf("stale key at kvno %d", k.KVNO)
		}
	}
}

func TestDeleteRemovesTheKeysToo(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "doomed@" + testRealm
	principal(t, s, name, "whatever")

	if err := s.Delete(ctx, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	var n int64
	err := s.db.Model(&Key{}).
		Where("principal_name = ?", name).Count(&n).Error
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d key rows survived the delete", n)
	}
}

// Attributes are what the KDC's policy gate reads, so round-tripping
// the bitfield matters more than it looks.
func TestAttributesRoundTrip(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "preauth@" + testRealm
	p := principal(t, s, name, "preauthpassword")
	p.Attributes = AttrRequiresPreAuth | AttrDisallowProxiable
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.RequiresPreAuth() {
		t.Error("RequiresPreAuth lost")
	}
	if got.Allows(AttrDisallowProxiable) {
		t.Error("DisallowProxiable lost")
	}
	if !got.Allows(AttrDisallowRenewable) {
		t.Error("DisallowRenewable appeared")
	}
}

// tl-data this implementation does not understand must survive, or
// importing another KDC's database silently loses whatever it put
// there.
func TestUnknownTLDataSurvives(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "exotic@" + testRealm
	p := principal(t, s, name, "exoticpassword")
	p.TLData = []TLDatum{
		{Type: 0x0100, Contents: []byte("pac logon info")},
		{Type: 0x0600, Contents: []byte("<I>issuer<S>subj")},
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got.TLData) != 2 {
		t.Fatalf("got %d tl-data records, want 2",
			len(got.TLData))
	}
	for _, d := range got.TLData {
		if len(d.Contents) == 0 {
			t.Errorf("tl-data %#x came back empty",
				d.Type)
		}
	}
}

// A row encrypted under a master key this process did not load must
// say so, not report a bad password.
func TestWrongMasterKeyVersionIsItsOwnError(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "rollover@" + testRealm
	p := principal(t, s, name, "rolloverpassword")
	for i := range p.Keys {
		p.Keys[i].MKVNO = 2
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	start := 0
	_, _, err = s.Key(got, &start, AnyEType,
		AnySaltType, HighestKVNO)
	if err == nil {
		t.Fatal("decrypted under the wrong master key")
	}
	if !strings.Contains(err.Error(), "master key version") {
		t.Errorf("error is %v, want a master key version "+
			"complaint", err)
	}
}

// List returns names in order, which is what a listing wants and what
// the one caller relies on to be stable between runs.
func TestList(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	for _, n := range []string{"zeta", "alpha", "mu"} {
		principal(t, s, n+"@"+testRealm, "pw-"+n)
	}
	names, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{
		"alpha@" + testRealm,
		"mu@" + testRealm,
		"zeta@" + testRealm,
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", names, want)
	}
}

// HighestKVNO reads the first key, which is only the highest because
// Lookup orders them descending -- the same reason SelectKey can
// resolve "highest" from element zero.
func TestHighestKVNO(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "versioned@" + testRealm

	p := store2Principal(t, s, name, "old", 1)
	if err := s.SetPassword(p, "new", 4); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.HighestKVNO() != 4 {
		t.Errorf("highest kvno is %d, want 4",
			got.HighestKVNO())
	}
	empty := &Principal{}
	if empty.HighestKVNO() != 0 {
		t.Error("a keyless principal claims a key version")
	}
}

// store2Principal builds and saves a principal at a given key
// version.
func store2Principal(
	t *testing.T,
	s *Store,
	name, password string,
	kvno int32,
) *Principal {
	t.Helper()
	components, realm, err := ParseName(name)
	if err != nil {
		t.Fatal(err)
	}
	p := NewPrincipal(realm, components)
	if err := s.SetPassword(p, password, kvno); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// A random key is random, is the right length for its enctype, and is
// nothing a password would have produced.
//
// The last part is the one worth asserting: a service's key is never
// typed by anyone, so deriving it from a password only weakens it to
// whatever the password was worth, and a SetRandomKey that quietly
// fell back to string-to-key would be invisible from every other
// angle.
func TestSetRandomKeyIsNotDerivedFromAnything(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	name := "host/a.test@" + testRealm
	principal(t, s, name, "servicepassword")

	p, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRandomKey(p, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, p); err != nil {
		t.Fatal(err)
	}
	again, err := s.Lookup(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	assertRandomKeys(t, s, again, "servicepassword")
}

// assertRandomKeys walks every key a principal holds and checks each
// one: the version is the new one, the length is the enctype's, and
// the bytes are not what the password would have given.
func assertRandomKeys(
	t *testing.T,
	s *Store,
	p *Principal,
	password string,
) {
	t.Helper()
	components, realm, err := ParseName(p.Name)
	if err != nil {
		t.Fatal(err)
	}
	salt := crypto.Salt(realm, components)
	seen := 0
	start := 0
	for {
		row, key, err := s.Key(p, &start, AnyEType,
			AnySaltType, HighestKVNO)
		if errors.Is(err, ErrNoMatchingKey) {
			break
		}
		if err != nil {
			t.Fatalf("Key: %v", err)
		}
		seen++
		assertRandomKey(t, row, key, password, salt)
	}
	if seen != len(DefaultSupportedEnctypes()) {
		t.Errorf("%d keys, want one per configured enctype "+
			"(%d)", seen, len(DefaultSupportedEnctypes()))
	}
}

// assertRandomKey checks one of them.
func assertRandomKey(
	t *testing.T,
	row *Key,
	key []byte,
	password string,
	salt []byte,
) {
	t.Helper()
	prof, err := crypto.Profile(crypto.EncType(row.EType))
	if err != nil {
		t.Fatal(err)
	}
	if row.KVNO != 2 {
		t.Errorf("enctype %d is at kvno %d, want 2",
			row.EType, row.KVNO)
	}
	if len(key) != prof.KeyLength {
		t.Errorf("enctype %d key is %d bytes not %d",
			row.EType, len(key), prof.KeyLength)
	}
	derived, err := prof.StringToKey(password, salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%X", key) == fmt.Sprintf("%X", derived) {
		t.Errorf("enctype %d got the password's key",
			row.EType)
	}
}

// Two calls give two different keys, which is what makes ktadd's
// re-key mean anything: handing out a keytab without changing the key
// would leave every previous copy working.
func TestSetRandomKeyDiffersEveryTime(t *testing.T) {
	s, _ := testStore(t)
	first := NewPrincipal(testRealm, []string{"a"})
	second := NewPrincipal(testRealm, []string{"a"})
	if err := s.SetRandomKey(first, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRandomKey(second, 1); err != nil {
		t.Fatal(err)
	}
	if len(first.Keys) == 0 {
		t.Fatal("no keys")
	}
	for i := range first.Keys {
		if fmt.Sprintf("%X", first.Keys[i].Blob) ==
			fmt.Sprintf("%X", second.Keys[i].Blob) {
			t.Errorf("key %d repeated", i)
		}
	}
}
