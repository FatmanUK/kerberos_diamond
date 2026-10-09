package golden

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/hostrealm"
	"github.com/FatmanUK/kerberos_diamond/internal/kdc"
	"github.com/FatmanUK/kerberos_diamond/internal/store"
	"github.com/FatmanUK/kerberos_diamond/internal/wire"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openAdmin connects outside any scratch schema, to create and drop
// them.
func openAdmin(url string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		return nil, err
	}
	// One connection is enough for a CREATE and a DROP, and the
	// suite runs enough of these in parallel that an unbounded
	// pool here was half of what exhausted Postgres' client
	// limit.
	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	sql.SetMaxOpenConns(2)
	sql.SetMaxIdleConns(1)
	return db, nil
}

// Diamond is this project's KDC, set up to answer the same realm the
// oracle serves.
type Diamond struct {
	KDC   *kdc.KDC
	Store *store.Store

	closers []func()
}

// Close releases the database.
func (d *Diamond) Close() {
	for i := len(d.closers) - 1; i >= 0; i-- {
		d.closers[i]()
	}
}

// TestDatabaseURL is where the harness looks for Postgres.
const TestDatabaseURL = "KD_TEST_DATABASE_URL"

// ErrNoDatabase reports that no test database was configured.
var ErrNoDatabase = fmt.Errorf("%s is unset", TestDatabaseURL)

// StartDiamond builds a Go KDC over a scratch schema, provisioned
// with the same principals the oracle's realm has.
//
// The passwords, key versions and lifetime defaults all have to match
// the C side, or the comparison measures the fixture rather than the
// implementations. They come from this package's constants and from
// store.NewPrincipal, which applies kadmin's own defaults.
func StartDiamond(
	ctx context.Context,
	schema string,
	now func() time.Time,
) (*Diamond, error) {
	base := os.Getenv(TestDatabaseURL)
	if base == "" {
		return nil, ErrNoDatabase
	}
	return StartDiamondAt(ctx, base, schema, now)
}

// StartDiamondAt is StartDiamond against a named database, for a test
// that brings its own Postgres rather than using the shared one.
func StartDiamondAt(
	ctx context.Context,
	base, schema string,
	now func() time.Time,
) (*Diamond, error) {
	mkey, err := store.DeriveMasterKey(
		Realm, MasterPass, store.DefaultMasterKeyType)
	if err != nil {
		return nil, err
	}
	d := &Diamond{}
	if err := d.open(ctx, base, schema, mkey); err != nil {
		d.Close()
		return nil, err
	}
	d.KDC = &kdc.KDC{
		Store:     d.Store,
		Realm:     Realm,
		ClockSkew: 5 * time.Minute,
		Now:       now,
		Hosts:     referralHosts(),
	}
	return d, nil
}

func (d *Diamond) open(
	ctx context.Context,
	base, schema string,
	mkey store.MasterKey,
) error {
	admin, err := openAdmin(base)
	if err != nil {
		return err
	}
	drop := "DROP SCHEMA IF EXISTS " + schema + " CASCADE"
	if err := admin.Exec(drop).Error; err != nil {
		return err
	}
	if err := admin.Exec(
		"CREATE SCHEMA " + schema).Error; err != nil {
		return err
	}
	s, err := store.Open(searchPath(base, schema), mkey)
	if err != nil {
		return err
	}
	d.Store = s
	d.closers = append(d.closers, func() { s.Close() },
		func() { admin.Exec(drop) })
	return provision(ctx, s, mkey)
}

// provision creates the oracle's principals with the same keys.
//
// krbtgt is written at TgtKVNO because the C side's cpw bumped it
// there; a kvno mismatch would show up in the ticket's enc-part and
// nowhere else, which is exactly the sort of fixture difference that
// reads as an implementation bug.
func provision(
	ctx context.Context,
	s *store.Store,
	mkey store.MasterKey,
) error {
	for _, e := range realmEntries() {
		p := store.NewPrincipal(Realm, e.components)
		p.Attributes = e.attrs
		err := p.SetPassword(mkey, e.password, e.kvno)
		if err != nil {
			return err
		}
		if err := s.Save(ctx, p); err != nil {
			return err
		}
	}
	if err := provisionTrust(ctx, s, mkey); err != nil {
		return err
	}
	if err := provisionReferral(ctx, s, mkey); err != nil {
		return err
	}
	return provisionFarRealm(ctx, s, mkey)
}

// fixtureEntry is one principal the fixture holds.
type fixtureEntry struct {
	components []string
	password   string
	kvno       int32
	attrs      uint32
}

// realmEntries is the oracle's realm, principal for principal.
func realmEntries() []fixtureEntry {
	return []fixtureEntry{
		{[]string{UserName}, UserPassword, 1, 0},
		{[]string{PreauthName}, UserPassword, 1,
			store.AttrRequiresPreAuth},
		{[]string{"krbtgt", Realm}, TgtPassword,
			TgtKVNO, 0},
		{ServiceName, ServicePassword, 1, 0},
		{[]string{PeerName}, PeerPassword, 1,
			store.AttrDisallowSvr},
		// PWCHANGE_SERVICE is what exempts a principal whose
		// password has expired from needing a valid one to
		// get a ticket here -- without it there would be no
		// way to change an expired password, which is the
		// condition the whole service exists for. kdb5_util
		// create sets it on this principal and so does this.
		{ChangePWName, ChangePWPassword, 1,
			store.AttrPWChangeService},
		// kadmin/admin is the administrative surface's own
		// principal, and it is an ordinary service entry: the
		// gate that makes it administrative is in AcceptAPReq
		// and not in the database.
		{AdminName, AdminPassword, 1, 0},
	}
}

// provisionFarRealm adds the far realm's own principals, so that a Go
// KDC can be stood up *as* that realm.
//
// Only one case needs it, and it needs it for a reason worth stating:
// the alternate-TGS search runs at the realm a client asks from,
// which is the far end of a path and never the near one. Comparing it
// means both implementations answering a request addressed to the far
// realm.
//
// A principal's key in the store is its fully qualified name, so two
// realms in one database never collide.
func provisionFarRealm(
	ctx context.Context,
	s *store.Store,
	mkey store.MasterKey,
) error {
	type entry struct {
		components []string
		password   string
		kvno       int32
	}
	for _, e := range []entry{
		{[]string{FarUser}, FarPassword, 1},
		// The krbtgt is at TgtKVNO because the fixture's cpw
		// bumped it there, as it does in every realm.
		{[]string{"krbtgt", FarRealm}, FarTGTPassword,
			TgtKVNO},
		{[]string{"krbtgt", MidRealm}, FarMidPassword, 1},
	} {
		p := store.NewPrincipal(FarRealm, e.components)
		err := p.SetPassword(mkey, e.password, e.kvno)
		if err != nil {
			return err
		}
		if err := s.Save(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// provisionTrust adds the inter-realm key, which is the whole of a
// cross-realm trust: this KDC can verify a ticket-granting ticket the
// foreign realm issued for a service here exactly because it holds
// the key for krbtgt/<here>@<there>.
//
// Note the realm: the principal's *name* says this realm and its
// *realm* says the foreign one, so its default salt is the foreign
// realm's. That is what makes the key identical to the one in the
// foreign realm's own database, derived from the same password there.
func provisionTrust(
	ctx context.Context,
	s *store.Store,
	mkey store.MasterKey,
) error {
	for realm, password := range map[string]string{
		// A direct trust, for the one-hop case.
		ForeignRealm: InterRealmPassword,
		// The last hop of a three-realm path, which is the
		// only part of that path this realm is in.
		MidRealm: MidLocalPassword,
	} {
		p := store.NewPrincipal(realm,
			[]string{"krbtgt", Realm})
		err := p.SetPassword(mkey, password, 1)
		if err != nil {
			return err
		}
		if err := s.Save(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// storeName is the database key for a principal in this realm, which
// the harness needs when it reaches past the KDC to adjust a
// principal directly.
func storeName(components []string) string {
	return store.UnparseName(Realm, components)
}

// AS runs one request through the Go KDC and returns the reply bytes,
// so that both sides of the comparison are driven through the same
// encoded message.
func (d *Diamond) AS(req wire.ASReq) ([]byte, error) {
	msg, err := wire.MarshalASReq(req)
	if err != nil {
		return nil, err
	}
	return d.KDC.Handle(msg)
}

func searchPath(base, schema string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// OpenDiamond builds a Go KDC over a schema that already exists.
//
// It differs from StartDiamond in exactly one way: it does not drop
// and recreate the schema, so a second KDC can be pointed at the same
// realm as the first. That is what makes the high-availability claim
// measurable -- two KDCs sharing a database and nothing else.
func OpenDiamond(
	base, schema string,
	now func() time.Time,
) (*Diamond, error) {
	mkey, err := store.DeriveMasterKey(
		Realm, MasterPass, store.DefaultMasterKeyType)
	if err != nil {
		return nil, err
	}
	s, err := store.Open(searchPath(base, schema), mkey)
	if err != nil {
		return nil, err
	}
	d := &Diamond{Store: s}
	d.closers = append(d.closers, func() { s.Close() })
	d.KDC = &kdc.KDC{
		Store:     s,
		Realm:     Realm,
		ClockSkew: 5 * time.Minute,
		Now:       now,
	}
	return d, nil
}

// referralHosts is the host-to-realm map the oracle's kdc.conf
// carries, so that both implementations answer a host-based referral
// from the same configuration. Without it the comparison would
// measure the fixture.
func referralHosts() hostrealm.Map {
	m, err := hostrealm.Parse(
		"." + ReferralDomain + "=" + ForeignRealm)
	if err != nil {
		panic(err)
	}
	return m
}

// provisionReferral adds the outbound half of the trust with the
// foreign realm, which is what a host-based referral hands a client:
// krbtgt/<ForeignRealm>@<Realm>, sealed with a key both realms hold.
//
// The inbound half is a different principal and has been there since
// cross-realm landed. Every earlier case used that one, because every
// earlier case had a client of the foreign realm reaching a service
// here; a referral goes the other way.
func provisionReferral(
	ctx context.Context,
	s *store.Store,
	mkey store.MasterKey,
) error {
	p := store.NewPrincipal(Realm,
		[]string{"krbtgt", ForeignRealm})
	err := p.SetPassword(mkey, LocalForeignPassword, 1)
	if err != nil {
		return err
	}
	return s.Save(ctx, p)
}
