package golden

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

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
	return gorm.Open(postgres.Open(url), &gorm.Config{
		Logger: logger.Discard,
	})
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
	type entry struct {
		components []string
		password   string
		kvno       int32
		attrs      uint32
	}
	for _, e := range []entry{
		{[]string{UserName}, UserPassword, 1, 0},
		{[]string{PreauthName}, UserPassword, 1,
			store.AttrRequiresPreAuth},
		{[]string{"krbtgt", Realm}, TgtPassword,
			TgtKVNO, 0},
		{ServiceName, ServicePassword, 1, 0},
		{[]string{PeerName}, PeerPassword, 1,
			store.AttrDisallowSvr},
	} {
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
	return provisionTrust(ctx, s, mkey)
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
