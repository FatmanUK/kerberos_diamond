package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Lookup fetches a principal by its fully qualified name.
//
// Keys come back sorted by kvno descending, and that is not a
// convenience: SelectKey breaks out of its scan on the first row
// below the requested version, so an unsorted list finds nothing.
// Upstream has the same requirement and meets it by re-sorting after
// every fetch (lib/kdb/kdb5.c:856-858); here the database does it,
// which is the one thing a relational store is unambiguously better
// at.
func (s *Store) Lookup(
	ctx context.Context,
	name string,
) (*Principal, error) {
	var p Principal
	err := s.db.WithContext(ctx).
		Preload("Keys", func(db *gorm.DB) *gorm.DB {
			return db.Order("kvno DESC, key_index ASC")
		}).
		Preload("StringAttrs").
		Preload("TLData").
		First(&p, "name = ?", name).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("store: lookup %s: %w",
			name, err)
	}
	return &p, nil
}

// LookupWire fetches a principal named the way a message names it.
func (s *Store) LookupWire(
	ctx context.Context,
	realm string,
	components []string,
) (*Principal, error) {
	return s.Lookup(ctx, UnparseName(realm, components))
}

// Key returns the decrypted key matching an enctype, salt type and
// key version, together with the row it came from.
//
// The returned key's enctype is the row's EType, not anything derived
// from the ciphertext: the stored blob records no enctype of its own
// (lib/kdb/decrypt_key.c:84-91).
func (s *Store) Key(
	p *Principal,
	start *int,
	etype, salttype, kvno int32,
) (*Key, []byte, error) {
	k, err := SelectKey(p.Keys, start, etype, salttype, kvno)
	if err != nil {
		return nil, nil, err
	}
	if err := s.mkey.usableFor(k); err != nil {
		return nil, nil, err
	}
	key, err := decodeKeyBlob(s.mkey.Key, s.mkey.EType, k.Blob)
	if err != nil {
		return nil, nil, err
	}
	return k, key, nil
}

// Save writes a principal and replaces its keys, string attributes
// and tl-data wholesale.
//
// Replacing rather than merging is deliberate: a principal's key list
// is a unit, and a partial update that left a stale kvno behind would
// be found by SelectKey and handed out.
func (s *Store) Save(ctx context.Context, p *Principal) error {
	err := s.db.WithContext(ctx).Transaction(
		func(tx *gorm.DB) error {
			return savePrincipal(tx, p)
		})
	if err != nil {
		return fmt.Errorf("store: save %s: %w", p.Name, err)
	}
	return nil
}

func savePrincipal(tx *gorm.DB, p *Principal) error {
	for _, m := range []any{
		&Key{}, &StringAttr{}, &TLDatum{},
	} {
		err := tx.Where("principal_name = ?", p.Name).
			Delete(m).Error
		if err != nil {
			return err
		}
	}
	for i := range p.Keys {
		p.Keys[i].PrincipalName = p.Name
	}
	for i := range p.StringAttrs {
		p.StringAttrs[i].PrincipalName = p.Name
	}
	for i := range p.TLData {
		p.TLData[i].PrincipalName = p.Name
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		UpdateAll: true,
	}).Create(p).Error
}

// Delete removes a principal and everything hanging off it.
func (s *Store) Delete(ctx context.Context, name string) error {
	db := s.db.WithContext(ctx)
	for _, m := range []any{
		&Key{}, &StringAttr{}, &TLDatum{},
	} {
		err := db.Where("principal_name = ?", name).
			Delete(m).Error
		if err != nil {
			return fmt.Errorf("store: delete %s: %w",
				name, err)
		}
	}
	err := db.Where("name = ?", name).Delete(&Principal{}).Error
	if err != nil {
		return fmt.Errorf("store: delete %s: %w", name, err)
	}
	return nil
}

// SetPassword derives a key for each supported enctype and writes
// them at one key version, the way kadmin's addprinc -pw does.
//
// The salt is the principal's default: the realm followed by its name
// components with no separator. A wrong salt is not a visible failure
// -- it produces a key the client disagrees with and the exchange
// reports a bad password -- which is why crypto.Salt is used rather
// than anything assembled here.
func (p *Principal) SetPassword(
	mkey MasterKey,
	password string,
	kvno int32,
) error {
	components, realm, err := ParseName(p.Name)
	if err != nil {
		return err
	}
	salt := crypto.Salt(realm, components)
	p.Keys = nil
	for i, e := range crypto.Supported() {
		k, err := newKey(mkey, password, salt, e)
		if err != nil {
			return err
		}
		k.PrincipalName = p.Name
		k.KeyIndex = int32(i)
		k.KVNO = kvno
		p.Keys = append(p.Keys, k)
	}
	p.LastPWChange = time.Now().UTC().Truncate(time.Second)
	return nil
}

// newKey derives and seals one key.
//
// SaltType is recorded as SaltNormal with an empty Salt column, which
// is how upstream stores a default salt: key_data_ver stays 1 and the
// salt is recomputed from the principal rather than held
// (lib/kdb/decrypt_key.c:111-123). Writing the computed salt into the
// column instead would read back identically and diverge the moment a
// principal is renamed.
func newKey(
	mkey MasterKey,
	password string,
	salt []byte,
	e crypto.EncType,
) (Key, error) {
	prof, err := crypto.Profile(e)
	if err != nil {
		return Key{}, err
	}
	key, err := prof.StringToKey(password, salt, nil)
	if err != nil {
		return Key{}, err
	}
	blob, err := encodeKeyBlob(mkey.Key, mkey.EType, key)
	if err != nil {
		return Key{}, err
	}
	return Key{
		EType:    int32(e),
		Blob:     blob,
		SaltType: SaltNormal,
		MKVNO:    mkey.KVNO,
	}, nil
}

// The lifetime defaults a new principal gets, which are kadmin's: one
// day of ticket life and *zero* renewable life
// (lib/kadm5/alt_prof.c:573-578).
//
// The zero is not an oversight to improve on. It means a freshly
// created realm issues renewable tickets whose renew-till equals
// their start time, because kdc_get_ticket_renewtime takes a plain
// min against it -- which is why `kinit -r 7d` against a new MIT
// realm appears to do nothing until an operator sets a renewable life
// on both the client and the krbtgt. Matching it is the point.
const (
	DefaultMaxLife          int32 = 24 * 60 * 60
	DefaultMaxRenewableLife int32 = 0
)

// NewPrincipal builds a principal with kadmin's defaults applied.
//
// Going through this rather than a bare struct literal is what keeps
// a Go-provisioned realm comparable with a kadmin-provisioned one: a
// principal with MaxLife left at zero would be *unlimited* to the KDC
// and would issue longer tickets than its C counterpart.
func NewPrincipal(
	realm string,
	components []string,
) *Principal {
	return &Principal{
		Name:             UnparseName(realm, components),
		Realm:            realm,
		NameType:         1,
		MaxLife:          DefaultMaxLife,
		MaxRenewableLife: DefaultMaxRenewableLife,
	}
}
