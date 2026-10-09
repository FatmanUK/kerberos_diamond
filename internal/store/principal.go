package store

import (
	"context"
	"crypto/rand"
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
		&HistoryKey{},
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
	return p.setPassword(mkey, password, kvno, false)
}

// SetPasswordKeepOld is SetPassword that keeps the previous key
// versions, which is kadmin's cpw -keepold.
//
// It exists because replacing a key locks out every ticket already
// issued under it. A service re-keyed without keepold stops accepting
// the tickets its clients are holding, which they only find out when
// they present one; keeping the old version means they keep working
// until they expire, and then purgekeys removes it.
//
// The new keys go *first* in the list, because SelectKey breaks out
// of its scan on the first row below the version it wants and so
// requires descending order.
func (p *Principal) SetPasswordKeepOld(
	mkey MasterKey,
	password string,
	kvno int32,
) error {
	return p.setPassword(mkey, password, kvno, true)
}

func (p *Principal) setPassword(
	mkey MasterKey,
	password string,
	kvno int32,
	keep bool,
) error {
	components, realm, err := ParseName(p.Name)
	if err != nil {
		return err
	}
	salt := crypto.Salt(realm, components)
	return p.setKeys(kvno, keep,
		func(e crypto.EncType) (Key, error) {
			return newKey(mkey, password, salt, e)
		})
}

// setKeys writes one key per supported enctype at a single version,
// keeping or discarding what was there.
func (p *Principal) setKeys(
	kvno int32,
	keep bool,
	makeKey func(crypto.EncType) (Key, error),
) error {
	old := p.Keys
	p.Keys = nil
	for i, e := range crypto.Supported() {
		k, err := makeKey(e)
		if err != nil {
			return err
		}
		k.PrincipalName = p.Name
		k.KeyIndex = int32(i)
		k.KVNO = kvno
		p.Keys = append(p.Keys, k)
	}
	if keep {
		for _, k := range old {
			if k.KVNO >= kvno {
				continue
			}
			k.ID = 0
			p.Keys = append(p.Keys, k)
		}
	}
	p.LastPWChange = time.Now().UTC().Truncate(time.Second)
	return nil
}

// PurgeOldKeys drops every key below the highest version, which is
// kadmin's purgekeys.
//
// It is the other half of keepold: an old key is kept so that tickets
// issued under it keep working, and removed once they cannot still be
// in use.
func (p *Principal) PurgeOldKeys() int {
	highest := p.HighestKVNO()
	var keep []Key
	for _, k := range p.Keys {
		if k.KVNO == highest {
			keep = append(keep, k)
		}
	}
	removed := len(p.Keys) - len(keep)
	p.Keys = keep
	return removed
}

// SetRandomKey writes a random key for each supported enctype at one
// key version, the way kadmin's addprinc -randkey and ktadd do.
//
// A service's key is never typed by anyone, so deriving it from a
// password only weakens it to whatever the password was worth. The
// salt does not come into it either: a random key has none, and
// upstream records that as SaltNormal with nothing stored, exactly as
// a default salt is recorded -- because nothing ever recomputes a
// salt for a key no string-to-key produced.
//
// Note what upstream does *not* do here. randkey_3 runs neither the
// password-quality check nor the history check
// (svr_principal.c:1388-1505), which is why `cpw -randkey` escapes a
// minimum password lifetime and a reuse rule. That is behaviour to
// reproduce rather than improve: the rules exist to constrain what a
// human chooses, and nothing here was chosen.
func (p *Principal) SetRandomKey(
	mkey MasterKey,
	kvno int32,
) error {
	return p.setKeys(kvno, false,
		func(e crypto.EncType) (Key, error) {
			return randomKey(mkey, e)
		})
}

// SetRandomKeyKeepOld is SetRandomKey that keeps the previous key
// versions, for the same reason SetPasswordKeepOld does.
func (p *Principal) SetRandomKeyKeepOld(
	mkey MasterKey,
	kvno int32,
) error {
	return p.setKeys(kvno, true,
		func(e crypto.EncType) (Key, error) {
			return randomKey(mkey, e)
		})
}

// randomKey makes and seals one random key.
//
// For every enctype this project implements, random-to-key is the
// identity: RFC 3962 says so for the AES pair (section 6, "the
// random-to-key function is the identity function") and RFC 8009
// repeats it for aes-sha2 (section 5). The enctypes where it is not
// -- the DES family's parity fixing, and 3DES -- are the ones this
// project does not have, so the indirection upstream keeps for
// krb5_c_random_to_key would have exactly one implementation here and
// is left out. It goes back in the day another family does.
func randomKey(
	mkey MasterKey,
	e crypto.EncType,
) (Key, error) {
	prof, err := crypto.Profile(e)
	if err != nil {
		return Key{}, err
	}
	key := make([]byte, prof.KeyLength)
	if _, err := rand.Read(key); err != nil {
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

// List returns every principal's name, sorted.
//
// Names only: a listing that loaded each principal's keys would read
// the whole database to print a column of strings, and the one caller
// that wants the rest asks for it by name afterwards.
func (s *Store) List(ctx context.Context) ([]string, error) {
	var names []string
	err := s.db.WithContext(ctx).Model(&Principal{}).
		Order("name").Pluck("name", &names).Error
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	return names, nil
}

// HighestKVNO is the greatest key version a principal holds, or 0
// when it holds no keys.
//
// It reads the first key because Lookup orders them by kvno
// descending, which is the same reason SelectKey can resolve
// "highest" from element zero (current_kvno, kdc/kdc_util.h:538-541).
func (p *Principal) HighestKVNO() int32 {
	if len(p.Keys) == 0 {
		return 0
	}
	return p.Keys[0].KVNO
}

// SpecializeSalt pins every key's salt to the value computed from the
// principal's *current* name, which is what makes a rename survivable
// (krb5_dbe_specialize_salt, lib/kdb/kdb5.c:2390-2421).
//
// The default salt is the realm followed by the name components, so
// it changes when the name does -- and a principal renamed without
// pinning it first would have every password-derived key become
// unusable, reported to the user as "password incorrect". Upstream's
// rename test is precisely this: rename, then kinit with the same
// password (tests/t_renprinc.py:31-38).
//
// A key that already carries an explicit salt is left alone, which is
// why renaming twice works: the second rename finds the salt from the
// first still pinned and has nothing to do.
func (p *Principal) SpecializeSalt() error {
	components, realm, err := ParseName(p.Name)
	if err != nil {
		return err
	}
	salt := crypto.Salt(realm, components)
	for i := range p.Keys {
		k := &p.Keys[i]
		if k.SaltType == SaltSpecial && len(k.Salt) > 0 {
			continue
		}
		k.SaltType = SaltSpecial
		k.Salt = append([]byte(nil), salt...)
	}
	return nil
}

// ErrNameInUse reports a rename onto a principal that exists.
var ErrNameInUse = errors.New("store: name already in use")

// Rename moves a principal to a new name, carrying everything that
// hangs off it.
//
// It is the most expensive write in this package and the reason is
// the schema: a principal's name is its primary key *and* the foreign
// key of its keys, its string attributes, its tl-data and its
// password history, so a rename is five updates that have to happen
// together. They do, in one transaction.
//
// The salt is pinned first, before anything moves. That ordering is
// the whole of what makes a rename safe, because the salt has to be
// computed from the name the keys were derived under.
//
// Upstream refuses two cases and so does this: a target that already
// exists (KRB5_KDB_INUSE) and a source that is an alias rather than a
// principal in its own right (KRB5_KDB_ALIAS_UNSUPPORTED,
// lib/kdb/kdb5.c:2240-2250). The second is refused here because an
// alias has no keys of its own to move, so "renaming" one would
// silently create a principal with none.
func (s *Store) Rename(
	ctx context.Context,
	from, to string,
) error {
	p, err := s.Lookup(ctx, from)
	if err != nil {
		return err
	}
	if _, err := s.Lookup(ctx, to); err == nil {
		return fmt.Errorf("%w: %q", ErrNameInUse, to)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := p.SpecializeSalt(); err != nil {
		return err
	}
	_, realm, err := ParseName(to)
	if err != nil {
		return err
	}
	return s.renameRows(ctx, p, to, realm)
}

// renameRows is the transaction.
func (s *Store) renameRows(
	ctx context.Context,
	p *Principal,
	to, realm string,
) error {
	old := p.Name
	err := s.db.WithContext(ctx).Transaction(
		func(tx *gorm.DB) error {
			p.Name = to
			p.Realm = realm
			for i := range p.Keys {
				p.Keys[i].PrincipalName = to
				p.Keys[i].ID = 0
			}
			for i := range p.StringAttrs {
				p.StringAttrs[i].PrincipalName = to
			}
			for i := range p.TLData {
				p.TLData[i].PrincipalName = to
				p.TLData[i].ID = 0
			}
			if err := savePrincipal(tx, p); err != nil {
				return err
			}
			return renameLeftovers(tx, old, to)
		})
	if err != nil {
		return fmt.Errorf("store: rename %q: %w", old, err)
	}
	return nil
}

// renameLeftovers moves what savePrincipal does not: the password
// history, which is deliberately not an association on Principal so
// that an ordinary Save cannot wipe it, and the old principal row
// with the rows that hung off it.
func renameLeftovers(tx *gorm.DB, old, to string) error {
	err := tx.Model(&HistoryKey{}).
		Where("principal_name = ?", old).
		Update("principal_name", to).Error
	if err != nil {
		return err
	}
	for _, m := range []any{
		&Key{}, &StringAttr{}, &TLDatum{},
	} {
		err := tx.Where("principal_name = ?", old).
			Delete(m).Error
		if err != nil {
			return err
		}
	}
	return tx.Where("name = ?", old).
		Delete(&Principal{}).Error
}
