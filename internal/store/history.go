package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
	"gorm.io/gorm"
)

// HistoryKey is one key from a password a principal used before.
//
// Upstream keeps these in the auxiliary osa_princ_ent_rec rather than
// in the principal itself -- a ring buffer of key *sets*, each the
// whole enctype list of one past password, with old_key_next as the
// write position (server_internal.h:62-70,
// svr_principal.c:1091-1210). Here they are rows with a generation
// number, which is the same thing said in a relational way: the ring
// exists to bound the size, and a DELETE does that without the
// arithmetic.
//
// **These are sealed under the master key, and upstream's are not.**
// Upstream seals history under the key of a principal called
// kadmin/history, and resets the whole history when that key changes
// (:1108-1114). That indirection buys nothing this project does not
// already have -- the master key is derived from the environment and
// protects every other key in the database -- and it adds a failure
// mode: a kadmin/history principal that is missing or re-keyed makes
// the history unreadable. What it costs is reading an MIT database's
// history rows, which is a dump/load limitation and is recorded as
// one.
type HistoryKey struct {
	ID uint `gorm:"primaryKey"`

	// PrincipalName is the fully qualified name, as every other
	// relation keys it.
	PrincipalName string `gorm:"size:1024;index"`

	// Seq numbers the generations, highest newest. It is not the
	// key version: a password change bumps the version of the
	// *live* keys, and this counts how many changes ago these
	// were live.
	Seq int32

	EType int32
	Blob  []byte
}

// ErrPasswordReuse reports a password the principal has used within
// the span its policy remembers.
var ErrPasswordReuse = errors.New(
	"store: password was used before")

// CheckPasswordReuse refuses a password within the policy's history.
//
// Two comparisons, and upstream makes both from the same function
// called twice (check_pw_reuse, svr_principal.c:1302-1317): the new
// key against the principal's *current* keys, which is what a history
// of 1 means, and then against the stored generations.
//
// The comparison is of key material rather than of passwords, which
// is the only way it can work -- nothing stored is reversible. That
// also makes it exact: a password that derives the same key under the
// same salt is the same password, and one that does not is not,
// however similar it looks.
func (s *Store) CheckPasswordReuse(
	ctx context.Context,
	p *Principal,
	password string,
) error {
	pol, err := s.PolicyFor(ctx, p)
	if err != nil || pol == nil {
		return err
	}
	want, err := derivedKeys(p, password)
	if err != nil {
		return err
	}
	if err := s.reusesCurrent(p, want); err != nil {
		return err
	}
	return s.reusesHistory(ctx, p, want)
}

// derivedKeys is what the new password would become, per enctype.
func derivedKeys(
	p *Principal,
	password string,
) (map[int32]string, error) {
	components, realm, err := ParseName(p.Name)
	if err != nil {
		return nil, err
	}
	salt := crypto.Salt(realm, components)
	out := map[int32]string{}
	for _, e := range crypto.Supported() {
		prof, err := crypto.Profile(e)
		if err != nil {
			return nil, err
		}
		key, err := prof.StringToKey(password, salt, nil)
		if err != nil {
			return nil, err
		}
		out[int32(e)] = string(key)
	}
	return out, nil
}

// reusesCurrent compares against the live keys at the highest
// version, which is the whole of what a history of 1 checks.
func (s *Store) reusesCurrent(
	p *Principal,
	want map[int32]string,
) error {
	highest := p.HighestKVNO()
	for i := range p.Keys {
		k := &p.Keys[i]
		if k.KVNO != highest {
			continue
		}
		err := s.sameKey(k.EType, k.Blob, want)
		if err != nil {
			return err
		}
	}
	return nil
}

// reusesHistory compares against every stored generation.
func (s *Store) reusesHistory(
	ctx context.Context,
	p *Principal,
	want map[int32]string,
) error {
	var rows []HistoryKey
	err := s.db.WithContext(ctx).
		Where("principal_name = ?", p.Name).
		Find(&rows).Error
	if err != nil {
		return fmt.Errorf("store: history: %w", err)
	}
	for _, r := range rows {
		err := s.sameKey(r.EType, r.Blob, want)
		if err != nil {
			return err
		}
	}
	return nil
}

// sameKey reports reuse when a stored blob opens to the key the new
// password would produce for the same enctype.
//
// A blob that will not open is skipped rather than reported, which is
// upstream's behaviour too -- check_pw_reuse continues past a
// decryption failure (svr_principal.c:1328-1330) -- because a history
// entry sealed under a master key this process does not hold cannot
// be compared and must not block a change.
func (s *Store) sameKey(
	etype int32,
	blob []byte,
	want map[int32]string,
) error {
	fresh, ok := want[etype]
	if !ok {
		return nil
	}
	old, err := decodeKeyBlob(s.mkey.Key, s.mkey.EType, blob)
	if err != nil {
		return nil
	}
	if string(old) == fresh {
		return ErrPasswordReuse
	}
	return nil
}

// RecordPasswordHistory moves a principal's *current* keys into its
// history and trims it to what the policy keeps.
//
// It has to be called before the keys are replaced, which is the one
// ordering constraint here: upstream builds its history entry from
// kdb's key_data before krb5_dbe_cpw touches it, and says so in a
// comment (svr_principal.c:1270-1271).
//
// A history of one keeps nothing stored at all -- "A history of 1
// means just check the current password" (:1102-1104) -- so this
// returns early rather than writing a generation nothing will read.
func (s *Store) RecordPasswordHistory(
	ctx context.Context,
	p *Principal,
) error {
	pol, err := s.PolicyFor(ctx, p)
	if err != nil || pol == nil || pol.PWHistoryNum <= 1 {
		return err
	}
	seq, err := s.nextHistorySeq(ctx, p.Name)
	if err != nil {
		return err
	}
	rows := make([]HistoryKey, 0, len(p.Keys))
	highest := p.HighestKVNO()
	for _, k := range p.Keys {
		if k.KVNO != highest {
			continue
		}
		rows = append(rows, HistoryKey{
			PrincipalName: p.Name,
			Seq:           seq,
			EType:         k.EType,
			Blob:          k.Blob,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.db.WithContext(ctx).
		Create(&rows).Error; err != nil {
		return fmt.Errorf("store: history: %w", err)
	}
	return s.trimHistory(ctx, p.Name, seq, pol.PWHistoryNum)
}

// nextHistorySeq is one past the newest generation stored.
func (s *Store) nextHistorySeq(
	ctx context.Context,
	name string,
) (int32, error) {
	var newest HistoryKey
	err := s.db.WithContext(ctx).
		Where("principal_name = ?", name).
		Order("seq desc").First(&newest).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: history: %w", err)
	}
	return newest.Seq + 1, nil
}

// trimHistory drops generations beyond what the policy keeps.
//
// The policy's number counts the current password as one of them, so
// the stored generations are one fewer: a history of three means the
// current password and the two before it.
func (s *Store) trimHistory(
	ctx context.Context,
	name string,
	newest, keep int32,
) error {
	oldest := newest - (keep - 1) + 1
	err := s.db.WithContext(ctx).
		Where("principal_name = ? AND seq < ?", name, oldest).
		Delete(&HistoryKey{}).Error
	if err != nil {
		return fmt.Errorf("store: trim history: %w", err)
	}
	return nil
}

// ForgetPasswordHistory removes every generation a principal has,
// which deleting the principal has to do.
//
// Clearing a principal's *policy* does not: upstream's POLICY_CLR
// drops the policy name and leaves old_keys where they are
// (svr_principal.c:628-634), so a principal put back on a policy
// remembers what it used before. Keeping that is free and surprising
// to change.
func (s *Store) ForgetPasswordHistory(
	ctx context.Context,
	name string,
) error {
	err := s.db.WithContext(ctx).
		Where("principal_name = ?", name).
		Delete(&HistoryKey{}).Error
	if err != nil {
		return fmt.Errorf("store: forget history: %w", err)
	}
	return nil
}
