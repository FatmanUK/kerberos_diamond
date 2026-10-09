package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// MaxAliasDepth is how many links of an alias chain resolve
// (MAX_ALIAS_DEPTH, lib/kdb/kdb5.c:800).
//
// Ten, and the eleventh is **not found** rather than an error saying
// the chain was too long (`:831` turns the depth check into
// KRB5_KDB_NOENTRY). Upstream tests exactly that boundary: a chain of
// ten resolves and the eleventh link reports "Server a11@... not
// found in Kerberos database" (tests/t_alias.py:51-60).
//
// It is also the whole of the loop detection. A self-referential
// alias is not caught as a cycle; it simply runs out of depth and
// reports not found, which `t_alias.py:60-63` asserts for `alias
// selfalias selfalias`.
const MaxAliasDepth = 10

// Errors the alias operations report.
var (
	// ErrAliasRealm is KADM5_ALIAS_REALM, "Alias target must be
	// within the same realm" (kadm_err.et:70).
	ErrAliasRealm = errors.New(
		"store: alias target must be in the same realm")

	// ErrAliasUnsupported is KRB5_KDB_ALIAS_UNSUPPORTED, which
	// rename answers for an alias (kdb5.c:1076-1083).
	ErrAliasUnsupported = errors.New(
		"store: operation unsupported on an alias")
)

// Canonical resolves an alias chain and returns the name it ends at.
//
// A name that is not an alias is returned unchanged, which is the
// case for almost every lookup and is why this is a single indexed
// read in the common path.
//
// Running out of depth is reported as ErrNotFound, not as a distinct
// error, because that is what upstream reports and because a client
// cannot do anything different with the distinction.
func (s *Store) Canonical(
	ctx context.Context,
	name string,
) (string, error) {
	at := name
	for depth := 0; ; depth++ {
		target, err := s.aliasTarget(ctx, at)
		if err != nil {
			return "", err
		}
		if target == "" {
			return at, nil
		}
		if depth+1 > MaxAliasDepth {
			return "", fmt.Errorf("%w: %s (alias chain "+
				"deeper than %d)", ErrNotFound, name,
				MaxAliasDepth)
		}
		at = target
	}
}

// aliasTarget reads one link, returning the empty string when the
// name is not an alias.
func (s *Store) aliasTarget(
	ctx context.Context,
	name string,
) (string, error) {
	var a Alias
	err := s.db.WithContext(ctx).
		First(&a, "alias_name = ?", name).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: alias %s: %w", name,
			err)
	}
	return a.TargetName, nil
}

// IsAlias reports whether a name resolves to a principal called
// something else, which is how upstream decides it: look the name up
// and compare the entry that comes back against the name asked for
// (kdb5.c:1076-1083).
//
// Resolving is the whole of it. A name whose chain dangles -- an
// alias pointing at a principal that does not exist -- is **not** an
// alias by this test, because the lookup fails, and that is
// deliberate rather than convenient: it is what makes a dangling
// alias overwritable by addprinc, by another alias or by a rename.
// Upstream calls that "emergent behavior" and keeps a test for it
// anyway (t_alias.py:75-85), which is the right record to copy.
func (s *Store) IsAlias(
	ctx context.Context,
	name string,
) (bool, error) {
	p, err := s.Lookup(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.Name != name, nil
}

// CreateAlias adds an alias.
//
// Two refusals, both upstream's (kadm5_create_alias,
// svr_principal.c:2051-2070):
//
//   - the target must be in the **same realm**. Upstream answers
//     KADM5_ALIAS_REALM, and the reason is structural rather than
//     arbitrary: an alias is resolved by a second database lookup,
//     and a KDC's database holds one realm.
//   - the alias name must not already resolve to anything. A name
//     that resolves is a duplicate; a name whose chain dangles is
//     not, which is why this asks Lookup rather than asking whether
//     a row exists.
func (s *Store) CreateAlias(
	ctx context.Context,
	alias, target string,
) error {
	if err := sameRealm(alias, target); err != nil {
		return err
	}
	if _, err := s.Lookup(ctx, alias); err == nil {
		return fmt.Errorf("%w: %s", ErrNameInUse, alias)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	row := &Alias{AliasName: alias, TargetName: target}
	err := s.db.WithContext(ctx).Save(row).Error
	if err != nil {
		return fmt.Errorf("store: alias %s: %w", alias, err)
	}
	return nil
}

// sameRealm is krb5_realm_compare on the two names.
func sameRealm(alias, target string) error {
	_, ar, err := ParseName(alias)
	if err != nil {
		return err
	}
	_, tr, err := ParseName(target)
	if err != nil {
		return err
	}
	if ar != tr {
		return fmt.Errorf("%w: %s is not in %s",
			ErrAliasRealm, target, ar)
	}
	return nil
}

// DeleteAlias removes an alias and leaves its target alone, which is
// what `delprinc' on an alias does (t_alias.py:12-16: the alias goes
// and `getprinc canon' still works).
func (s *Store) DeleteAlias(
	ctx context.Context,
	alias string,
) error {
	err := s.db.WithContext(ctx).
		Where("alias_name = ?", alias).
		Delete(&Alias{}).Error
	if err != nil {
		return fmt.Errorf("store: delete alias %s: %w",
			alias, err)
	}
	return nil
}

// ListAliases returns every alias name, which `listprincs' includes
// because upstream stores an alias as an ordinary database entry and
// so iterates over it like any other (t_alias.py:108-109).
func (s *Store) ListAliases(
	ctx context.Context,
) ([]string, error) {
	var names []string
	err := s.db.WithContext(ctx).Model(&Alias{}).
		Order("alias_name").Pluck("alias_name", &names).
		Error
	if err != nil {
		return nil, fmt.Errorf("store: list aliases: %w",
			err)
	}
	return names, nil
}
