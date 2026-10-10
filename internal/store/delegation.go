package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Delegation is the **traditional** constrained-delegation relation:
// which services an impersonator may obtain tickets to on somebody
// else's behalf.
//
// It is upstream's `krb5_db_check_allowed_to_delegate', and this is
// the place the plan said Postgres would pay off. **DB2 cannot
// express it at all** -- it has no check_allowed_to_delegate method,
// so the dispatch answers KRB5_PLUGIN_OP_NOTSUPP and every S4U2Proxy
// request is refused. Upstream's real answer is LDAP's
// `krbAllowedToDelegateTo' attribute, and its own test suite needs a
// *test* KDB module reading JSON out of krb5.conf to exercise the
// successful cases at all (t_s4u.py:32-34). Here it is a table.
//
// Both names are realm-qualified, which is a divergence from
// upstream's test module and a deliberate one: that module compares
// unparsed names **without** realms (kdb_test.c:736-743), which in a
// single-realm fixture is the same thing and in a cross-realm one
// would let a grant to `host/x@A' authorise `host/x@B'.
type Delegation struct {
	// Impersonator is the service holding the evidence ticket,
	// the one asking to act for somebody.
	Impersonator string `gorm:"primaryKey;size:1024"`

	// Target is the service it may get a ticket to.
	Target string `gorm:"primaryKey;size:1024"`
}

// RBCDGrant is the **resource-based** relation, which runs the other
// way round: which impersonators a resource is willing to accept
// delegation from.
//
// That inversion is the whole point of RBCD, and it is an
// administrative one rather than a technical one. A traditional grant
// is made by whoever administers the *impersonator*, so a front-end
// service's operator decides which back ends it may reach; a
// resource-based grant is made by whoever administers the *resource*,
// so the back end decides who may reach it. The second is the one a
// resource's owner can audit.
type RBCDGrant struct {
	// Resource is the service being reached.
	Resource string `gorm:"primaryKey;size:1024"`

	// Impersonator is the service allowed to reach it on somebody
	// else's behalf.
	Impersonator string `gorm:"primaryKey;size:1024"`
}

// ErrNotAllowed reports a delegation the realm has not authorised,
// which is upstream's KRB5KDC_ERR_BADOPTION from either relation.
var ErrNotAllowed = errors.New("delegation not allowed")

// AllowedToDelegate reports whether an impersonator may obtain a
// ticket to a target (check_allowed_to_delegate,
// lib/kdb/kdb5.c:2554-2568).
//
// **An empty target asks whether there are any grants at all**, which
// is upstream's `proxy == NULL' and is what s4u2self_forwardable uses
// to decide whether a server may hold forwardable S4U2Self tickets
// (kdc_util.c:1634-1636). The two questions share one method there
// and share one here.
func (s *Store) AllowedToDelegate(
	ctx context.Context,
	impersonator, target string,
) error {
	q := s.db.WithContext(ctx).Model(&Delegation{}).
		Where("impersonator = ?", impersonator)
	if target != "" {
		q = q.Where("target = ?", target)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return fmt.Errorf("store: delegation: %w", err)
	}
	if n == 0 {
		return ErrNotAllowed
	}
	return nil
}

// AllowedToDelegateFrom reports whether a resource accepts delegation
// from an impersonator (allowed_to_delegate_from, kdb5.c:2588-2603).
func (s *Store) AllowedToDelegateFrom(
	ctx context.Context,
	resource, impersonator string,
) error {
	var n int64
	err := s.db.WithContext(ctx).Model(&RBCDGrant{}).
		Where("resource = ? AND impersonator = ?",
			resource, impersonator).
		Count(&n).Error
	if err != nil {
		return fmt.Errorf("store: rbcd: %w", err)
	}
	if n == 0 {
		return ErrNotAllowed
	}
	return nil
}

// GrantDelegation records a traditional grant, idempotently.
func (s *Store) GrantDelegation(
	ctx context.Context,
	impersonator, target string,
) error {
	return upsert(ctx, s.db, &Delegation{
		Impersonator: impersonator, Target: target,
	})
}

// GrantRBCD records a resource-based grant, idempotently.
func (s *Store) GrantRBCD(
	ctx context.Context,
	resource, impersonator string,
) error {
	return upsert(ctx, s.db, &RBCDGrant{
		Resource: resource, Impersonator: impersonator,
	})
}

// upsert inserts a grant and does nothing if it is already there.
//
// Idempotent rather than an error, because a grant is a statement
// about what is permitted and saying it twice says the same thing --
// and because several KDCs share one database, so two administrators
// can race.
func upsert(ctx context.Context, db *gorm.DB, row any) error {
	err := db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(row).Error
	if err != nil {
		return fmt.Errorf("store: grant: %w", err)
	}
	return nil
}

// RevokeDelegation removes a traditional grant.
func (s *Store) RevokeDelegation(
	ctx context.Context,
	impersonator, target string,
) error {
	err := s.db.WithContext(ctx).
		Where("impersonator = ? AND target = ?",
			impersonator, target).
		Delete(&Delegation{}).Error
	if err != nil {
		return fmt.Errorf("store: delegation: %w", err)
	}
	return nil
}

// RevokeRBCD removes a resource-based grant.
func (s *Store) RevokeRBCD(
	ctx context.Context,
	resource, impersonator string,
) error {
	err := s.db.WithContext(ctx).
		Where("resource = ? AND impersonator = ?",
			resource, impersonator).
		Delete(&RBCDGrant{}).Error
	if err != nil {
		return fmt.Errorf("store: rbcd: %w", err)
	}
	return nil
}

// Delegations lists an impersonator's traditional grants, in a stable
// order so that an operator's listing does not shuffle.
func (s *Store) Delegations(
	ctx context.Context,
	impersonator string,
) ([]string, error) {
	var out []string
	err := s.db.WithContext(ctx).Model(&Delegation{}).
		Where("impersonator = ?", impersonator).
		Order("target").Pluck("target", &out).Error
	if err != nil {
		return nil, fmt.Errorf("store: delegation: %w", err)
	}
	return out, nil
}

// RBCDGrants lists the impersonators a resource accepts.
func (s *Store) RBCDGrants(
	ctx context.Context,
	resource string,
) ([]string, error) {
	var out []string
	err := s.db.WithContext(ctx).Model(&RBCDGrant{}).
		Where("resource = ?", resource).
		Order("impersonator").
		Pluck("impersonator", &out).Error
	if err != nil {
		return nil, fmt.Errorf("store: rbcd: %w", err)
	}
	return out, nil
}
