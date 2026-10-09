package store

import (
	"context"
	"fmt"
	"time"
)

// Lockout is what the three lockout policy fields say about one
// principal at one moment, resolved so that a caller does not have to
// know the rules.
//
// Upstream puts the rules in each database back end rather than in
// the KDC -- there are three copies, in db2, lmdb and ldap
// (plugins/kdb/db2/lockout.c and its siblings) -- because the
// counters live with the data and have to be updated atomically with
// it. Here there is one place because there is one back end.
type Lockout struct {
	// Locked reports whether an AS exchange must be refused.
	Locked bool

	// Until is when the lock lifts, zero meaning never: a lockout
	// duration of zero locks the principal permanently and only
	// an administrator can clear it.
	Until time.Time
}

// LockoutFor resolves a principal's state (locked_check_p,
// plugins/kdb/db2/lockout.c:84-105).
//
// The order of the tests is upstream's and each one matters: a
// maximum of zero is no lockout at all, a count below the maximum is
// not locked however old the failures are, and a duration of zero
// means the lock never lifts on its own.
func (s *Store) LockoutFor(
	ctx context.Context,
	p *Principal,
	now time.Time,
) (Lockout, error) {
	pol, err := s.PolicyFor(ctx, p)
	if err != nil || pol == nil || pol.PWMaxFail == 0 {
		return Lockout{}, err
	}
	if p.FailAuthCount < pol.PWMaxFail {
		return Lockout{}, nil
	}
	if pol.PWLockoutDuration == 0 {
		return Lockout{Locked: true}, nil
	}
	until := p.LastFailed.Add(
		time.Duration(pol.PWLockoutDuration) * time.Second)
	if now.Before(until) {
		return Lockout{Locked: true, Until: until}, nil
	}
	return Lockout{}, nil
}

// The outcomes a lockout counter is kept for. Upstream audits exactly
// three statuses and ignores every other (krb5_db2_lockout_audit,
// lockout.c:150-158): a success, a failed pre-authentication, and a
// bad integrity check. Nothing else says anything about whether the
// client knew the password.
type Outcome int

const (
	// Succeeded is an exchange the client proved itself in.
	Succeeded Outcome = iota

	// FailedPreauth is a pre-authentication that did not verify.
	FailedPreauth
)

// RecordOutcome updates a principal's lockout counters, and writes
// only when something changed.
//
// **This is the first thing in this project to write to the database
// on the request path**, which is a departure worth naming: the KDC
// has otherwise held nothing an exchange leaves behind. It is also
// where the architecture pays off rather than costing -- upstream has
// to replicate fail_auth_count between KDCs as an
// incremental-propagation delta (lib/kdb/kdb_convert.c:76), and
// several KDCs over one Postgres share the counter for free.
//
// The subtlety is in the success case, and upstream explains it in a
// comment: the counter is reset "only ... if the entry required
// preauthentication, otherwise we have no idea" (lockout.c:177-178).
// A principal with no pre-authentication requirement gets a ticket
// without ever proving it knows the password, so a successful
// exchange says nothing and must not clear a count of failures.
func (s *Store) RecordOutcome(
	ctx context.Context,
	p *Principal,
	outcome Outcome,
	now time.Time,
) error {
	pol, err := s.PolicyFor(ctx, p)
	if err != nil {
		return err
	}
	// **A divergence, and a deliberate one.** With no lockout
	// policy in force there is nothing the counters are for, so
	// nothing is written at all. Upstream writes last_success on
	// every authenticated exchange regardless, gated only by a
	// disable_last_success option that exists because the write
	// is expensive -- and a KDC that writes on every login has
	// given up the property that makes it cheap to run several.
	//
	// So a realm that has not asked for lockout keeps the
	// crash-only guarantee intact, and a realm that has asked
	// pays for what it asked for.
	if pol == nil || pol.PWMaxFail == 0 {
		return nil
	}
	locked, err := s.LockoutFor(ctx, p, now)
	if err != nil {
		return err
	}
	// An already-locked principal is left alone, which upstream
	// does too and explains: in most cases the request was
	// refused before reaching here, but an integrity failure can
	// arrive before any policy check (lockout.c:168-172).
	if locked.Locked {
		return nil
	}
	if !applyOutcome(p, pol, outcome, now) {
		return nil
	}
	return s.saveLockout(ctx, p)
}

// applyOutcome mutates the counters and reports whether anything
// moved.
func applyOutcome(
	p *Principal,
	pol *Policy,
	outcome Outcome,
	now time.Time,
) bool {
	now = now.UTC().Truncate(time.Second)
	if outcome == Succeeded {
		// See RecordOutcome: without a preauth requirement a
		// success proves nothing.
		if p.Attributes&AttrRequiresPreAuth == 0 {
			return false
		}
		p.FailAuthCount = 0
		p.LastSuccess = now
		return true
	}
	// A failure older than the policy's interval does not count
	// towards the next lockout (lockout.c:190-194).
	if pol != nil && pol.PWFailCountInterval != 0 {
		stale := p.LastFailed.Add(time.Duration(
			pol.PWFailCountInterval) * time.Second)
		if now.After(stale) {
			p.FailAuthCount = 0
		}
	}
	p.LastFailed = now
	p.FailAuthCount++
	return true
}

// saveLockout writes just the three counters.
//
// Not through Save, deliberately: Save replaces a principal's whole
// key list and every row hanging off it, which is far too much for a
// counter and would make a failed password attempt rewrite every key
// the principal has.
func (s *Store) saveLockout(
	ctx context.Context,
	p *Principal,
) error {
	err := s.db.WithContext(ctx).Model(&Principal{}).
		Where("name = ?", p.Name).
		Updates(map[string]any{
			"last_success":    p.LastSuccess,
			"last_failed":     p.LastFailed,
			"fail_auth_count": p.FailAuthCount,
		}).Error
	if err != nil {
		return fmt.Errorf("store: lockout: %w", err)
	}
	return nil
}

// Unlock clears a principal's failure count, which is kadmin's
// modprinc -unlock.
//
// Upstream also records the moment of the unlock, as tl-data, and
// consults it on the next failure to decide whether to reset the
// counter again (lockout.c:88-91, :185-189). That exists for
// replicas: a KDC whose copy of the counter is stale needs to know an
// unlock happened after the failures it can see. With one shared
// database there is no stale copy, so zeroing the counter is the
// whole of it -- another mechanism the architecture removes rather
// than reimplements.
func (s *Store) Unlock(
	ctx context.Context,
	p *Principal,
) error {
	p.FailAuthCount = 0
	return s.saveLockout(ctx, p)
}
