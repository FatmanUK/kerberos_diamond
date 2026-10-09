package store

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Replay is one authenticator this realm has already accepted.
//
// Upstream's replay cache keeps the same thing in a per-host file or
// in process memory (`lib/krb5/rcache/`), and **that is the shape
// this table is replacing rather than the mechanism**. A realm with
// several administrative hosts has several caches, and an
// authenticator replayed to a different host than the one that saw it
// first is not caught -- which is the same single-host assumption
// that `kprop` exists to work around and that this project's database
// replaces everywhere else. One table is shared by every process that
// can reach it.
//
// It is also, after lockout, the second thing written on a request
// path, and it is worth being explicit that this does not weaken the
// crash-only rule: a lost Replay row costs a window in which one
// authenticator could be replayed, not a realm that will not start.
// Nothing here has to be rebuilt after a restart because every row
// expires within the clock skew anyway.
type Replay struct {
	// Tag identifies the authenticator, and it is **the last
	// octets of its ciphertext** -- the integrity tag, as many
	// octets as that enctype's checksum is long
	// (k5_rc_tag_from_ciphertext, rcache/rc_base.c:109-126).
	//
	// Not the client name, not the timestamp, and not a hash this
	// code computed: the tag a sender could not have produced
	// without the key, taken straight out of what it sent. Two
	// different authenticators collide only if their integrity
	// tags do.
	Tag []byte `gorm:"primaryKey;type:bytea"`

	// ExpiresAt is when this row stops meaning anything, which is
	// the moment the authenticator's own clock skew runs out. An
	// authenticator older than the skew is refused for being
	// stale before it is ever looked up here, so remembering it
	// past that point would buy nothing (k5_memrcache_store,
	// memrcache.c:176-186, discards entries on exactly that
	// test).
	ExpiresAt time.Time `gorm:"index;not null"`
}

// ErrReplay reports that an authenticator has been seen before, which
// is upstream's KRB5KRB_AP_ERR_REPEAT (memrcache.c:174).
var ErrReplay = errors.New("store: authenticator replayed")

// RecordAuthenticator remembers an authenticator and refuses one
// already recorded.
//
// The order is upstream's: stale rows go first and the insertion
// follows, so a tag whose row has expired is accepted again. Two
// statements rather than one, because `ON CONFLICT DO NOTHING`
// against a table still holding expired rows would report a replay
// for an authenticator that is merely unlucky.
func (s *Store) RecordAuthenticator(
	ctx context.Context,
	tag []byte,
	now time.Time,
	skew time.Duration,
) error {
	if len(tag) == 0 {
		return errors.New("store: empty replay tag")
	}
	db := s.db.WithContext(ctx)
	if err := db.Where("expires_at <= ?", now).
		Delete(&Replay{}).Error; err != nil {
		return err
	}
	row := &Replay{Tag: tag, ExpiresAt: now.Add(skew)}
	res := db.Clauses(clause.OnConflict{DoNothing: true}).
		Create(row)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrReplay
	}
	return nil
}

// ForgetAuthenticators empties the table, which only a test wants:
// nothing operational needs it, because every row expires on its own.
func (s *Store) ForgetAuthenticators(
	ctx context.Context,
) error {
	return s.db.WithContext(ctx).
		Session(&gorm.Session{AllowGlobalUpdate: true}).
		Delete(&Replay{}).Error
}
