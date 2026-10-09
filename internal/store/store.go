// Package store holds the principal database.
//
// This replaces the flat file Kerberos 5 uses with Postgres through
// GORM, so a principal's key data, salts, attributes, lifetimes and
// policy become real columns rather than a packed record. The schema
// is not invented: it follows the relations kadmin/dbutil/tabdump.c
// already projects krb5_db_entry into, so a tabdump and a SELECT line
// up field for field.
//
// Key material is still encrypted. The master-key indirection is kept
// -- see MasterKey -- so that a database dump does not hand over
// every principal's long-term key.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ErrNotFound reports a principal that is not in the database.
//
// It is deliberately one error for both the client and the server
// principal. The KDC answers them with different protocol codes, so
// the distinction is the caller's to make and not something to encode
// here.
var ErrNotFound = errors.New("principal not found")

// Store is the principal database.
type Store struct {
	db   *gorm.DB
	mkey MasterKey
}

// Open connects to Postgres and makes sure the schema is present.
//
// The URL carries everything, search_path included. Setting the
// schema with a SET statement instead would reach exactly one pooled
// connection and silently leak across the rest, which is the failure
// the tests here assert against.
func Open(url string, mkey MasterKey) (*Store, error) {
	if err := mkey.check(); err != nil {
		return nil, err
	}
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := limitPool(db); err != nil {
		return nil, err
	}
	s := &Store{db: db, mkey: mkey}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Pool bounds. A KDC's queries are short and one per request, so a
// small pool is enough, and an unbounded one is actively wrong here
// for a reason the crash-only design makes sharper: several KDCs
// share one database, and a herd of them restarting at once would
// otherwise open as many connections as they had requests in flight
// and exhaust it for each other.
//
// The suite found this before a deployment could. `go test ./...`
// runs packages in parallel, and with no cap the two database-backed
// packages together passed Postgres' default hundred-client limit and
// failed with "sorry, too many clients already" -- intermittently,
// which is the worst way to find out.
const (
	maxOpenConns = 8
	maxIdleConns = 2
	connLifetime = 30 * time.Minute
)

// limitPool bounds the connection pool.
func limitPool(db *gorm.DB) error {
	sql, err := db.DB()
	if err != nil {
		return fmt.Errorf("store: pool: %w", err)
	}
	sql.SetMaxOpenConns(maxOpenConns)
	sql.SetMaxIdleConns(maxIdleConns)
	// A lifetime bound is what lets a connection follow the
	// database rather than the process: a failover moves the
	// primary and an idle connection pinned to the old one would
	// keep answering until something used it.
	sql.SetConnMaxLifetime(connLifetime)
	return nil
}

// migrate creates or updates the tables.
func (s *Store) migrate() error {
	err := s.db.AutoMigrate(
		&Principal{}, &Key{}, &StringAttr{},
		&TLDatum{}, &Alias{}, &Policy{}, &HistoryKey{},
		&Replay{},
	)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// MasterKey is the key stored key material is sealed with.
//
// It is exposed because provisioning happens outside the KDC -- the
// administrative subcommands derive keys and have to seal them with
// the same key the KDC will unseal them with.
func (s *Store) MasterKey() MasterKey { return s.mkey }

// Close releases the connection pool.
func (s *Store) Close() error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}

// Ping reports whether the database is reachable.
//
// It exists for the health endpoint, and it deliberately asks the
// *database* rather than inspecting a cached flag. A KDC can only
// answer requests it can look principals up for, so a readiness check
// that reported on anything else would be a check on the wrong thing.
func (s *Store) Ping(ctx context.Context) error {
	db, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}
