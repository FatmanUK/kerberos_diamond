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
	"errors"
	"fmt"

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
	s := &Store{db: db, mkey: mkey}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// migrate creates or updates the tables.
func (s *Store) migrate() error {
	err := s.db.AutoMigrate(
		&Principal{}, &Key{}, &StringAttr{},
		&TLDatum{}, &Alias{},
	)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (s *Store) Close() error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
