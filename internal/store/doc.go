// Package store holds the principal database.
//
// Nothing is implemented yet. This replaces the flat file Kerberos 5
// uses with Postgres through GORM, so a principal's key data, salts,
// attributes, lifetimes and policy become real columns rather than a
// packed record.
package store
