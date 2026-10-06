package store

import (
	"fmt"
	"strings"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
	"golang.org/x/crypto/argon2"
)

// Where Argon2id fits, and where it cannot.
//
// Kerberos' string-to-key is part of the *protocol*. A client derives
// its long-term key from the password itself, using the enctype's
// string-to-key over the salt and s2kparams the KDC advertises in
// PA-ETYPE-INFO2. Replacing that with Argon2id would mean no stock
// client could ever derive the same key: the function is not
// negotiable, it is fixed by the enctype number on the wire. So a
// principal's long-term key stays PBKDF2, and that is not a decision
// this project gets to make differently while claiming to
// interoperate.
//
// What *is* this KDC's own business is the master key -- the one
// secret it holds, which no client ever sees and which protects every
// stored key. That is derived here with Argon2id, and the difference
// is worth having: PBKDF2 is cheap to attack with hardware, Argon2id
// is deliberately not, and the master key is the single thing an
// attacker with a database dump needs.
//
// The cost is paid once per process start, which a 12-factor KDC can
// afford and a password-checking path could not.

// MasterKDF names how a master key is derived from its password.
type MasterKDF string

// The two derivations.
//
// Argon2id is what this project writes. StringToKey is upstream's --
// PBKDF2 through the enctype's own string-to-key, exactly as
// kdb5_util create does -- and exists so a database created by MIT
// Kerberos can still be opened. It is read, never written.
const (
	KDFArgon2id    MasterKDF = "argon2id"
	KDFStringToKey MasterKDF = "string2key"
)

// Argon2id parameters.
//
// They are fixed in code rather than stored, because the master key
// is re-derived from the environment at every start and nothing
// persists that could carry them. The consequence is the thing to
// understand before changing any of them: raising a parameter changes
// the derived key, which makes every existing database unreadable.
// Doing it means re-keying, the same as changing the master password.
//
// The figures are the RFC 9106 second recommended option -- 64 MiB,
// three passes, four lanes -- chosen over the first (2 GiB) because a
// KDC should not need two gigabytes resident to start, and over
// anything smaller because the whole point is to be expensive.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// ErrBadKDF reports a master-key derivation this does not know.
var ErrBadKDF = fmt.Errorf("unknown master key derivation")

// ParseMasterKDF reads the name of a derivation.
func ParseMasterKDF(s string) (MasterKDF, error) {
	switch MasterKDF(strings.ToLower(strings.TrimSpace(s))) {
	case "", KDFArgon2id:
		return KDFArgon2id, nil
	case KDFStringToKey:
		return KDFStringToKey, nil
	}
	return "", fmt.Errorf("%w: %q, want %q or %q",
		ErrBadKDF, s, KDFArgon2id, KDFStringToKey)
}

// deriveArgon2id derives a master key with Argon2id.
//
// The salt is the one for K/M@REALM, the same salt the legacy
// derivation uses, so that realm plus password still determine the
// key completely and there is still nothing to stash. Argon2id wants
// at least eight bytes of salt and a realm name easily gives that; a
// realm short enough to fall below it is refused rather than padded,
// because padding would be a second rule nobody would remember.
func deriveArgon2id(
	realm, password string,
	keyLen int,
) ([]byte, error) {
	salt := crypto.Salt(realm, []string{"K", "M"})
	if len(salt) < 8 {
		return nil, fmt.Errorf(
			"realm %q gives a %d-byte salt, want 8+",
			realm, len(salt))
	}
	return argon2.IDKey([]byte(password), salt,
		argonTime, argonMemory, argonThreads,
		uint32(keyLen)), nil
}
