package store

import (
	"errors"
	"fmt"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
)

// ErrNoMasterKey reports a master key that was never derived.
var ErrNoMasterKey = errors.New("master key not set")

// ErrWrongMKVNO reports key material encrypted under a master key
// version this process did not load.
var ErrWrongMKVNO = errors.New("unknown master key version")

// MasterKey is the key every stored key is encrypted under.
//
// Kerberos Diamond keeps upstream's master-key indirection rather
// than relying on database-level encryption, and the reason is the
// threat model: a KDC assumes that reading the database is not the
// same as holding every principal's long-term key, and a pg_dump of
// plaintext key columns would end that assumption. The indirection is
// kept; the stash file is not.
//
// Instead the key is derived at startup from KD_MASTER_PASSWORD, by
// string-to-key over the salt for K/M@REALM -- exactly what kdb5_util
// create does (kadmin/dbutil/kdb5_create.c:223-231). Realm plus
// password plus enctype therefore determine it completely, so there
// is nothing on disk to stash, nothing to lose, and a replacement
// container derives the same key from the same environment. That
// suits a 12-factor process; it also means the password is the only
// secret and must be treated as one.
//
// One master key is loaded, not a list. Upstream carries a list with
// a per-entry mkvno saying which version was used, tries each in
// turn, and reloads from disk once on total failure -- which is how a
// live KDC survives a rollover (lib/kdb/kdb5.c). None of that is here
// yet: rows whose MKVNO is neither zero nor this one are refused with
// ErrWrongMKVNO rather than reported as a bad password, so the gap is
// visible instead of baffling.
type MasterKey struct {
	Key   []byte
	EType crypto.EncType

	// KVNO is this master key's version, which kdb5_util create
	// writes as 1.
	KVNO int32
}

// DefaultMasterKeyType is the enctype kdb5_util create uses unless
// told otherwise.
const DefaultMasterKeyType = crypto.AES256CTSHMACSHA196

// DeriveMasterKey derives the master key from a password and realm.
//
// The salt is the one for K/M@REALM: the realm followed by the
// components "K" and "M" with no separator, which is what
// krb5_principal2salt produces and what the C KDC's stash file was
// made from.
func DeriveMasterKey(
	realm, password string,
	etype crypto.EncType,
) (MasterKey, error) {
	p, err := crypto.Profile(etype)
	if err != nil {
		return MasterKey{}, err
	}
	salt := crypto.Salt(realm, []string{"K", "M"})
	key, err := p.StringToKey(password, salt, nil)
	if err != nil {
		return MasterKey{}, err
	}
	return MasterKey{Key: key, EType: etype, KVNO: 1}, nil
}

func (m MasterKey) check() error {
	if len(m.Key) == 0 {
		return ErrNoMasterKey
	}
	if _, err := crypto.Profile(m.EType); err != nil {
		return err
	}
	return nil
}

// usableFor reports whether this master key can decrypt a row.
//
// A stored MKVNO of zero means "not recorded", which upstream
// resolves to the lowest version in its loaded list; with one key
// loaded that is this one.
func (m MasterKey) usableFor(k *Key) error {
	if k.MKVNO == 0 || k.MKVNO == m.KVNO {
		return nil
	}
	return fmt.Errorf("%w: row says %d, this process has %d",
		ErrWrongMKVNO, k.MKVNO, m.KVNO)
}
