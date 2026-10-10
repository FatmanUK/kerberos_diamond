package store

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
)

// kdbKeyUsage is the key usage stored key material is encrypted
// under.
//
// Zero is not one of the protocol usage numbers at all
// (include/krb5/krb5.hin:944-1007). The database simply passes 0 to
// krb5_c_decrypt (lib/kdb/decrypt_key.c:91), so there is no constant
// upstream to cite and nothing to look it up by.
const kdbKeyUsage = crypto.Usage(0)

// maxStoredKeyLen is the largest true key length a blob may declare.
// Upstream loads the prefix with load_16_le into an int16_t and
// rejects a negative result (lib/kdb/decrypt_key.c:80-82), so the top
// bit is unusable and the real ceiling is 32767 rather than 65535.
const maxStoredKeyLen = 0x7FFF

var (
	// ErrBadKeyBlob reports stored key material that cannot be
	// the layout the KDB uses.
	ErrBadKeyBlob = errors.New("malformed stored key")

	// ErrNoMatchingKey reports that no key matched the requested
	// enctype, salt type and key version.
	ErrNoMatchingKey = errors.New("no matching key")

	// ErrNoPermittedKey reports that a key matched but its
	// enctype is not one this implementation supports. Upstream
	// keeps the two apart (KRB5_KDB_NO_PERMITTED_KEY), and so
	// does this, because they call for different KDC errors and
	// different operator action.
	ErrNoPermittedKey = errors.New("no permitted key")
)

// encodeKeyBlob builds the stored form of a key: a 2-byte
// little-endian true key length followed by the key encrypted under
// the master key.
//
// The length prefix is not redundant. The ciphertext is produced by a
// generic enctype whose plaintext may be longer than the key -- the
// confounder and any padding are inside it -- so the true length has
// to travel separately, and a reader that trusted the decrypted
// length would hand out a key with trailing rubbish on it.
func encodeKeyBlob(
	mkey []byte,
	mkeyType crypto.EncType,
	key []byte,
) ([]byte, error) {
	if len(key) > maxStoredKeyLen {
		return nil, fmt.Errorf("%w: key is %d bytes, max %d",
			ErrBadKeyBlob, len(key), maxStoredKeyLen)
	}
	p, err := crypto.Profile(mkeyType)
	if err != nil {
		return nil, err
	}
	ct, err := p.Encrypt(mkey, key, kdbKeyUsage)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2, 2+len(ct))
	binary.LittleEndian.PutUint16(out, uint16(len(key)))
	return append(out, ct...), nil
}

// decodeKeyBlob reverses encodeKeyBlob.
//
// The blob's own enctype is not recorded anywhere: upstream sets
// cipher.enctype to ENCTYPE_UNKNOWN and lets the master keyblock
// decide (lib/kdb/decrypt_key.c:84-91). So the caller has to know
// which enctype the master key is, and a Key row's EType field is the
// *key's* enctype, not the ciphertext's -- a distinction that costs
// an afternoon if it is missed.
func decodeKeyBlob(
	mkey []byte,
	mkeyType crypto.EncType,
	blob []byte,
) ([]byte, error) {
	if len(blob) < 2 {
		return nil, fmt.Errorf(
			"%w: %d bytes, want at least 2",
			ErrBadKeyBlob, len(blob))
	}
	keyLen := int(binary.LittleEndian.Uint16(blob[:2]))
	if keyLen > maxStoredKeyLen {
		return nil, fmt.Errorf(
			"%w: declares %d bytes, negative to upstream",
			ErrBadKeyBlob, keyLen)
	}
	p, err := crypto.Profile(mkeyType)
	if err != nil {
		return nil, err
	}
	plain, err := p.Decrypt(mkey, blob[2:], kdbKeyUsage)
	if err != nil {
		return nil, err
	}
	if keyLen > len(plain) {
		return nil, fmt.Errorf(
			"%w: declares %d bytes, decrypted %d",
			ErrBadKeyBlob, keyLen, len(plain))
	}
	// The plaintext may be longer than the key and is truncated,
	// never padded (decrypt_key.c:93-98).
	return plain[:keyLen], nil
}

// Sentinels for SelectKey, matching upstream's
// krb5_dbe_def_search_enctype (lib/kdb/kdb_default.c:47-101).
const (
	// AnyEType and AnySaltType match whatever is stored.
	AnyEType    int32 = -1
	AnySaltType int32 = -1

	// HighestKVNO matches only the greatest key version present,
	// which is what a kvno of 0 means on the wire.
	HighestKVNO int32 = 0

	// AnyKVNO matches every version, which the preauth path uses
	// to try each key in turn.
	AnyKVNO int32 = -1
)

// SelectKey finds the next key matching an enctype, salt type and key
// version, starting at index *start and advancing it past the match.
//
// This is krb5_dbe_def_search_enctype ported literally, cursor and
// all, because the preauth path depends on being able to resume: a
// client may hold any of several keys and the KDC tries each matching
// one. Two details are load-bearing and neither is obvious:
//
// The key list must be sorted by kvno descending. Upstream re-sorts
// after every fetch (lib/kdb/kdb5.c:856-858) and this loop *breaks*
// on the first row below the requested version rather than
// continuing, so an unsorted list silently finds nothing.
//
// A kvno of 0 means the highest version present, resolved from the
// first element -- which is only the highest because of that sort.
func SelectKey(
	keys []Key,
	start *int,
	etype, salttype, kvno int32,
) (*Key, error) {
	if len(keys) == 0 {
		return nil, ErrNoMatchingKey
	}
	if etype != AnyEType && !permitted(etype) {
		return nil, ErrNoPermittedKey
	}
	if kvno == HighestKVNO {
		kvno = keys[0].KVNO
	}
	i, unsupported := scanKeys(
		keys, *start, etype, salttype, kvno)
	if i < 0 {
		if *start == 0 && unsupported {
			return nil, ErrNoPermittedKey
		}
		return nil, ErrNoMatchingKey
	}
	*start = i + 1
	return &keys[i], nil
}

// scanKeys returns the index of the next match, or -1, and whether it
// passed over a key whose enctype is unsupported.
//
// The order of the four tests is upstream's and so is the break,
// which fires only after the enctype and salt type have matched. That
// is why they cannot be folded into one predicate: a break hoisted
// above the enctype test would stop the scan on a row that never
// matched.
func scanKeys(
	keys []Key,
	from int,
	etype, salttype, kvno int32,
) (int, bool) {
	unsupported := false
	for i := from; i < len(keys); i++ {
		k := &keys[i]
		if etype != AnyEType && k.EType != etype {
			continue
		}
		if salttype >= 0 && k.SaltType != salttype {
			continue
		}
		if kvno >= 0 && k.KVNO < kvno {
			break
		}
		if kvno >= 0 && k.KVNO != kvno {
			continue
		}
		if !permitted(k.EType) {
			unsupported = true
			continue
		}
		return i, unsupported
	}
	return -1, unsupported
}

// permitted reports whether this implementation can use an enctype at
// all. Upstream's krb5_is_permitted_enctype consults a configurable
// list; here the list is whatever internal/crypto implements, which
// is narrower and cannot be widened by configuration.
func permitted(etype int32) bool {
	for _, e := range crypto.Supported() {
		if int32(e) == etype {
			return true
		}
	}
	return false
}
