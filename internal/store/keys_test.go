package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/FatmanUK/kerberos_diamond/internal/crypto"
)

// testMKey is a master key for the unit tests, derived the same way a
// real one is so the blob layout is exercised end to end.
func testMKey(t *testing.T) MasterKey {
	t.Helper()
	m, err := DeriveMasterKey(
		testRealm, testMasterPW, DefaultMasterKeyType)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	return m
}

// The master key is determined by realm, password and enctype alone
// -- there is nothing random in it and no stash file to lose. That is
// the property the whole no-stash-file decision rests on.
func TestMasterKeyIsReproducible(t *testing.T) {
	a := testMKey(t)
	b := testMKey(t)
	if !bytes.Equal(a.Key, b.Key) {
		t.Error("two derivations disagree")
	}
	other, err := DeriveMasterKey(
		"OTHER.TEST", testMasterPW, DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Key, other.Key) {
		t.Error("the realm does not affect the master key")
	}
}

// The salt is the one for K/M@REALM, which is the realm followed by
// the components "K" and "M" with no separator. Getting it wrong
// gives a master key that cannot read an existing KDB and fails as
// corruption rather than as a wrong password.
func TestMasterKeySaltIsForKSlashM(t *testing.T) {
	salt := crypto.Salt(testRealm, []string{"K", "M"})
	if want := testRealm + "KM"; string(salt) != want {
		t.Errorf("salt is %q, want %q", salt, want)
	}
}

func TestKeyBlobRoundTrips(t *testing.T) {
	m := testMKey(t)
	key := bytes.Repeat([]byte{0xA5}, 32)
	blob, err := encodeKeyBlob(m.Key, m.EType, key)
	if err != nil {
		t.Fatalf("encodeKeyBlob: %v", err)
	}
	got, err := decodeKeyBlob(m.Key, m.EType, blob)
	if err != nil {
		t.Fatalf("decodeKeyBlob: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Errorf("\n got %X\nwant %X", got, key)
	}
}

// The 2-byte prefix is little-endian and is the *true* key length,
// not the blob's. A big-endian prefix would read a 32-byte key as
// 8192 bytes and fail as corruption.
func TestKeyBlobPrefixIsLittleEndianTrueLength(t *testing.T) {
	m := testMKey(t)
	key := bytes.Repeat([]byte{1}, 32)
	blob, err := encodeKeyBlob(m.Key, m.EType, key)
	if err != nil {
		t.Fatal(err)
	}
	got := binary.LittleEndian.Uint16(blob[:2])
	if got != 32 {
		t.Errorf("prefix says %d, want 32", got)
	}
	// The ciphertext is longer than the key -- confounder and
	// integrity tag -- which is exactly why the prefix exists.
	if len(blob)-2 <= len(key) {
		t.Errorf("ciphertext is %d bytes for a %d-byte key",
			len(blob)-2, len(key))
	}
}

// The plaintext is truncated to the declared length, never padded. A
// decoder that returned the whole plaintext would hand out a key with
// the enctype's padding on the end of it.
func TestKeyBlobTruncatesToTheDeclaredLength(t *testing.T) {
	m := testMKey(t)
	key := bytes.Repeat([]byte{7}, 32)
	blob, err := encodeKeyBlob(m.Key, m.EType, key)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(blob[:2], 16)
	got, err := decodeKeyBlob(m.Key, m.EType, blob)
	if err != nil {
		t.Fatalf("decodeKeyBlob: %v", err)
	}
	if len(got) != 16 {
		t.Errorf("got %d bytes, want 16", len(got))
	}
}

func TestKeyBlobRejectsRubbish(t *testing.T) {
	m := testMKey(t)
	good, err := encodeKeyBlob(m.Key, m.EType, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	short := []byte{0x20}
	_, err = decodeKeyBlob(m.Key, m.EType, short)
	if err == nil {
		t.Error("accepted a one-byte blob")
	}

	// A length upstream would read as negative.
	negative := append([]byte{}, good...)
	binary.LittleEndian.PutUint16(negative[:2], 0x8000)
	_, err = decodeKeyBlob(m.Key, m.EType, negative)
	if !errors.Is(err, ErrBadKeyBlob) {
		t.Errorf("negative length gave %v", err)
	}

	// A length longer than the plaintext.
	toolong := append([]byte{}, good...)
	binary.LittleEndian.PutUint16(toolong[:2], 0x7FFF)
	_, err = decodeKeyBlob(m.Key, m.EType, toolong)
	if !errors.Is(err, ErrBadKeyBlob) {
		t.Errorf("overlong length gave %v", err)
	}

	// Tampering must fail the integrity check, not decrypt.
	bad := append([]byte{}, good...)
	bad[len(bad)-1] ^= 0xFF
	_, err = decodeKeyBlob(m.Key, m.EType, bad)
	if err == nil {
		t.Error("a tampered blob decrypted")
	}
}

// keyList builds a descending-kvno list the way the database returns
// one.
func keyList(entries ...[2]int32) []Key {
	out := make([]Key, len(entries))
	for i, e := range entries {
		out[i] = Key{
			KVNO:     e[0],
			EType:    e[1],
			KeyIndex: int32(i),
		}
	}
	return out
}

const (
	aes256 = int32(crypto.AES256CTSHMACSHA196)
	aes128 = int32(crypto.AES128CTSHMACSHA196)
)

// A kvno of 0 means the highest version present, resolved from the
// first element -- which is only the highest because the list is
// sorted descending.
func TestSelectKeyHighestKVNO(t *testing.T) {
	keys := keyList(
		[2]int32{3, aes256}, [2]int32{3, aes128},
		[2]int32{1, aes256}, [2]int32{1, aes128},
	)
	start := 0
	k, err := SelectKey(keys, &start, aes128,
		AnySaltType, HighestKVNO)
	if err != nil {
		t.Fatalf("SelectKey: %v", err)
	}
	if k.KVNO != 3 {
		t.Errorf("got kvno %d, want 3", k.KVNO)
	}
}

// The cursor is what the preauth path relies on: a client may hold
// any of several keys and the KDC tries each matching one in turn.
func TestSelectKeyCursorWalksEveryMatch(t *testing.T) {
	keys := keyList(
		[2]int32{2, aes256}, [2]int32{2, aes128},
		[2]int32{1, aes256},
	)
	start := 0
	var seen []int32
	for {
		k, err := SelectKey(keys, &start, AnyEType,
			AnySaltType, AnyKVNO)
		if err != nil {
			break
		}
		seen = append(seen, k.KVNO)
	}
	if len(seen) != 3 {
		t.Errorf("walked %d keys, want 3: %v",
			len(seen), seen)
	}
}

// The scan breaks on the first row below the requested version, which
// is only correct because the list is sorted. This is the assertion
// that fails if the ORDER BY is ever dropped.
func TestSelectKeyStopsBelowTheRequestedKVNO(t *testing.T) {
	keys := keyList(
		[2]int32{3, aes256},
		[2]int32{1, aes256},
	)
	start := 0
	if _, err := SelectKey(keys, &start, aes256,
		AnySaltType, 2); err == nil {
		t.Error("found a key for a version that is not there")
	}

	// Ascending order is what a missing ORDER BY would give, and
	// HighestKVNO then resolves to the lowest and finds nothing
	// above it.
	ascending := keyList(
		[2]int32{1, aes256},
		[2]int32{3, aes256},
	)
	start = 0
	k, err := SelectKey(ascending, &start, aes256,
		AnySaltType, HighestKVNO)
	if err != nil {
		t.Fatalf("SelectKey: %v", err)
	}
	if k.KVNO == 3 {
		t.Error("an unsorted list worked, so this test " +
			"no longer proves the sort is needed")
	}
}

// An enctype this implementation does not support is a different
// answer from no key at all: upstream keeps KRB5_KDB_NO_PERMITTED_KEY
// apart, and the two call for different KDC errors.
func TestSelectKeySeparatesUnsupportedFromMissing(t *testing.T) {
	keys := keyList([2]int32{1, 23}) // rc4-hmac
	start := 0
	_, err := SelectKey(keys, &start, AnyEType,
		AnySaltType, HighestKVNO)
	if !errors.Is(err, ErrNoPermittedKey) {
		t.Errorf("got %v, want ErrNoPermittedKey", err)
	}

	start = 0
	_, err = SelectKey(nil, &start, AnyEType,
		AnySaltType, HighestKVNO)
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Errorf("got %v, want ErrNoMatchingKey", err)
	}
}
