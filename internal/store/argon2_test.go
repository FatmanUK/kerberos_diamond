package store

import (
	"bytes"
	"errors"
	"testing"

	"github.com/FatmanUK/diamond_krb/internal/crypto"
)

// Argon2id is what this project writes, so the default has to be it.
// A default that quietly fell back to PBKDF2 would leave every
// deployment with the weaker derivation and nothing would say so.
func TestArgon2idIsTheDefault(t *testing.T) {
	kdf, err := ParseMasterKDF("")
	if err != nil {
		t.Fatalf("ParseMasterKDF: %v", err)
	}
	if kdf != KDFArgon2id {
		t.Errorf("the default is %q, want %q",
			kdf, KDFArgon2id)
	}
	m, err := DeriveMasterKey(testRealm, testMasterPW,
		DefaultMasterKeyType)
	if err != nil {
		t.Fatalf("DeriveMasterKey: %v", err)
	}
	if m.KDF != KDFArgon2id {
		t.Errorf("DeriveMasterKey used %q", m.KDF)
	}
}

func TestParseMasterKDF(t *testing.T) {
	for _, in := range []string{
		"argon2id", "ARGON2ID", " argon2id ", "",
	} {
		got, err := ParseMasterKDF(in)
		if err != nil || got != KDFArgon2id {
			t.Errorf("%q gave (%q, %v)", in, got, err)
		}
	}
	if got, err := ParseMasterKDF("string2key"); err != nil ||
		got != KDFStringToKey {
		t.Errorf("string2key gave (%q, %v)", got, err)
	}
	_, err := ParseMasterKDF("pbkdf2")
	if !errors.Is(err, ErrBadKDF) {
		t.Errorf("an unknown name gave %v", err)
	}
}

// The two derivations must give different keys from the same inputs,
// or one of them is not doing what it says.
func TestTheTwoDerivationsDiffer(t *testing.T) {
	a := mustDerive(t, KDFArgon2id)
	l := mustDerive(t, KDFStringToKey)
	if bytes.Equal(a.Key, l.Key) {
		t.Fatal("Argon2id and string-to-key agree")
	}
	if len(a.Key) != len(l.Key) {
		t.Errorf("key lengths differ: %d and %d",
			len(a.Key), len(l.Key))
	}
}

// Each derivation is reproducible on its own, which is the property
// the whole no-stash-file arrangement rests on: realm plus password
// plus enctype determine the key and nothing is written down.
func TestEachDerivationIsReproducible(t *testing.T) {
	for _, kdf := range []MasterKDF{
		KDFArgon2id, KDFStringToKey,
	} {
		a := mustDerive(t, kdf)
		b := mustDerive(t, kdf)
		if !bytes.Equal(a.Key, b.Key) {
			t.Errorf("%s is not reproducible", kdf)
		}
	}
}

// The realm is part of the salt for both, so two realms sharing a
// password must not share a master key.
func TestTheRealmSeparatesMasterKeys(t *testing.T) {
	for _, kdf := range []MasterKDF{
		KDFArgon2id, KDFStringToKey,
	} {
		a, err := DeriveMasterKeyWith(kdf, testRealm,
			testMasterPW, DefaultMasterKeyType)
		if err != nil {
			t.Fatal(err)
		}
		b, err := DeriveMasterKeyWith(kdf, "OTHER.TEST",
			testMasterPW, DefaultMasterKeyType)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a.Key, b.Key) {
			t.Errorf("%s: two realms share a key", kdf)
		}
	}
}

// Key material sealed under one derivation's key must open under that
// same derivation and not the other. This is what an operator sees if
// KD_MASTER_KDF is wrong: nothing is corrupted, a key simply does not
// decrypt.
func TestLegacyMaterialNeedsTheLegacyDerivation(t *testing.T) {
	legacy := mustDerive(t, KDFStringToKey)
	argon := mustDerive(t, KDFArgon2id)

	key := bytes.Repeat([]byte{0x5A}, 32)
	blob, err := encodeKeyBlob(legacy.Key, legacy.EType, key)
	if err != nil {
		t.Fatalf("encodeKeyBlob: %v", err)
	}
	got, err := decodeKeyBlob(legacy.Key, legacy.EType, blob)
	if err != nil {
		t.Fatalf("the legacy key did not open it: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("the legacy round trip changed the key")
	}
	if _, err := decodeKeyBlob(
		argon.Key, argon.EType, blob); err == nil {
		t.Error("the Argon2id key opened legacy material")
	}
}

// The legacy derivation has to be upstream's exactly, or an imported
// MIT database cannot be read at all. This asserts it against
// crypto.StringToKey over the K/M salt directly, which is what
// kdb5_util create computes.
func TestLegacyDerivationIsUpstreams(t *testing.T) {
	m := mustDerive(t, KDFStringToKey)
	p, err := crypto.Profile(DefaultMasterKeyType)
	if err != nil {
		t.Fatal(err)
	}
	want, err := p.StringToKey(testMasterPW,
		crypto.Salt(testRealm, []string{"K", "M"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Key, want) {
		t.Errorf("\n got %X\nwant %X", m.Key, want)
	}
}

// A realm too short to salt Argon2id is refused rather than padded.
// Padding would be a second rule nobody would remember, and it would
// silently make two short realms share a key.
func TestArgon2idRefusesAShortSalt(t *testing.T) {
	_, err := DeriveMasterKeyWith(KDFArgon2id, "AB",
		testMasterPW, DefaultMasterKeyType)
	if err == nil {
		t.Fatal("accepted a four-byte salt")
	}
	// "AB" plus "KM" is four bytes; eight is the floor.
	if _, err := DeriveMasterKeyWith(KDFArgon2id, "ABCDEF",
		testMasterPW, DefaultMasterKeyType); err != nil {
		t.Errorf("refused an eight-byte salt: %v", err)
	}
}

// An unknown derivation is refused at the point of use too, not only
// when a name is parsed.
func TestDeriveMasterKeyWithRejectsAnUnknownKDF(t *testing.T) {
	_, err := DeriveMasterKeyWith(MasterKDF("scrypt"),
		testRealm, testMasterPW, DefaultMasterKeyType)
	if !errors.Is(err, ErrBadKDF) {
		t.Errorf("got %v, want ErrBadKDF", err)
	}
}

func mustDerive(t *testing.T, kdf MasterKDF) MasterKey {
	t.Helper()
	m, err := DeriveMasterKeyWith(kdf, testRealm, testMasterPW,
		DefaultMasterKeyType)
	if err != nil {
		t.Fatalf("%s: %v", kdf, err)
	}
	return m
}
