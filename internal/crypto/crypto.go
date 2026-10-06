// Package crypto implements the Kerberos 5 encryption types.
//
// Four are supported, in two families. RFC 3962's
// aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96 are what an
// unconfigured client negotiates; RFC 8009's
// aes256-cts-hmac-sha384-192 and aes128-cts-hmac-sha256-128 are what
// a modern realm prefers.
//
// The two families share almost nothing. RFC 3962 derives keys by
// n-folding a constant and encrypting it repeatedly, and MACs the
// *plaintext* before encrypting. RFC 8009 derives with a counter-mode
// HMAC and MACs the *ciphertext* after encrypting. So the row in the
// dispatch table carries the two differing steps as functions rather
// than the table being consulted and then switched on: a switch would
// put that difference in four places instead of one, and adding a
// third family would mean finding all four.
package crypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// EncType is a Kerberos encryption type number, as it appears on the
// wire.
type EncType int32

// CksumType is a Kerberos checksum type number.
type CksumType int32

// The encryption types this package implements.
const (
	AES128CTSHMACSHA196    EncType = 17
	AES256CTSHMACSHA196    EncType = 18
	AES128CTSHMACSHA256128 EncType = 19
	AES256CTSHMACSHA384192 EncType = 20
)

// The checksum types that go with them.
const (
	HMACSHA196AES128    CksumType = 15
	HMACSHA196AES256    CksumType = 16
	HMACSHA256128AES128 CksumType = 19
	HMACSHA384192AES256 CksumType = 20
)

// ErrUnsupported reports an encryption or checksum type this package
// does not implement.
var ErrUnsupported = errors.New("unsupported type")

// EncProfile is one row of the enctype table: everything that differs
// between encryption types.
//
// The shape follows upstream's krb5_keytypes
// (lib/crypto/krb/crypto_int.h:154-171), including the required
// checksum type and the message-length fields, because those are what
// callers outside this package need in order to size a message
// without knowing which enctype it is.
type EncProfile struct {
	EncType EncType
	Name    string

	// KeyLength is the size of a key in bytes.
	KeyLength int

	// BlockSize is the cipher's block size.
	BlockSize int

	// HeaderLength is the confounder prepended to a plaintext.
	HeaderLength int

	// PaddingLength is the multiple a plaintext is padded to. It
	// is 0 for these types: ciphertext stealing means no padding
	// is needed at all, which is a departure from the generic RFC
	// 3961 profile and the reason these have a row of their own.
	PaddingLength int

	// TrailerLength is the integrity tag appended to a
	// ciphertext.
	TrailerLength int

	// RequiredCksum is the checksum type a peer must accept with
	// this enctype.
	RequiredCksum CksumType

	// DefaultIterations is the PBKDF2 iteration count used when a
	// request carries no s2kparams, and also the floor below
	// which a supplied count is refused.
	DefaultIterations uint32

	// PRFLength is how many bytes the pseudo-random function
	// produces, which the enctype fixes and a caller cannot
	// choose. It is the cipher's block size for the RFC 3962
	// types and the full hash size for the aes-sha2 pair.
	PRFLength int

	// newHash is the hash every HMAC and the PBKDF2 use.
	newHash func() hash.Hash

	// integrityKeyLength is how long Ki and Kc are.
	//
	// It is not always the key length. RFC 3962 derives all three
	// subkeys at the cipher's key length; RFC 8009 derives Ke at
	// the key length but Ki and Kc at *half the hash size*
	// (enc_etm.c:75-78, checksum_etm.c:45-48), which for
	// aes256-sha384 is 24 bytes against a 32-byte key.
	integrityKeyLength int

	// s2kPepper prefixes the salt, with a NUL between them,
	// before PBKDF2 sees it.
	//
	// RFC 8009 puts the enctype's own name there
	// (krb5int_aes2_string_to_key, s2k_pbkdf2.c:196-203), so the
	// same password and salt give different keys for the two
	// aes-sha2 types. RFC 3962 has no pepper, and the empty
	// string here means none rather than an empty prefix plus a
	// NUL.
	s2kPepper string

	// derive, seal and open are the two steps the families do
	// differently. They are package functions taking the row, not
	// methods, so that a row literal can name them.
	derive deriveFunc
	seal   sealFunc
	open   openFunc
	prf    prfFunc
}

// The three per-family operations.
//
// derive produces one subkey of outLen bytes from a base key and a
// five-byte label. seal and open are the message layout: which of the
// plaintext and the ciphertext the MAC covers, and in what order.
type (
	deriveFunc func(
		p *EncProfile,
		base, label []byte,
		outLen int,
	) ([]byte, error)

	sealFunc func(
		p *EncProfile,
		ke, ki, plain []byte,
	) ([]byte, error)

	openFunc func(
		p *EncProfile,
		ke, ki, ct []byte,
	) ([]byte, error)

	prfFunc func(
		p *EncProfile,
		key, in []byte,
	) ([]byte, error)
)

// profiles is the dispatch table, searched linearly as upstream's is
// (lib/crypto/krb/etypes.c:37-148). Four entries do not need an
// index, and a slice keeps the preference order visible -- which
// matters, because Supported() hands this order to a client as the
// KDC's own preference and the aes-sha2 pair belongs ahead of the
// aes-sha1 one.
var profiles = []EncProfile{
	{
		EncType:            AES256CTSHMACSHA384192,
		Name:               "aes256-cts-hmac-sha384-192",
		KeyLength:          32,
		BlockSize:          16,
		HeaderLength:       16,
		PaddingLength:      0,
		TrailerLength:      24,
		RequiredCksum:      HMACSHA384192AES256,
		DefaultIterations:  32768,
		PRFLength:          48,
		newHash:            sha512.New384,
		integrityKeyLength: 24,
		s2kPepper:          "aes256-cts-hmac-sha384-192",
		derive:             deriveSP800108,
		seal:               sealETM,
		open:               openETM,
		prf:                prfSP800108,
	},
	{
		EncType:            AES128CTSHMACSHA256128,
		Name:               "aes128-cts-hmac-sha256-128",
		KeyLength:          16,
		BlockSize:          16,
		HeaderLength:       16,
		PaddingLength:      0,
		TrailerLength:      16,
		RequiredCksum:      HMACSHA256128AES128,
		DefaultIterations:  32768,
		PRFLength:          32,
		newHash:            sha256.New,
		integrityKeyLength: 16,
		s2kPepper:          "aes128-cts-hmac-sha256-128",
		derive:             deriveSP800108,
		seal:               sealETM,
		open:               openETM,
		prf:                prfSP800108,
	},
	{
		EncType:            AES256CTSHMACSHA196,
		Name:               "aes256-cts-hmac-sha1-96",
		KeyLength:          32,
		BlockSize:          16,
		HeaderLength:       16,
		PaddingLength:      0,
		TrailerLength:      12,
		RequiredCksum:      HMACSHA196AES256,
		DefaultIterations:  4096,
		PRFLength:          16,
		newHash:            sha1.New,
		integrityKeyLength: 32,
		derive:             deriveDK,
		seal:               sealDK,
		open:               openDK,
		prf:                prfDK,
	},
	{
		EncType:            AES128CTSHMACSHA196,
		Name:               "aes128-cts-hmac-sha1-96",
		KeyLength:          16,
		BlockSize:          16,
		HeaderLength:       16,
		PaddingLength:      0,
		TrailerLength:      12,
		RequiredCksum:      HMACSHA196AES128,
		DefaultIterations:  4096,
		PRFLength:          16,
		newHash:            sha1.New,
		integrityKeyLength: 16,
		derive:             deriveDK,
		seal:               sealDK,
		open:               openDK,
		prf:                prfDK,
	},
}

// Profile returns the row for an encryption type.
func Profile(e EncType) (*EncProfile, error) {
	for i := range profiles {
		if profiles[i].EncType == e {
			return &profiles[i], nil
		}
	}
	return nil, fmt.Errorf("enctype %d: %w", e, ErrUnsupported)
}

// Supported lists the encryption types this package implements, most
// preferred first.
func Supported() []EncType {
	out := make([]EncType, len(profiles))
	for i := range profiles {
		out[i] = profiles[i].EncType
	}
	return out
}

// CipherLength gives the size of the ciphertext that Encrypt will
// produce for a plaintext of n bytes.
//
// It is exact rather than an upper bound, because ciphertext stealing
// makes the encryption length-preserving: the only growth is the
// confounder and the integrity tag.
func (p *EncProfile) CipherLength(n int) int {
	return p.HeaderLength + n + p.TrailerLength
}
