// Package crypto implements the Kerberos 5 encryption types.
//
// Two are supported: aes256-cts-hmac-sha1-96 and
// aes128-cts-hmac-sha1-96, the RFC 3962 pair an unconfigured client
// negotiates. They are reached through a dispatch table rather than
// called directly, even at two entries, because the families that
// follow derive keys by entirely different schemes and have to be
// rows in this table rather than special cases beside it.
package crypto

import (
	"errors"
	"fmt"
)

// EncType is a Kerberos encryption type number, as it appears on the
// wire.
type EncType int32

// CksumType is a Kerberos checksum type number.
type CksumType int32

// The encryption types this package implements.
const (
	AES128CTSHMACSHA196 EncType = 17
	AES256CTSHMACSHA196 EncType = 18
)

// The checksum types that go with them.
const (
	HMACSHA196AES128 CksumType = 15
	HMACSHA196AES256 CksumType = 16
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
}

// profiles is the dispatch table, searched linearly as upstream's is
// (lib/crypto/krb/etypes.c:37-148). Two entries do not need an index,
// and a slice keeps the preference order visible.
var profiles = []EncProfile{
	{
		EncType:           AES256CTSHMACSHA196,
		Name:              "aes256-cts-hmac-sha1-96",
		KeyLength:         32,
		BlockSize:         16,
		HeaderLength:      16,
		PaddingLength:     0,
		TrailerLength:     12,
		RequiredCksum:     HMACSHA196AES256,
		DefaultIterations: 4096,
	},
	{
		EncType:           AES128CTSHMACSHA196,
		Name:              "aes128-cts-hmac-sha1-96",
		KeyLength:         16,
		BlockSize:         16,
		HeaderLength:      16,
		PaddingLength:     0,
		TrailerLength:     12,
		RequiredCksum:     HMACSHA196AES128,
		DefaultIterations: 4096,
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
