// Package crypto implements the Kerberos 5 encryption types.
//
// Six are supported, in three families. RFC 3962's
// aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96 are what an
// unconfigured client negotiates; RFC 8009's
// aes256-cts-hmac-sha384-192 and aes128-cts-hmac-sha256-128 are what
// a modern realm prefers; RFC 6803's camellia256-cts-cmac and
// camellia128-cts-cmac are the only other enctypes upstream has not
// deprecated.
//
// The families share almost nothing. RFC 3962 derives keys by
// n-folding a constant and encrypting it repeatedly, and MACs the
// *plaintext* before encrypting. RFC 8009 derives with a counter-mode
// HMAC and MACs the *ciphertext* after encrypting. RFC 6803 keeps RFC
// 3962's layout but replaces both primitives: a CMAC instead of a
// truncated HMAC, and SP 800-108 in *feedback* mode instead of the
// n-fold. So the row in the dispatch table carries the differing
// steps as functions rather than the table being consulted and then
// switched on: a switch would put that difference in six places
// instead of one, and adding a fourth family would mean finding all
// six.
package crypto

import (
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strings"
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
	Camellia128CTSCMAC     EncType = 25
	Camellia256CTSCMAC     EncType = 26
)

// The checksum types that go with them.
const (
	HMACSHA196AES128    CksumType = 15
	HMACSHA196AES256    CksumType = 16
	HMACSHA256128AES128 CksumType = 19
	HMACSHA384192AES256 CksumType = 20
	CMACCamellia128     CksumType = 17
	CMACCamellia256     CksumType = 18
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

	// newHash is the hash the PBKDF2 uses, and the HMAC where the
	// family has one.
	//
	// The RFC 6803 family has no hash of its own -- its MAC is a
	// CMAC, keyed with the block cipher -- and upstream leaves
	// the field NULL, whereupon pbkdf2_string_to_key substitutes
	// SHA-1 (s2k_pbkdf2.c:163). So these rows carry sha1.New for
	// the PBKDF2 alone and never reach an HMAC.
	newHash func() hash.Hash

	// newBlock makes the row's block cipher.
	//
	// It is in the row because the layout functions are shared
	// across families: sealDK and openDK are RFC 3962's and RFC
	// 6803's message layout both, differing only in the cipher
	// and the MAC.
	newBlock blockFunc

	// mac is the keyed message authentication code: an HMAC over
	// the row's hash, or a CMAC over the row's cipher.
	mac macFunc

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

	blockFunc func(key []byte) (cipher.Block, error)

	macFunc func(
		p *EncProfile,
		key, msg []byte,
	) ([]byte, error)
)

// profiles is the dispatch table, searched linearly as upstream's is
// (lib/crypto/krb/etypes.c:37-148). Six entries do not need an index,
// and a slice keeps the preference order visible -- which matters,
// because Supported() hands this order to a client as the KDC's own
// preference and the aes-sha2 pair belongs ahead of the aes-sha1 one.
//
// The camellia pair goes last because that is where the stock
// client's own default list puts it (init_ctx.c:59-66), behind even
// the deprecated types. Within the pair this table prefers 256 to
// 128, which upstream's client list does *not* -- it names
// camellia128 first -- but that list is a client's preference and
// this one is the KDC's, and every other pair here is stronger first.
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
		newBlock:           newAES,
		mac:                macHMAC,
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
		newBlock:           newAES,
		mac:                macHMAC,
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
		newBlock:           newAES,
		mac:                macHMAC,
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
		newBlock:           newAES,
		mac:                macHMAC,
		integrityKeyLength: 16,
		derive:             deriveDK,
		seal:               sealDK,
		open:               openDK,
		prf:                prfDK,
	},
	{
		EncType:            Camellia256CTSCMAC,
		Name:               "camellia256-cts-cmac",
		KeyLength:          32,
		BlockSize:          16,
		HeaderLength:       16,
		PaddingLength:      0,
		TrailerLength:      16,
		RequiredCksum:      CMACCamellia256,
		DefaultIterations:  32768,
		PRFLength:          16,
		newHash:            sha1.New,
		newBlock:           newCamellia,
		mac:                macCMAC,
		integrityKeyLength: 32,
		s2kPepper:          "camellia256-cts-cmac",
		derive:             deriveFeedbackCMAC,
		seal:               sealDK,
		open:               openDK,
		prf:                prfCMAC,
	},
	{
		EncType:            Camellia128CTSCMAC,
		Name:               "camellia128-cts-cmac",
		KeyLength:          16,
		BlockSize:          16,
		HeaderLength:       16,
		PaddingLength:      0,
		TrailerLength:      16,
		RequiredCksum:      CMACCamellia128,
		DefaultIterations:  32768,
		PRFLength:          16,
		newHash:            sha1.New,
		newBlock:           newCamellia,
		mac:                macCMAC,
		integrityKeyLength: 16,
		s2kPepper:          "camellia128-cts-cmac",
		derive:             deriveFeedbackCMAC,
		seal:               sealDK,
		open:               openDK,
		prf:                prfCMAC,
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

// ProfileForCksum returns the row whose required checksum type is the
// one named.
//
// A checksum type does not stand alone in this project the way it
// does upstream: there is no checksum table, because every keyed
// checksum any Kerberos message carries is the one its enctype
// requires (krb5int_c_mandatory_cksumtype, mandatory_sumtype.c:29-39
// returns exactly the row's required_ctype). So a checksum type
// identifies a row, and the row's TrailerLength is what
// krb5_c_checksum_length would answer.
//
// The PAC is the first thing that needs the lookup in this direction,
// because a PAC's buffers each name their own checksum type and a
// verifier has to honour what it was handed rather than recomputing
// from the key it holds -- a PAC built by a Windows KDC under a key
// this realm shares may still name a type this project does not
// implement, and the right answer then is "unsupported" and not a
// wrong verdict.
func ProfileForCksum(c CksumType) (*EncProfile, error) {
	for i := range profiles {
		if profiles[i].RequiredCksum == c {
			return &profiles[i], nil
		}
	}
	return nil, fmt.Errorf("checksum type %d: %w",
		c, ErrUnsupported)
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

// EncTypeByName looks an enctype up by the name krb5.conf uses.
//
// The names are the rows' own, which are upstream's
// (lib/crypto/krb/etypes.c), and the aliases upstream accepts are
// accepted too: `aes256-cts' and `aes128-cts' are what an operator
// actually types, and krb5_string_to_enctype takes them (etypes.c's
// aliases field).
func EncTypeByName(name string) (EncType, bool) {
	for i := range profiles {
		if strings.EqualFold(profiles[i].Name, name) {
			return profiles[i].EncType, true
		}
	}
	e, ok := encTypeAliases[strings.ToLower(name)]
	return e, ok
}

// encTypeAliases are the shorter spellings upstream accepts for the
// enctypes this project implements.
var encTypeAliases = map[string]EncType{
	"aes256-cts":      AES256CTSHMACSHA196,
	"aes256-sha1":     AES256CTSHMACSHA196,
	"aes128-cts":      AES128CTSHMACSHA196,
	"aes128-sha1":     AES128CTSHMACSHA196,
	"aes128-sha2":     AES128CTSHMACSHA256128,
	"aes256-sha2":     AES256CTSHMACSHA384192,
	"aes128-cts-sha2": AES128CTSHMACSHA256128,
	"aes256-cts-sha2": AES256CTSHMACSHA384192,
	"camellia128-cts": Camellia128CTSCMAC,
	"camellia256-cts": Camellia256CTSCMAC,
}
