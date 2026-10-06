package crypto

import (
	"crypto/pbkdf2"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// s2kConstant is the label the PBKDF2 output is derived through to
// become a long-term key. RFC 3962 section 4 and RFC 8009 section 5
// both use the same eight bytes.
var s2kConstant = []byte("kerberos")

// maxIterations is upstream's ceiling on an s2kparams iteration count
// (lib/crypto/krb/s2k_pbkdf2.c:104).
const maxIterations = 0x1000000

// ErrWeakIterations reports an s2kparams iteration count below the
// enctype's default.
var ErrWeakIterations = errors.New(
	"iteration count below the default")

// StringToKey turns a password into a long-term key.
//
// It is PBKDF2 over the password and the *peppered* salt, then the
// row's derivation of the result with the label "kerberos". params,
// when not empty, is the four-byte big-endian iteration count from a
// PA-ETYPE-INFO2 entry.
//
// Everything that differs between the families is in the row: which
// hash the PBKDF2 uses, how many iterations it defaults to, whether
// the salt is peppered, and how the result is derived.
func (p *EncProfile) StringToKey(
	password string,
	salt, params []byte,
) ([]byte, error) {
	iter, err := p.iterations(params)
	if err != nil {
		return nil, err
	}
	return p.stringToKeyIter(password, salt, iter)
}

// stringToKeyIter is StringToKey with the iteration count already
// settled.
//
// It exists so the published vectors can be tested: most of RFC
// 3962's use counts below the default, which is exactly what
// iterations() refuses, so they cannot be driven through s2kparams.
func (p *EncProfile) stringToKeyIter(
	password string,
	salt []byte,
	iter uint32,
) ([]byte, error) {
	tkey, err := pbkdf2.Key(p.newHash, password,
		p.pepperedSalt(salt), int(iter), p.KeyLength)
	if err != nil {
		return nil, err
	}
	return p.derive(p, tkey, s2kConstant, p.KeyLength)
}

// pepperedSalt prefixes the salt with the enctype's name and a NUL.
//
// RFC 8009 does this (krb5int_aes2_string_to_key by way of
// pbkdf2_string_to_key, lib/crypto/krb/s2k_pbkdf2.c:140-160,
// :196-203) so that one password and salt give *different* keys for
// aes128-sha256 and aes256-sha384. Without it the two enctypes' keys
// for a principal would be related, which is the thing the pepper
// exists to prevent.
//
// RFC 3962 has no pepper at all, and that is not the same as an empty
// one: an empty pepper would still contribute the NUL separator and
// change every key.
func (p *EncProfile) pepperedSalt(salt []byte) []byte {
	if p.s2kPepper == "" {
		return salt
	}
	out := make([]byte, 0,
		len(p.s2kPepper)+1+len(salt))
	out = append(out, p.s2kPepper...)
	out = append(out, 0)
	return append(out, salt...)
}

// iterations reads the PBKDF2 iteration count out of s2kparams.
//
// A count *below* the enctype's default is refused rather than
// honoured. That is upstream's behaviour as of 1.22
// (lib/crypto/krb/s2k_pbkdf2.c:116-126) and it matters: the field
// arrives from the network, so without the floor a KDC could talk a
// client into deriving its key with one iteration.
func (p *EncProfile) iterations(params []byte) (uint32, error) {
	if len(params) == 0 {
		return p.DefaultIterations, nil
	}
	if len(params) != 4 {
		return 0, fmt.Errorf(
			"s2kparams is %d bytes, want 4", len(params))
	}
	iter := binary.BigEndian.Uint32(params)
	if iter == 0 {
		// Upstream refuses this rather than reading it as
		// 2^32.
		return 0, errors.New("s2kparams iteration count is 0")
	}
	if iter < p.DefaultIterations {
		return 0, fmt.Errorf("%d: %w",
			iter, ErrWeakIterations)
	}
	if iter > maxIterations {
		return 0, fmt.Errorf(
			"iteration count %d exceeds the maximum %d",
			iter, maxIterations)
	}
	return iter, nil
}

// Salt builds the default salt for a principal: the realm followed by
// the name components, concatenated with no separator at all.
//
// The missing separator is deliberate and is upstream's
// krb5_principal2salt (lib/krb5/krb/pr_to_salt.c:36-67). It means
// different principals can collide -- realm EXAMPLE.COM with name
// "ab" salts the same as realm EXAMPLE.COMa with name "b" -- and that
// is simply how Kerberos salts. Inserting a separator would make
// every key this project derives disagree with every other
// implementation, and the failure would surface as "bad password".
func Salt(realm string, components []string) []byte {
	var b strings.Builder
	b.WriteString(realm)
	for _, c := range components {
		b.WriteString(c)
	}
	return []byte(b.String())
}
