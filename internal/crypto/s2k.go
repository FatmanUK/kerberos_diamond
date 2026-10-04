package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// s2kConstant is the constant the PBKDF2 output is derived through to
// become a long-term key. RFC 3962 section 4.
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
// It is PBKDF2-HMAC-SHA1 over the password and salt, then DK(tkey,
// "kerberos"). params, when not empty, is the four-byte big-endian
// iteration count from a PA-ETYPE-INFO2 entry.
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
// It exists so the published RFC 3962 vectors can be tested: most of
// them use counts below the default, which is exactly what
// iterations() refuses, so they cannot be driven through s2kparams.
func (p *EncProfile) stringToKeyIter(
	password string,
	salt []byte,
	iter uint32,
) ([]byte, error) {
	tkey, err := pbkdf2.Key(
		sha1.New, password, salt, int(iter), p.KeyLength)
	if err != nil {
		return nil, err
	}
	return deriveKey(tkey, s2kConstant, p.KeyLength)
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
