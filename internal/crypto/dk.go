package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
)

// ErrIntegrity reports a ciphertext whose integrity tag does not
// match its contents.
var ErrIntegrity = errors.New("integrity check failed")

// Encrypt encrypts plain under key for the given usage.
//
// The message is
//
//	E(Ke, conf || plain) || HMAC(Ki, conf || plain)
//
// truncated to the enctype's trailer length -- the RFC 3961 "dk"
// profile. Two things about it are easy to get wrong and both are
// deliberate here:
//
// The HMAC covers the *plaintext*, not the ciphertext. This is
// MAC-then-encrypt, which the newer aes-sha2 types replace with
// encrypt-then-MAC; that difference is exactly why these live in a
// table rather than being the one true way to encrypt.
//
// There is no padding. Ciphertext stealing makes the encryption
// length-preserving, so PaddingLength is 0 and the output is always
// header + len(plain) + trailer.
func (p *EncProfile) Encrypt(
	key, plain []byte,
	usage Usage,
) ([]byte, error) {
	ke, ki, err := p.subkeys(key, usage)
	if err != nil {
		return nil, err
	}

	confounded := make([]byte, p.HeaderLength+len(plain))
	if _, err := rand.Read(
		confounded[:p.HeaderLength]); err != nil {
		return nil, err
	}
	copy(confounded[p.HeaderLength:], plain)

	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	ct, err := ctsEncrypt(block, nil, confounded)
	if err != nil {
		return nil, err
	}
	return append(ct, p.tag(ki, confounded)...), nil
}

// Decrypt reverses Encrypt, checking the integrity tag before
// returning anything.
func (p *EncProfile) Decrypt(
	key, ct []byte,
	usage Usage,
) ([]byte, error) {
	least := p.HeaderLength + p.TrailerLength
	if len(ct) < least {
		return nil, fmt.Errorf(
			"ciphertext is %d bytes, want at least %d",
			len(ct), least)
	}
	ke, ki, err := p.subkeys(key, usage)
	if err != nil {
		return nil, err
	}

	body := ct[:len(ct)-p.TrailerLength]
	want := ct[len(ct)-p.TrailerLength:]

	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	confounded, err := ctsDecrypt(block, nil, body)
	if err != nil {
		return nil, err
	}

	// hmac.Equal rather than bytes.Equal: the comparison is on a
	// value an attacker supplies, so it is done in constant time.
	if !hmac.Equal(p.tag(ki, confounded), want) {
		return nil, ErrIntegrity
	}
	return confounded[p.HeaderLength:], nil
}

// Checksum computes the keyed checksum for a message: HMAC under Kc,
// truncated to the checksum type's length.
func (p *EncProfile) Checksum(
	key, msg []byte,
	usage Usage,
) ([]byte, error) {
	kc, err := deriveKey(
		key, usageConstant(usage, constKc), p.KeyLength)
	if err != nil {
		return nil, err
	}
	return p.tag(kc, msg), nil
}

// VerifyChecksum reports whether a checksum matches a message.
func (p *EncProfile) VerifyChecksum(
	key, msg, sum []byte,
	usage Usage,
) error {
	want, err := p.Checksum(key, msg, usage)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, sum) {
		return ErrIntegrity
	}
	return nil
}

// subkeys derives the encryption and integrity keys for a usage.
func (p *EncProfile) subkeys(
	key []byte,
	usage Usage,
) (ke, ki []byte, err error) {
	ke, err = deriveKey(
		key, usageConstant(usage, constKe), p.KeyLength)
	if err != nil {
		return nil, nil, err
	}
	ki, err = deriveKey(
		key, usageConstant(usage, constKi), p.KeyLength)
	if err != nil {
		return nil, nil, err
	}
	return ke, ki, nil
}

// tag is HMAC-SHA1 truncated to the enctype's trailer length, which
// for these types is 96 bits of the 160 SHA-1 produces.
func (p *EncProfile) tag(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	return m.Sum(nil)[:p.TrailerLength]
}
