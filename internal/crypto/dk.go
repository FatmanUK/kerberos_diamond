package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrIntegrity reports a ciphertext whose integrity tag does not
// match its contents.
var ErrIntegrity = errors.New("integrity check failed")

// Encrypt encrypts plain under key for the given usage.
//
// The layout is the enctype's own; this derives the two subkeys and
// hands them to the row's seal function. There is no padding in
// either family: ciphertext stealing makes the encryption
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
	return p.seal(p, ke, ki, plain)
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
	return p.open(p, ke, ki, ct)
}

// sealDK is the RFC 3961 "dk" profile's layout:
//
//	E(Ke, conf || plain) || MAC(Ki, conf || plain)
//
// truncated to the trailer length. The MAC covers the *plaintext*,
// not the ciphertext -- MAC-then-encrypt, which RFC 8009 replaces
// with the reverse. That difference is the whole reason these are
// rows in a table and not one true way to encrypt.
//
// It is shared with RFC 6803, whose layout is the same to the octet
// (krb5int_dk_cmac_encrypt, lib/crypto/krb/enc_dk_cmac.c:88-133:
// confounder, checksum of the plaintext, then encrypt). The cipher
// and the MAC come out of the row, so this function does not know
// which family it is serving.
func sealDK(
	p *EncProfile,
	ke, ki, plain []byte,
) ([]byte, error) {
	confounded := make([]byte, p.HeaderLength+len(plain))
	if _, err := rand.Read(
		confounded[:p.HeaderLength]); err != nil {
		return nil, err
	}
	copy(confounded[p.HeaderLength:], plain)

	block, err := p.newBlock(ke)
	if err != nil {
		return nil, err
	}
	ct, err := ctsEncrypt(block, nil, confounded)
	if err != nil {
		return nil, err
	}
	sum, err := p.tag(ki, confounded)
	if err != nil {
		return nil, err
	}
	return append(ct, sum...), nil
}

// openDK reverses sealDK.
func openDK(
	p *EncProfile,
	ke, ki, ct []byte,
) ([]byte, error) {
	body := ct[:len(ct)-p.TrailerLength]
	want := ct[len(ct)-p.TrailerLength:]

	block, err := p.newBlock(ke)
	if err != nil {
		return nil, err
	}
	confounded, err := ctsDecrypt(block, nil, body)
	if err != nil {
		return nil, err
	}
	sum, err := p.tag(ki, confounded)
	if err != nil {
		return nil, err
	}

	// hmac.Equal rather than bytes.Equal: the comparison is on a
	// value an attacker supplies, so it is done in constant time.
	if !hmac.Equal(sum, want) {
		return nil, ErrIntegrity
	}
	return confounded[p.HeaderLength:], nil
}

// Checksum computes the keyed checksum for a message: the row's MAC
// under Kc, truncated to the checksum type's length.
//
// Every family computes it the same way once Kc is in hand, so this
// is not a per-row function -- what differs is how Kc is derived, how
// long it is and which MAC, and all three are already in the row.
func (p *EncProfile) Checksum(
	key, msg []byte,
	usage Usage,
) ([]byte, error) {
	kc, err := p.derive(p, key, usageConstant(usage, constKc),
		p.integrityKeyLength)
	if err != nil {
		return nil, err
	}
	return p.tag(kc, msg)
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
//
// Ke is the cipher's key length and Ki is the row's integrity key
// length, which are the same thing for RFC 3962 and are not for RFC
// 8009 -- an aes256-sha384 Ki is 24 bytes against a 32-byte Ke.
func (p *EncProfile) subkeys(
	key []byte,
	usage Usage,
) (ke, ki []byte, err error) {
	ke, err = p.derive(p, key, usageConstant(usage, constKe),
		p.KeyLength)
	if err != nil {
		return nil, nil, err
	}
	ki, err = p.derive(p, key, usageConstant(usage, constKi),
		p.integrityKeyLength)
	if err != nil {
		return nil, nil, err
	}
	return ke, ki, nil
}

// tag is the row's keyed MAC truncated to the enctype's trailer
// length: 96 bits of SHA-1's 160 for RFC 3962, exactly half the hash
// for RFC 8009, and the whole of the CMAC for RFC 6803, whose output
// is the block size already.
//
// It returns an error because a CMAC has to build a block cipher and
// that can refuse a key, where an HMAC takes any key at all.
func (p *EncProfile) tag(key, msg []byte) ([]byte, error) {
	sum, err := p.mac(p, key, msg)
	if err != nil {
		return nil, err
	}
	return sum[:p.TrailerLength], nil
}

// macHMAC is the keyed MAC of both AES families: HMAC over the row's
// hash, untruncated -- tag does the truncating, because how much is
// kept is the row's business and not the MAC's.
func macHMAC(p *EncProfile, key, msg []byte) ([]byte, error) {
	m := hmac.New(p.newHash, key)
	m.Write(msg)
	return m.Sum(nil), nil
}

// newAES is the block-cipher constructor for the four AES rows.
func newAES(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
