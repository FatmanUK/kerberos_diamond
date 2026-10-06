package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// deriveSP800108 is RFC 8009's KDF-HMAC-SHA2, which is NIST SP
// 800-108 counter mode with a single block
// (k5_sp800_108_counter_hmac, lib/crypto/builtin/kdf.c:32-70):
//
//	truncate(HMAC(base, 0x00000001 || label || 0x00 || context ||
//	              be32(outLen * 8)),
//	         outLen)
//
// The context is always empty for key derivation; upstream passes a
// separate context only for the pseudo-random function
// (prf_aes2.c:41).
//
// Three details are each enough to produce a plausible wrong key. The
// counter is a four-byte big-endian 1 and not a single byte. There is
// a NUL between the label and the context even when the context is
// empty, so it is never absent. And the trailing length is in *bits*,
// not bytes -- a 24-byte output ends the input with 00 00 00 C0.
//
// Nothing is n-folded and nothing is encrypted, which is the whole
// difference from deriveDK: this family's derivation touches AES only
// when it later encrypts a message.
func deriveSP800108(
	p *EncProfile,
	base, label []byte,
	outLen int,
) ([]byte, error) {
	return sp800108(p, base, label, nil, outLen)
}

// sp800108 is the same with a context, which only the pseudo-random
// function supplies.
func sp800108(
	p *EncProfile,
	base, label, context []byte,
	outLen int,
) ([]byte, error) {
	m := hmac.New(p.newHash, base)
	if outLen > m.Size() {
		return nil, fmt.Errorf(
			"%w: cannot derive %d bytes from %s",
			ErrUnsupported, outLen, p.Name)
	}
	var counter, bits [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)
	binary.BigEndian.PutUint32(bits[:], uint32(outLen)*8)

	m.Write(counter[:])
	m.Write(label)
	m.Write([]byte{0})
	m.Write(context)
	m.Write(bits[:])
	return m.Sum(nil)[:outLen], nil
}

// sealETM is RFC 8009's layout:
//
//	E(Ke, conf || plain) || truncate(HMAC(Ki, IV || E(...)))
//
// Encrypt-then-MAC, where RFC 3962 is MAC-then-encrypt, and the MAC
// covers the *ciphertext* rather than the plaintext. Two things in
// that one line are easy to get wrong:
//
// The IV is part of the MAC input (hmac_ivec_data, enc_etm.c:95-131).
// Kerberos never supplies one, so it is a block of zeros -- but it is
// *present*, not omitted, and a MAC over the ciphertext alone
// verifies against nothing any other implementation produces.
//
// The confounder is inside the ciphertext the MAC covers, because it
// was encrypted along with the plaintext.
func sealETM(
	p *EncProfile,
	ke, ki, plain []byte,
) ([]byte, error) {
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
	return append(ct, p.etmTag(ki, ct)...), nil
}

// openETM reverses sealETM.
//
// The tag is checked *before* the ciphertext is decrypted, which is
// the point of encrypt-then-MAC: a forged or altered ciphertext never
// reaches the cipher at all.
func openETM(
	p *EncProfile,
	ke, ki, ct []byte,
) ([]byte, error) {
	body := ct[:len(ct)-p.TrailerLength]
	want := ct[len(ct)-p.TrailerLength:]

	// hmac.Equal rather than bytes.Equal: the comparison is on a
	// value an attacker supplies, so it is done in constant time.
	if !hmac.Equal(p.etmTag(ki, body), want) {
		return nil, ErrIntegrity
	}
	block, err := aes.NewCipher(ke)
	if err != nil {
		return nil, err
	}
	confounded, err := ctsDecrypt(block, nil, body)
	if err != nil {
		return nil, err
	}
	return confounded[p.HeaderLength:], nil
}

// etmTag is the integrity tag over the initialisation vector followed
// by the ciphertext.
//
// The vector is a block of zeros because Kerberos supplies none, and
// upstream builds exactly that when its ivec argument is NULL
// (enc_etm.c:104-110). It is prepended rather than skipped.
func (p *EncProfile) etmTag(ki, ct []byte) []byte {
	m := hmac.New(p.newHash, ki)
	m.Write(make([]byte, p.BlockSize))
	m.Write(ct)
	return m.Sum(nil)[:p.TrailerLength]
}
