package crypto

import (
	"crypto/cipher"
	"errors"
)

// ErrShort reports a message too short for the mode to operate on.
var ErrShort = errors.New("message shorter than one block")

// AES-CBC with ciphertext stealing, in the CS3 ordering Kerberos
// uses.
//
// Writing P1..Pn for the plaintext blocks, where Pn may be short:
//
//	C1..C(n-1) = CBC(P1..P(n-1))
//	Cn         = E(pad(Pn) XOR C(n-1))
//	ciphertext = C1..C(n-2) || Cn || C(n-1) truncated to |Pn|
//
// So the final two blocks are always emitted swapped, and the output
// is exactly as long as the input. That length-preservation is the
// point: every length calculation in the protocol assumes it.
//
// The single-block case is NOT ciphertext stealing and does NOT use
// the caller's IV. Upstream encrypts it with plain CBC and a forced
// zero IV, discarding whatever ivec it was handed
// (lib/crypto/builtin/enc_provider/aes.c:253-261). Reproducing that
// exactly matters, because a key-derivation constant is exactly one
// block, so the whole derivation path goes through it.

// ctsEncrypt encrypts plain under block, returning as many bytes.
func ctsEncrypt(
	block cipher.Block,
	iv, plain []byte,
) ([]byte, error) {
	bs := block.BlockSize()
	if len(plain) < bs {
		return nil, ErrShort
	}
	if len(plain) == bs {
		return oneBlock(block, plain, true), nil
	}

	headLen, tailLen := split(len(plain), bs)
	head := make([]byte, headLen)
	cipher.NewCBCEncrypter(block, ivOrZero(iv, bs)).
		CryptBlocks(head, plain[:headLen])
	penult := head[headLen-bs:]

	// The short final block is zero-padded and chained onto the
	// last full one.
	padded := make([]byte, bs)
	copy(padded, plain[headLen:])
	last := make([]byte, bs)
	cipher.NewCBCEncrypter(block, penult).
		CryptBlocks(last, padded)

	out := make([]byte, len(plain))
	copy(out, head[:headLen-bs])
	copy(out[headLen-bs:], last)
	copy(out[headLen:], penult[:tailLen])
	return out, nil
}

// ctsDecrypt reverses ctsEncrypt.
func ctsDecrypt(
	block cipher.Block,
	iv, ct []byte,
) ([]byte, error) {
	bs := block.BlockSize()
	if len(ct) < bs {
		return nil, ErrShort
	}
	if len(ct) == bs {
		return oneBlock(block, ct, false), nil
	}

	headLen, tailLen := split(len(ct), bs)
	out := make([]byte, len(ct))

	// Decrypting the swapped-forward block with no chaining gives
	// pad(Pn) XOR C(n-1). Above |Pn| the padding is zero, so
	// those bytes *are* the missing tail of C(n-1).
	bare := make([]byte, bs)
	block.Decrypt(bare, ct[headLen-bs:headLen])

	penult := make([]byte, bs)
	copy(penult, ct[headLen:])
	copy(penult[tailLen:], bare[tailLen:])

	for i := 0; i < tailLen; i++ {
		out[headLen+i] = bare[i] ^ ct[headLen+i]
	}

	// With C(n-1) recovered, the leading blocks are plain CBC.
	stream := make([]byte, headLen)
	copy(stream, ct[:headLen-bs])
	copy(stream[headLen-bs:], penult)
	cipher.NewCBCDecrypter(block, ivOrZero(iv, bs)).
		CryptBlocks(out[:headLen], stream)
	return out, nil
}

// split divides a message length into the leading whole blocks and
// the final block, which is a whole block when the length divides
// evenly rather than being empty.
func split(n, bs int) (headLen, tailLen int) {
	tailLen = n % bs
	if tailLen == 0 {
		tailLen = bs
	}
	return n - tailLen, tailLen
}

// oneBlock is the single-block case: CBC with a forced zero IV.
func oneBlock(
	block cipher.Block,
	in []byte,
	encrypt bool,
) []byte {
	bs := block.BlockSize()
	zero := make([]byte, bs)
	out := make([]byte, bs)
	if encrypt {
		cipher.NewCBCEncrypter(block, zero).
			CryptBlocks(out, in)
	} else {
		cipher.NewCBCDecrypter(block, zero).
			CryptBlocks(out, in)
	}
	return out
}

// ivOrZero returns iv, or a block of zeroes when none was supplied.
func ivOrZero(iv []byte, bs int) []byte {
	if len(iv) == bs {
		return iv
	}
	return make([]byte, bs)
}
