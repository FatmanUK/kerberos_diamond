package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// The key and plaintext upstream exercises CTS with, from
// lib/crypto/crypto_tests/t_cts.c.
const (
	ctsKey   = "chicken teriyaki"
	ctsPlain = "I would like the General Gau's Chicken, " +
		"please, and wonton soup."
)

// The lengths are upstream's own list: either side of a block
// boundary, exactly on one, and a whole number of blocks.
var ctsLengths = []int{17, 31, 32, 47, 48, 64}

func TestCTSRoundTrip(t *testing.T) {
	block, err := aes.NewCipher([]byte(ctsKey))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)

	for _, n := range ctsLengths {
		plain := []byte(ctsPlain)[:n]
		ct, err := ctsEncrypt(block, iv, plain)
		if err != nil {
			t.Fatalf("len %d: encrypt: %v", n, err)
		}
		// CTS is length-preserving; that is the whole point
		// of it, and a padded output would break every length
		// calculation in the protocol.
		if len(ct) != n {
			t.Errorf("len %d: ciphertext is %d bytes",
				n, len(ct))
		}
		got, err := ctsDecrypt(block, iv, ct)
		if err != nil {
			t.Fatalf("len %d: decrypt: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("len %d: round trip"+
				"\n got %X\nwant %X", n, got, plain)
		}
	}
}

// Exactly one block must be plain CBC with a zero IV, ignoring the IV
// it was handed. Upstream does this deliberately, and the derivation
// path depends on it, so it is pinned here rather than left to be
// noticed later.
func TestCTSSingleBlockIgnoresTheIV(t *testing.T) {
	block, err := aes.NewCipher([]byte(ctsKey))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	plain := []byte(ctsPlain)[:aes.BlockSize]

	zero := make([]byte, aes.BlockSize)
	withZero, err := ctsEncrypt(block, zero, plain)
	if err != nil {
		t.Fatalf("encrypt with a zero IV: %v", err)
	}

	nonzero := bytes.Repeat([]byte{0xA5}, aes.BlockSize)
	withNonzero, err := ctsEncrypt(block, nonzero, plain)
	if err != nil {
		t.Fatalf("encrypt with a set IV: %v", err)
	}

	if !bytes.Equal(withZero, withNonzero) {
		t.Errorf("the IV changed a single-block result:"+
			"\n zero IV %X\n set IV  %X",
			withZero, withNonzero)
	}

	// And it really is plain ECB-equivalent for one block, which
	// is what a zero-IV CBC of one block reduces to.
	want := make([]byte, aes.BlockSize)
	block.Encrypt(want, plain)
	if !bytes.Equal(withZero, want) {
		t.Errorf("one block\n got %X\nwant %X",
			withZero, want)
	}
}

// Anything shorter than a block has no defined CTS result and must be
// refused rather than silently padded.
func TestCTSRefusesAShortMessage(t *testing.T) {
	block, err := aes.NewCipher([]byte(ctsKey))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)

	if _, err := ctsEncrypt(
		block, iv, []byte("short"),
	); err == nil {
		t.Error("encrypt accepted a sub-block message")
	}
	if _, err := ctsDecrypt(
		block, iv, []byte("short"),
	); err == nil {
		t.Error("decrypt accepted a sub-block message")
	}
}

// A whole number of blocks must come out as CBC with the last two
// blocks swapped -- that is what CS3 is -- so the swap is checked
// against a plain CBC encryption rather than only round-tripped.
func TestCTSWholeBlocksAreCBCWithASwap(t *testing.T) {
	block, err := aes.NewCipher([]byte(ctsKey))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	plain := []byte(ctsPlain)[:32]

	ct, err := ctsEncrypt(block, iv, plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cbc := cbcEncrypt(t, block, iv, plain)
	bs := aes.BlockSize
	wantFirst := cbc[bs:]
	wantSecond := cbc[:bs]
	if !bytes.Equal(ct[:bs], wantFirst) ||
		!bytes.Equal(ct[bs:], wantSecond) {
		t.Errorf("not CBC with the final two blocks swapped"+
			"\n got %X\nCBC  %X", ct, cbc)
	}
}

// cbcEncrypt is plain CBC, for comparing against.
func cbcEncrypt(
	t *testing.T,
	block cipher.Block,
	iv, plain []byte,
) []byte {
	t.Helper()
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out
}
