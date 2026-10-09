package spnego

import (
	"bytes"
	"testing"
)

// The fixed part of an 0x8003 checksum, and the thing about it that
// catches a reimplementation: **it is little-endian**, in a protocol
// that is big-endian everywhere else. RFC 4121 §4.1.1 specifies it
// that way and upstream writes it with k5_buf_add_uint32_le
// (init_sec_context.c:333-335).
func TestChecksumIsLittleEndian(t *testing.T) {
	c := &Checksum{Flags: FlagMutual | FlagReplay}
	for i := range c.ChannelBindings {
		c.ChannelBindings[i] = byte(i)
	}
	out := c.Marshal()
	if len(out) != minLen {
		t.Fatalf("%d octets, want %d", len(out), minLen)
	}
	// 16 as four little-endian octets, not 00 00 00 10.
	if !bytes.Equal(out[:4], []byte{0x10, 0, 0, 0}) {
		t.Errorf("length is % x", out[:4])
	}
	// FlagMutual|FlagReplay is 6, so 06 00 00 00.
	if !bytes.Equal(out[20:], []byte{0x06, 0, 0, 0}) {
		t.Errorf("flags are % x", out[20:])
	}
	back, err := ParseChecksum(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Flags != c.Flags ||
		back.ChannelBindings != c.ChannelBindings {
		t.Errorf("got %+v", back)
	}
}

// A bindings length that is not exactly sixteen is refused rather
// than skipped over (accept_sec_context.c:527-532), which closes the
// obvious way to make the flags word land where an attacker chose.
func TestChecksumRefusesAWrongBindingsLength(t *testing.T) {
	good := (&Checksum{Flags: FlagMutual}).Marshal()
	for _, n := range []byte{0, 4, 8, 17, 0xff} {
		bad := append([]byte{}, good...)
		bad[0] = n
		if _, err := ParseChecksum(bad); err == nil {
			t.Errorf("a length of %d was accepted", n)
		}
	}
	if _, err := ParseChecksum(good[:minLen-1]); err == nil {
		t.Error("a short checksum was accepted")
	}
}

// Only a subset of the initiator's flags is honoured
// (INITIATOR_FLAGS, :413-417), and the one left out is the one that
// matters: a client asking for delegation does not get the flag by
// asking, because upstream sets it only after a credential has
// actually been read and stored (:578).
func TestOnlySomeInitiatorFlagsAreHonoured(t *testing.T) {
	c := &Checksum{Flags: ^uint32(0)}
	got := c.Accepted()
	if got&FlagDeleg != 0 {
		t.Error("the delegation flag was honoured")
	}
	for _, f := range []uint32{FlagAnon, FlagProtReady,
		FlagTrans, FlagDelegPolicy, FlagChannelBound} {
		if got&f != 0 {
			t.Errorf("flag %#x was honoured", f)
		}
	}
	for _, f := range []uint32{FlagMutual, FlagReplay,
		FlagSequence, FlagConf, FlagInteg, FlagDCEStyle,
		FlagIdentify, FlagExtError} {
		if got&f == 0 {
			t.Errorf("flag %#x was dropped", f)
		}
	}
}

// A forwarded credential is read only when four octets remain *and*
// the delegation flag is set (:555). Neither alone is enough, and the
// header is two octets little-endian where an extension's is four
// octets big-endian -- a difference upstream's own comment calls out
// (:582-583) and the easiest thing here to transcribe backwards.
func TestDelegationAndExtensionsUseDifferentHeaders(t *testing.T) {
	cred := []byte("a KRB-CRED would go here")
	c := &Checksum{
		Flags:      FlagMutual | FlagDeleg,
		DelegCred:  cred,
		Extensions: []Extension{{ID: 2, Body: []byte("fin")}},
	}
	out := c.Marshal()
	// 01 00 then the length, both little-endian.
	if !bytes.Equal(out[minLen:minLen+4],
		[]byte{0x01, 0x00, byte(len(cred)), 0x00}) {
		t.Errorf("deleg header is % x",
			out[minLen:minLen+4])
	}
	back, err := ParseChecksum(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.DelegCred, cred) {
		t.Errorf("credential is %q", back.DelegCred)
	}
	if len(back.Extensions) != 1 ||
		back.Extensions[0].ID != 2 {
		t.Fatalf("extensions are %+v", back.Extensions)
	}
	// Without the flag the same octets are an extension, which is
	// the gate working rather than a tolerance.
	c.Flags &^= FlagDeleg
	back, err = ParseChecksum(c.Marshal())
	if err == nil && back.DelegCred != nil {
		t.Error("a credential was read with no flag set")
	}
}
