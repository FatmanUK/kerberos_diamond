package wire

import (
	"bytes"
	"testing"
)

// PA-PAC-OPTIONS has no reference encoding -- upstream's asn.1 suite
// has no entry for it -- so what is pinned here is the shape by hand,
// the way KDC-PROXY-MESSAGE and ChangePasswdData already are.
//
// The shape that matters is that the flags field is a **full
// KerberosFlags**: thirty-two bits whatever is set, which is one
// unused-bits octet of zero and then four content octets. So an
// element with nothing set is the same length as one with everything
// set, which is why the golden harness compares this element by its
// flags rather than by its length.
func TestPAPACOptionsIsAlwaysThirtyTwoBits(t *testing.T) {
	for _, f := range []Flags{0, PACOptRBCD, 0xFFFFFFFF} {
		der, err := MarshalPAPACOptions(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(der) != 11 {
			t.Errorf("%#08x encoded to %d octets: % X",
				uint32(f), len(der), der)
		}
		back, err := UnmarshalPAPACOptions(der)
		if err != nil {
			t.Fatal(err)
		}
		if back != f {
			t.Errorf("%#08x came back as %#08x",
				uint32(f), uint32(back))
		}
	}
}

// RBCD is bit 3 of the first octet, which is what 0x10000000 means
// once the bit ordering is applied -- and getting that wrong is the
// failure that looks like the client asking for nothing.
func TestRBCDLandsWhereTheCPutsIt(t *testing.T) {
	der, err := MarshalPAPACOptions(PACOptRBCD)
	if err != nil {
		t.Fatal(err)
	}
	// SEQUENCE { [0] BIT STRING { 00 10 00 00 00 } }
	want := []byte{
		0x30, 0x09, 0xA0, 0x07, 0x03, 0x05, 0x00,
		0x10, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(der, want) {
		t.Errorf("got % X\nwant % X", der, want)
	}
}

// A peer that trims the bit string is accepted and the missing
// low-order bits read as zero, which is what flagsFromBitString does
// everywhere else and what upstream's decoder does.
func TestAShortPACOptionsIsAccepted(t *testing.T) {
	// SEQUENCE { [0] BIT STRING { 00 10 } }
	in := []byte{0x30, 0x06, 0xA0, 0x04, 0x03, 0x02,
		0x00, 0x10}
	got, err := UnmarshalPAPACOptions(in)
	if err != nil {
		t.Fatal(err)
	}
	if got != PACOptRBCD {
		t.Errorf("%#08x, want %#08x",
			uint32(got), uint32(PACOptRBCD))
	}
}
