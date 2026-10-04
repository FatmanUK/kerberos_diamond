package wire

import (
	"encoding/asn1"
	"fmt"
)

// Flags is a KerberosFlags value: KDCOptions in a request,
// TicketFlags in a ticket. Both are the same 32-bit BIT STRING.
//
// Bit 0 is the *most* significant bit of the first octet, which is
// the opposite of the intuitive ordering and the reason a flags bug
// usually shows up as the wrong flag entirely rather than as no flag.
// The constants below are named by bit position, and Has converts.
type Flags uint32

// Ticket flags, by bit number, from RFC 4120 section 5.3.
const (
	FlagReserved Flags = 1 << (31 - iota)
	FlagForwardable
	FlagForwarded
	FlagProxiable
	FlagProxy
	FlagMayPostdate
	FlagPostdated
	FlagInvalid
	FlagRenewable
	FlagInitial
	FlagPreAuthent
	FlagHWAuthent
	FlagTransitedPolicyChecked
	FlagOKAsDelegate
	FlagEncPARep
	FlagAnonymous
)

// KDC options, by bit number, from RFC 4120 section 5.4.1. They share
// the wire representation with ticket flags and mostly the bit
// positions too, which is why upstream converts between them by
// masking rather than mapping.
const (
	OptForwardable   Flags = FlagForwardable
	OptForwarded     Flags = FlagForwarded
	OptProxiable     Flags = FlagProxiable
	OptProxy         Flags = FlagProxy
	OptAllowPostdate Flags = FlagMayPostdate
	OptPostdated     Flags = FlagPostdated
	OptRenewable     Flags = FlagRenewable
	OptRenewableOK   Flags = 1 << (31 - 27)
	OptEncTktInSkey  Flags = 1 << (31 - 28)
	OptRenew         Flags = 1 << (31 - 30)
	OptValidate      Flags = 1 << (31 - 31)
)

// Has reports whether every flag in f is set.
func (fl Flags) Has(f Flags) bool { return fl&f == f }

// bitString renders the flags as the BIT STRING Kerberos puts on the
// wire.
//
// It is always exactly 32 bits, never trimmed to the highest set bit:
// upstream writes one unused-bits octet of zero followed by the whole
// 32-bit word, so a flags value of 0 is five content octets rather
// than one (k5_asn1_encode_bitstring).
func (fl Flags) bitString() asn1.BitString {
	return asn1.BitString{
		Bytes: []byte{
			byte(fl >> 24), byte(fl >> 16),
			byte(fl >> 8), byte(fl),
		},
		BitLength: flagsBitStringBits,
	}
}

// flagsFromBitString reads a KerberosFlags BIT STRING.
//
// A peer sending fewer than 32 bits is accepted and the missing
// low-order bits read as zero, which is what upstream's decoder does:
// it copies up to four bytes from the most significant end and
// zero-extends. Rejecting a short BIT STRING would be stricter than
// the C and would break against an implementation that trims.
func flagsFromBitString(b asn1.BitString) (Flags, error) {
	if len(b.Bytes) > 4 {
		return 0, fmt.Errorf(
			"%w: KerberosFlags is %d octets, want <= 4",
			ErrMalformed, len(b.Bytes))
	}
	var fl Flags
	for i := 0; i < 4; i++ {
		fl <<= 8
		if i < len(b.Bytes) {
			fl |= Flags(b.Bytes[i])
		}
	}
	return fl, nil
}
