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

// Ticket flags, from include/krb5/krb5.hin:1717-1733. The values are
// the C's, not a bit count, and the reason is the gap below.
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
)

// Bit 14 does not exist.
//
// The run above stops at bit 13 because upstream skips 0x00020000
// entirely -- it is not even one of the commented-out reserved values
// in that header, which do resume at 0x00004000. So enc-pa-rep is bit
// 15 and anonymous is bit 16, and continuing the iota run through
// them would put both one bit too high: a KDC that set what it
// thought was enc-pa-rep would be setting a bit no implementation
// defines, and clients would not see the flag they were promised.
const (
	FlagEncPARep  Flags = 0x00010000
	FlagAnonymous Flags = 0x00008000
)

// KDC options, from include/krb5/krb5.hin:1620-1650. They share the
// wire representation with ticket flags and the first six share bit
// positions too, which is why upstream converts between those by
// masking rather than mapping (OPTS2FLAGS, kdc/kdc_util.h:493-500).
// Past that the two sets diverge: request-anonymous is bit 16 in
// both, but canonicalize, renewable-ok, enc-tkt-in-skey, renew and
// validate have no ticket flag at all.
const (
	OptForwardable   Flags = FlagForwardable
	OptForwarded     Flags = FlagForwarded
	OptProxiable     Flags = FlagProxiable
	OptProxy         Flags = FlagProxy
	OptAllowPostdate Flags = FlagMayPostdate
	OptPostdated     Flags = FlagPostdated
	OptRenewable     Flags = FlagRenewable

	OptCNameInAddlTkt Flags = 0x00020000
	OptCanonicalize   Flags = 0x00010000
	OptRequestAnon    Flags = 0x00008000

	OptDisableTransitedCheck Flags = 0x00000020
	OptRenewableOK           Flags = 0x00000010
	OptEncTktInSKey          Flags = 0x00000008
	OptRenew                 Flags = 0x00000002
	OptValidate              Flags = 0x00000001
)

// ASInvalidOptions are the options that only make sense in a TGS-REQ,
// and an AS-REQ carrying any of them is refused with
// KDC_ERR_BADOPTION (AS_INVALID_OPTIONS, kdc/kdc_util.h:456-463).
//
// Note that cname-in-addl-tkt is in the set while canonicalize is
// not, even though they are adjacent bits.
const ASInvalidOptions = OptForwarded | OptProxy | OptRenew |
	OptValidate | OptEncTktInSKey | OptCNameInAddlTkt

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
