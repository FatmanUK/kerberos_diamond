package wire

import "encoding/asn1"

// PACOptRBCD is the one PA-PAC-OPTIONS bit MIT implements:
// resource-based constrained delegation (KRB5_PA_PAC_OPTIONS_RBCD,
// include/k5-int.h:579).
//
// **The other [MS-KILE] bits are not merely unimplemented, they are
// not named anywhere in MIT at all** -- not claims, not branch-aware,
// not forward-to-full-DC. `kdc_add_pa_pac_options' masks the field
// down to this single bit before echoing it (kdc/kdc_util.c:1839),
// which is how a KDC tells a client what it actually honoured rather
// than repeating back what it was asked.
const PACOptRBCD Flags = 0x10000000

// derPAPACOptions is PA-PAC-OPTIONS, a SEQUENCE of one KerberosFlags
// (asn1_k_encode.c:1712-1718).
//
// The field is a full KerberosFlags and not a smaller bit string, so
// it is thirty-two bits on the wire whatever is set -- see
// Flags.bitString for why that is five content octets rather than
// one.
type derPAPACOptions struct {
	Options asn1.BitString `asn1:"explicit,tag:0"`
}

// MarshalPAPACOptions encodes a PA-PAC-OPTIONS.
func MarshalPAPACOptions(f Flags) ([]byte, error) {
	return asn1.Marshal(derPAPACOptions{
		Options: f.bitString(),
	})
}

// UnmarshalPAPACOptions decodes a PA-PAC-OPTIONS.
func UnmarshalPAPACOptions(b []byte) (Flags, error) {
	var d derPAPACOptions
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return 0, derErr("PA-PAC-OPTIONS", err)
	}
	return flagsFromBitString(d.Options)
}
