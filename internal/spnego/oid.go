// Package spnego is enough of RFC 4178 and RFC 4121 to accept a
// Kerberos ticket from an HTTP client's Negotiate header.
//
// It is not a GSS-API mechanism and is not trying to become one. What
// an HTTP acceptor needs is three things: the RFC 2743 framing that
// wraps a mechanism token, the SPNEGO negotiation that picks Kerberos
// out of a list of mechanisms, and the 0x8003 structure the Kerberos
// mechanism keeps in the authenticator's checksum field instead of a
// checksum. Everything else GSS does -- per-message wrap, unwrap,
// MIC, credential delegation, the context lifecycle -- is absent, and
// the non-goals in the plan say why: this project is a KDC, not a
// distribution.
//
// Nothing here touches a key. The package decodes and encodes, and
// the one decision it makes (which mechanism was negotiated) is a
// comparison of octet strings. That keeps it testable against bytes a
// real GSS initiator produced, which is the whole point of choosing
// SPNEGO for the administrative surface.
package spnego

import "bytes"

// An OID is the DER *contents* of an OBJECT IDENTIFIER -- the value
// octets with no tag and no length. That is the form upstream keeps
// them in (gss_OID_desc, gssapi.hin), the form they are compared in,
// and the form they are written back out in, so storing them any
// other way would mean converting at every use.
type OID []byte

// The mechanism OIDs this acceptor knows, from krb5_gss_oid_array
// (gssapi_krb5.c:130-146) and SPNEGO_OID (gssapiP_spnego.h:90-91).
var (
	// MechSPNEGO is 1.3.6.1.5.5.2.
	MechSPNEGO = OID("\x2b\x06\x01\x05\x05\x02")

	// MechKrb5 is 1.2.840.113554.1.2.2, the OID RFC 1964
	// assigned.
	MechKrb5 = OID("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02")

	// MechKrb5Wrong is the same OID mis-encoded, and it is
	// accepted rather than refused because Microsoft shipped it:
	// the fourth octet is 0x82 where it should be 0x86, which
	// drops a bit out of the 113554 arc. Upstream takes it, maps
	// it to MechKrb5 for the negotiation and then answers with
	// the broken spelling rather than the correct one, so that a
	// client comparing what came back against what it sent still
	// agrees (negotiate_mech, spnego_mech.c:3245-3258).
	MechKrb5Wrong = OID("\x2a\x86\x48\x82\xf7\x12\x01\x02\x02")

	// MechKrb5Old is 1.3.5.1.5.2, the pre-RFC OID. Still offered
	// by old initiators and still accepted by upstream's
	// parse_init_token (accept_sec_context.c:650-658).
	MechKrb5Old = OID("\x2b\x05\x01\x05\x02")
)

// Equal compares two OIDs.
func (o OID) Equal(p OID) bool {
	return bytes.Equal(o, p)
}

// IsKerberos reports whether an OID names a Kerberos mechanism this
// acceptor can answer -- which is the correct OID, the old one, and
// Microsoft's broken one.
//
// IAKERB (1.3.6.1.5.2.5) is deliberately not in the list. Upstream
// accepts it here and then expects to proxy KDC exchanges over the
// GSS conversation, which is a client-side protocol this project has
// no acceptor for; taking the OID and then failing later would be
// worse than not taking it.
func IsKerberos(o OID) bool {
	return o.Equal(MechKrb5) || o.Equal(MechKrb5Old) ||
		o.Equal(MechKrb5Wrong)
}
