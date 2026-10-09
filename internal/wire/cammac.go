package wire

import "encoding/asn1"

// VerifierMAC is one checksum over a CAMMAC's contents, with enough
// to say which key made it (RFC 7751 §6, asn1_k_encode.c:1652-1659).
//
// Every field but the checksum is OPTIONAL and **zero means absent**,
// which is upstream's DEFOPTIONALZEROTYPE for all three (:48, :116,
// :212). So a verifier with no kvno is a verifier whose kvno is zero,
// and the two cannot be told apart -- which is tolerable because kvno
// zero is not a key version anything issues.
type VerifierMAC struct {
	// Identifier names the key's principal, and is absent in both
	// of the verifiers a KDC makes: the reader knows which key to
	// try from *which verifier it is*.
	Identifier *PrincipalName

	// KVNO is the key version, which the KDC verifier sets and
	// the service verifier does not (cammac.c:52 and :67).
	KVNO uint32

	// EType is checked only when present: a verifier naming an
	// enctype is refused if the key found has another
	// (cammac_check_kdcver, cammac.c:127-128).
	EType int32

	// MAC is the checksum itself.
	MAC Checksum
}

// CAMMAC is RFC 7751's container: authorization data with one or more
// checksums over it, so that a service can tell what the KDC vouched
// for from what a client supplied.
type CAMMAC struct {
	// Elements is the authorization data being vouched for.
	Elements AuthorizationData

	// KDCVerifier is checksummed with the **local krbtgt key**
	// over the DER-encoded EncTicketPart with Elements
	// substituted as its authorization data -- a self-referential
	// construction that binds the contents to the exact ticket
	// they were issued in (encode_kdcver_encpart,
	// cammac.c:30-40).
	KDCVerifier *VerifierMAC

	// SvcVerifier is checksummed with the **server's** key over
	// the encoded Elements alone, so the service that receives
	// the ticket can check it without the krbtgt key.
	SvcVerifier *VerifierMAC

	// OtherVerifiers is for recipients neither of the above
	// covers. Nothing in MIT produces one.
	OtherVerifiers []VerifierMAC
}

type derVerifierMAC struct {
	Identifier derPrincipalName `asn1:"explicit,optional,tag:0"`
	KVNO       int64            `asn1:"explicit,optional,tag:1"`
	EType      int32            `asn1:"explicit,optional,tag:2"`
	MAC        derChecksum      `asn1:"explicit,tag:3"`
}

type derCAMMAC struct {
	Elements []derAuthDatum `asn1:"explicit,tag:0"`

	KDCVer derVerifierMAC   `asn1:"explicit,optional,tag:1"`
	SvcVer derVerifierMAC   `asn1:"explicit,optional,tag:2"`
	Others []derVerifierMAC `asn1:"explicit,optional,tag:3"`
}

// MarshalCAMMAC encodes a CAMMAC.
func MarshalCAMMAC(c CAMMAC) ([]byte, error) {
	d := derCAMMAC{Elements: derAuthData(c.Elements)}
	if c.KDCVerifier != nil {
		d.KDCVer = c.KDCVerifier.der()
	}
	if c.SvcVerifier != nil {
		d.SvcVer = c.SvcVerifier.der()
	}
	for i := range c.OtherVerifiers {
		d.Others = append(d.Others,
			c.OtherVerifiers[i].der())
	}
	return asn1.Marshal(d)
}

// UnmarshalCAMMAC decodes a CAMMAC.
func UnmarshalCAMMAC(b []byte) (CAMMAC, error) {
	var d derCAMMAC
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return CAMMAC{}, derErr("CAMMAC", err)
	}
	out := CAMMAC{Elements: authDataOf(d.Elements)}
	if v, ok := d.KDCVer.value(); ok {
		out.KDCVerifier = &v
	}
	if v, ok := d.SvcVer.value(); ok {
		out.SvcVerifier = &v
	}
	for i := range d.Others {
		if v, ok := d.Others[i].value(); ok {
			out.OtherVerifiers = append(
				out.OtherVerifiers, v)
		}
	}
	return out, nil
}

// der encodes one verifier.
func (v VerifierMAC) der() derVerifierMAC {
	out := derVerifierMAC{
		KVNO:  int64(v.KVNO),
		EType: v.EType,
		MAC: derChecksum{
			Type: v.MAC.Type, Checksum: v.MAC.Checksum,
		},
	}
	if v.Identifier != nil {
		out.Identifier = v.Identifier.der()
	}
	return out
}

// value decodes one verifier, reporting whether it was there at all.
//
// An absent OPTIONAL SEQUENCE decodes as the zero struct, which for a
// verifier means a checksum of no octets -- and that is how absence
// is told from presence, because a verifier with no checksum is not a
// verifier.
func (d derVerifierMAC) value() (VerifierMAC, bool) {
	if len(d.MAC.Checksum) == 0 {
		return VerifierMAC{}, false
	}
	out := VerifierMAC{
		KVNO:  uint32(d.KVNO),
		EType: d.EType,
		MAC: Checksum{
			Type: d.MAC.Type, Checksum: d.MAC.Checksum,
		},
	}
	if len(d.Identifier.Components) != 0 {
		if n, err := d.Identifier.value(); err == nil {
			out.Identifier = &n
		}
	}
	return out, true
}

// derAuthData and authDataOf convert the element list, which the
// CAMMAC encoder needs inline rather than as opaque DER.
func derAuthData(a AuthorizationData) []derAuthDatum {
	out := make([]derAuthDatum, len(a))
	for i, d := range a {
		out[i] = derAuthDatum{Type: d.Type, Data: d.Data}
	}
	return out
}

func authDataOf(d []derAuthDatum) AuthorizationData {
	out := make(AuthorizationData, len(d))
	for i := range d {
		out[i] = AuthDatum{
			Type: d[i].Type, Data: d[i].Data,
		}
	}
	return out
}

// MarshalAuthIndicators encodes an AD-AUTH-INDICATOR's contents: a
// SEQUENCE OF UTF8String (seqof_utf8_data, asn1_k_encode.c:92-95 and
// :1679).
func MarshalAuthIndicators(ind []string) ([]byte, error) {
	out := make([]asn1.RawValue, len(ind))
	for i, s := range ind {
		out[i] = asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte(s),
			FullBytes: derTLV(0x0c,
				[]byte(s)),
		}
	}
	return asn1.Marshal(out)
}

// UnmarshalAuthIndicators decodes them.
func UnmarshalAuthIndicators(b []byte) ([]string, error) {
	var raw []asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return nil, derErr("AuthIndicators", err)
	}
	out := make([]string, len(raw))
	for i := range raw {
		if raw[i].Tag != asn1.TagUTF8String {
			return nil, derErr("AuthIndicators",
				asn1.StructuralError{
					Msg: "not a UTF8String",
				})
		}
		out[i] = string(raw[i].Bytes)
	}
	return out, nil
}
