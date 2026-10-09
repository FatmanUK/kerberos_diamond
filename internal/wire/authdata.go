package wire

import "encoding/asn1"

// The authorization-data types this KDC acts on (krb5.hin:1861-1873).
//
// Five of them are **KDC-issued**: a client may not supply one,
// because the whole point of each is that the KDC vouched for it.
// They are stripped from anything a client sent rather than refused,
// which is upstream's choice and the kinder one -- a client that
// included one by accident still gets a ticket, just without it.
const (
	// ADIfRelevant is a container whose contents may be ignored
	// by anything that does not understand them. It matters here
	// because the filter **descends one level into it**: wrapping
	// a forged PAC in a container would otherwise smuggle it
	// through, and that is the whole reason
	// is_kdc_issued_authdatum is not a top-level type check
	// (kdc_authdata.c:119-127).
	ADIfRelevant int32 = 1

	// ADKDCIssued is RFC 4120's signed container.
	ADKDCIssued int32 = 4

	// ADMandatoryForKDC is the one outright refusal: an element
	// the KDC must either understand or reject. Checked at the
	// top level only (has_mandatory_for_kdc_authdata, :152-166,
	// does not descend).
	ADMandatoryForKDC int32 = 8

	// ADCAMMAC is RFC 7751's container, and ADAuthIndicator the
	// list of how its holder authenticated.
	ADCAMMAC        int32 = 96
	ADAuthIndicator int32 = 97

	// ADWin2KPAC is the Windows PAC.
	ADWin2KPAC int32 = 128

	// ADSignTicket is **512**, not 142. 142 is Heimdal's value
	// and also PA-OTP-REQUEST's number in the padata table; MIT
	// uses neither for this (krb5.hin:1871, where it is marked
	// deprecated in favour of the PAC).
	ADSignTicket int32 = 512
)

// kdcIssuedTypes are the five a client may not supply.
var kdcIssuedTypes = map[int32]bool{
	ADKDCIssued:     true,
	ADCAMMAC:        true,
	ADAuthIndicator: true,
	ADWin2KPAC:      true,
	ADSignTicket:    true,
}

// AuthDatum is one authorization-data element.
type AuthDatum struct {
	Type int32
	Data []byte
}

// AuthorizationData is the SEQUENCE OF them (asn1_k_encode.c's
// authorization_data).
type AuthorizationData []AuthDatum

// derAuthDatum is the element's own SEQUENCE.
type derAuthDatum struct {
	Type int32  `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,tag:1"`
}

// MarshalAuthorizationData encodes the sequence.
//
// An empty list encodes as an empty SEQUENCE rather than as nothing,
// because the caller decides whether the field appears at all --
// there is no such thing as an AuthorizationData with no elements on
// the wire, and conflating the two here would hide the decision.
func MarshalAuthorizationData(
	a AuthorizationData,
) ([]byte, error) {
	out := make([]derAuthDatum, len(a))
	for i, d := range a {
		out[i] = derAuthDatum{Type: d.Type, Data: d.Data}
	}
	return asn1.Marshal(out)
}

// UnmarshalAuthorizationData decodes the sequence.
func UnmarshalAuthorizationData(
	b []byte,
) (AuthorizationData, error) {
	var d []derAuthDatum
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	out := make(AuthorizationData, len(d))
	for i := range d {
		out[i] = AuthDatum{
			Type: d[i].Type, Data: d[i].Data,
		}
	}
	return out, nil
}

// IsKDCIssued reports whether an element is one only a KDC may
// produce, descending one level into an AD-IF-RELEVANT container
// (is_kdc_issued_authdatum, kdc_authdata.c:110-150).
//
// The descent is the point. A top-level type check would let
// `AD-IF-RELEVANT{ AD-WIN2K-PAC }' through, and a service reading a
// ticket unwraps the container without caring who put it there -- so
// a client could hand itself a PAC. One level is all upstream does
// and all that is needed: a container inside a container is not a
// shape anything generates.
func (d AuthDatum) IsKDCIssued() bool {
	if d.Type != ADIfRelevant {
		return kdcIssuedTypes[d.Type]
	}
	inner, err := UnmarshalAuthorizationData(d.Data)
	if err != nil {
		// An unparseable container cannot be shown to be
		// harmless, so it is treated as KDC-issued and
		// dropped. Upstream's own reading fails closed the
		// same way: krb5int_get_authdata_containee_types
		// failing leaves result FALSE and the element is
		// *kept* -- the opposite choice, and one worth
		// diverging from, because keeping an element nobody
		// could decode is how a smuggling path stays open.
		return true
	}
	for _, e := range inner {
		if kdcIssuedTypes[e.Type] {
			return true
		}
	}
	return false
}

// HasMandatoryForKDC reports an element the KDC must understand or
// reject, which is checked at the **top level only** -- upstream's
// has_mandatory_for_kdc_authdata does not descend into containers
// (kdc_authdata.c:152-166).
func (a AuthorizationData) HasMandatoryForKDC() bool {
	for _, d := range a {
		if d.Type == ADMandatoryForKDC {
			return true
		}
	}
	return false
}

// Filtered is the list with every KDC-issued element removed, which
// is what a client's own authorization data is reduced to before it
// travels in a ticket.
func (a AuthorizationData) Filtered() AuthorizationData {
	out := make(AuthorizationData, 0, len(a))
	for _, d := range a {
		if !d.IsKDCIssued() {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// authDataTag is the context tag the authorization-data field takes
// in both an EncTicketPart and an Authenticator (asn1_k_encode.c's
// enc_tkt_part and authenticator).
const authDataTag = 10

// AuthDataField encodes an AuthorizationData into the form a
// passthrough field needs: **already wrapped in its own context
// tag**.
//
// That wrapping is not optional and it is the trap in this layer.
// encoding/asn1 emits an asn1.RawValue's FullBytes verbatim and
// **ignores the `explicit' tag parameter on the field**, so a
// RawValue holding only the bare SEQUENCE encodes without any [10]
// around it -- which decodes back as absent, silently, because the
// field is OPTIONAL and nothing matched. The field simply vanishes.
//
// ctxWrap exists for exactly this and its own comment records the
// first time it bit: "how user-to-user's second ticket went missing
// the first time."
func AuthDataField(
	a AuthorizationData,
) (asn1.RawValue, error) {
	if len(a) == 0 {
		return asn1.RawValue{}, nil
	}
	der, err := MarshalAuthorizationData(a)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return ctxWrap(authDataTag, der), nil
}

// AuthDataOf reads a passthrough field back.
//
// The content is in Bytes and not FullBytes: a decoded RawValue
// carries the whole tagged element in FullBytes and its contents in
// Bytes, so reading FullBytes here would hand the [10] wrapper to the
// sequence decoder.
func AuthDataOf(
	r asn1.RawValue,
) (AuthorizationData, error) {
	body := ctxUnwrap(r)
	if len(body) == 0 {
		return nil, nil
	}
	return UnmarshalAuthorizationData(body)
}

// encAuthDataTag is the context tag KDC-REQ-BODY gives
// enc-authorization-data (RFC 4120's KDC-REQ-BODY [10]).
const encAuthDataTag = 10

// EncAuthDataField encodes an EncryptedData into the request body's
// passthrough field, wrapped in its own context tag.
//
// **The wrapping caught a test passing for the wrong reason.** A
// RawValue holding only the bare EncryptedData encodes without any
// [10] around it, so the field never reaches the wire -- and an
// in-process test that hands the KDC the *struct* rather than the
// encoded request never notices, because the KDC reads the field it
// was given. The C KDC noticed: it copied nothing, because as far as
// it could see nothing was sent.
func EncAuthDataField(
	ed EncryptedData,
) (asn1.RawValue, error) {
	der, err := MarshalEncryptedData(ed)
	if err != nil {
		return asn1.RawValue{}, err
	}
	return ctxWrap(encAuthDataTag, der), nil
}

// EncAuthDataOf reads the request body's field back.
func EncAuthDataOf(
	r asn1.RawValue,
) (EncryptedData, bool, error) {
	body := ctxUnwrap(r)
	if len(body) == 0 {
		return EncryptedData{}, false, nil
	}
	ed, err := UnmarshalEncryptedData(body)
	if err != nil {
		return EncryptedData{}, false, err
	}
	return ed, true, nil
}
