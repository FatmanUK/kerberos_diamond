package wire

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// The FAST messages of RFC 6113, from asn1_k_encode.c:995-1068 under
// the header comment "draft-ietf-krb-wg-preauth-framework-09".
//
// FAST wraps an ordinary request inside an encrypted tunnel keyed
// with an *armor key* that neither the client nor the KDC chose
// alone, which is what stops an eavesdropper taking a
// pre-authentication exchange away and attacking the password
// offline. The shape is two layers in each direction: a PA-FX-FAST
// padata item holding an armored container, and inside that the real
// request or reply.
//
// The reply half of this file is anchored to upstream's own
// byte-exact reference output; the request half is not. See
// fast_test.go.

// FAST armor types (KRB5_FAST_ARMOR_AP_REQUEST, krb5.hin).
const (
	// FastArmorAPRequest is the only armor type anyone defines or
	// sends: an AP-REQ for the local ticket-granting service,
	// whose authenticator subkey and ticket session key are
	// combined into the armor key.
	FastArmorAPRequest int32 = 1
)

// FAST option bits, which are KerberosFlags and share Flags' layout.
const (
	// FastOptionHideClientNames asks the KDC to put the anonymous
	// principal in the reply instead of the real client
	// (KRB5_FAST_OPTION_HIDE_CLIENT_NAMES, k5-int.h:803).
	FastOptionHideClientNames Flags = 0x40000000

	// FastCriticalOptions are the bits a KDC must refuse if it
	// does not understand them
	// (UNSUPPORTED_CRITICAL_FAST_OPTIONS, k5-int.h:802, whose own
	// comment cites RFC 6113 section 7.3: "Bits 0-15 are critical
	// in FAST options"). Note that hide-client-names is bit 1 and
	// is deliberately *not* here -- upstream understands it.
	FastCriticalOptions Flags = 0xbfff0000
)

// KrbFastArmor is how the armor key is established
// (asn1_k_encode.c:996-1002).
type KrbFastArmor struct {
	Type  int32
	Value []byte
}

type derKrbFastArmor struct {
	Type  int32  `asn1:"explicit,tag:0"`
	Value []byte `asn1:"explicit,tag:1"`
}

// KrbFastArmoredReq is the armored request container
// (asn1_k_encode.c:1006-1015).
//
// Armor is optional, and which exchange it is absent from is the
// whole difference between the two armor paths: an AS request must
// carry it, while a TGS request must *not* -- upstream refuses one
// outright ("Ap-request armor not permitted with TGS",
// fast_util.c:158-164) and derives the armor key from the request's
// own AP-REQ instead.
type KrbFastArmoredReq struct {
	// Armor is absent when Type is zero, which is not a valid
	// armor type, so the zero value means absent and cannot
	// collide.
	Armor KrbFastArmor

	ReqChecksum Checksum
	EncPart     EncryptedData
}

type derKrbFastArmoredReq struct {
	Armor       derKrbFastArmor  `asn1:"explicit,optional,tag:0"`
	ReqChecksum derChecksum      `asn1:"explicit,tag:1"`
	EncPart     derEncryptedData `asn1:"explicit,tag:2"`
}

// KrbFastReq is the request inside the tunnel
// (asn1_k_encode.c:1022-1031).
//
// PAData and Body are *one field* in the C: both [1] and [2] name
// req_body, and [1] reaches through it to the padata inside
// (DEFOFFSETTYPE at :1022, with the matching comment at
// include/k5-int.h:793-798 -- "padata from req_body is used"). That
// is why the KDC can hand the decoded inner request straight to its
// ordinary pre-authentication machinery.
//
// Here they are separate, because a Go KDCReqBody has its own PAData
// nowhere: an ASReq carries it beside the body. A caller splices the
// two together. Getting that wrong is not a subtle failure -- the
// *outer* request's padata holds only PA-FX-FAST, so a KDC that read
// the outer padata would see no pre-authentication at all.
type KrbFastReq struct {
	Options Flags
	PAData  []PAData
	Body    KDCReqBody
}

type derKrbFastReq struct {
	Options asn1.BitString `asn1:"explicit,tag:0"`
	PAData  []derPAData    `asn1:"explicit,tag:1"`
	Body    asn1.RawValue  `asn1:"explicit,tag:2"`
}

// KrbFastFinished is the KDC's proof that the reply belongs to this
// exchange (asn1_k_encode.c:1033-1043).
//
// TicketChecksum is over the *encoded, already encrypted* ticket,
// keyed with the armor key, and CRealm/CName replace the reply's
// client name at the client (lib/krb5/krb/fast.c:541-556). Both are
// mandatory: a client refuses a FAST reply with no finished field at
// all.
type KrbFastFinished struct {
	Timestamp      time.Time
	Usec           int32
	CRealm         string
	CName          PrincipalName
	TicketChecksum Checksum
}

type derKrbFastFinished struct {
	Timestamp time.Time `asn1:"explicit,generalized,tag:0"`
	Usec      int32     `asn1:"explicit,tag:1"`

	CRealm asn1.RawValue    `asn1:"explicit,tag:2"`
	CName  derPrincipalName `asn1:"explicit,tag:3"`
	Cksum  derChecksum      `asn1:"explicit,tag:4"`
}

// KrbFastResponse is the reply inside the tunnel
// (asn1_k_encode.c:1047-1057).
//
// StrengthenKey and Finished are both optional and the two cases that
// omit them are different. A *success* reply carries both. An error
// reply carries neither (fast_util.c:402-407), because there is no
// ticket to checksum and no reply key to strengthen.
type KrbFastResponse struct {
	PAData []PAData

	// StrengthenKey is absent when KeyType is zero. A client that
	// receives one combines it with the key it expected
	// (fast_util.c:427-441), so that neither side's key alone
	// decrypts the reply.
	StrengthenKey EncryptionKey

	// Finished is absent when its Timestamp is zero.
	Finished KrbFastFinished

	Nonce int32
}

type derKrbFastResponse struct {
	PAData     []derPAData        `asn1:"explicit,tag:0"`
	Strengthen derEncryptionKey   `asn1:"explicit,optional,tag:1"`
	Finished   derKrbFastFinished `asn1:"explicit,optional,tag:2"`
	Nonce      int32              `asn1:"explicit,tag:3"`
}

// derKrbFastArmoredRep is the armored reply container
// (asn1_k_encode.c:1059-1063).
//
// It has *no* armor field, unlike the request: the client already
// knows the armor key by the time a reply arrives. Copying the
// request's structure is the obvious mistake and the resulting reply
// decodes as garbage at every client.
type derKrbFastArmoredRep struct {
	EncPart derEncryptedData `asn1:"explicit,tag:0"`
}

// errFastChoice reports a PA-FX-FAST whose single CHOICE alternative
// is not the one defined.
//
// Both PA-FX-FAST types are a CHOICE with one alternative, and
// upstream says so in a comment it repeats verbatim twice
// (asn1_k_encode.c:1017-1018 and :1065-1066): "This is a CHOICE type
// with only one choice (so far) and we're not using a
// distinguisher/union for it." Its encoder therefore hard-codes the
// [0] tag and its decoder accepts only that by accident. This rejects
// anything else on purpose, so that a future alternative is a clear
// refusal rather than a misread armored-data.
var errFastChoice = fmt.Errorf(
	"%w: PA-FX-FAST is not armored-data", ErrMalformed)

// MarshalPAFXFastRequest encodes a PA-FX-FAST holding an armored
// request, ready to be the value of a PA-FX-FAST padata item.
func MarshalPAFXFastRequest(r KrbFastArmoredReq) ([]byte, error) {
	seq, err := asn1.Marshal(r.der())
	if err != nil {
		return nil, err
	}
	return derTLV(0xA0, seq), nil
}

// UnmarshalPAFXFastRequest decodes one.
func UnmarshalPAFXFastRequest(
	b []byte,
) (KrbFastArmoredReq, error) {
	inner, err := fastChoice(b)
	if err != nil {
		return KrbFastArmoredReq{}, err
	}
	var d derKrbFastArmoredReq
	if _, err := asn1.Unmarshal(inner, &d); err != nil {
		return KrbFastArmoredReq{}, derErr(
			"KrbFastArmoredReq", err)
	}
	return d.value()
}

// MarshalPAFXFastReply encodes a PA-FX-FAST holding an armored reply.
func MarshalPAFXFastReply(e EncryptedData) ([]byte, error) {
	seq, err := asn1.Marshal(derKrbFastArmoredRep{
		EncPart: e.der(),
	})
	if err != nil {
		return nil, err
	}
	return derTLV(0xA0, seq), nil
}

// UnmarshalPAFXFastReply decodes one.
func UnmarshalPAFXFastReply(b []byte) (EncryptedData, error) {
	inner, err := fastChoice(b)
	if err != nil {
		return EncryptedData{}, err
	}
	var d derKrbFastArmoredRep
	if _, err := asn1.Unmarshal(inner, &d); err != nil {
		return EncryptedData{}, derErr(
			"KrbFastArmoredRep", err)
	}
	return d.EncPart.value(), nil
}

// fastChoice steps past the [0] CHOICE wrapper, refusing any other
// tag.
func fastChoice(b []byte) ([]byte, error) {
	if len(b) == 0 || b[0] != 0xA0 {
		return nil, errFastChoice
	}
	return tlvContent(b)
}

// MarshalKrbFastReq encodes the request that goes inside the tunnel,
// ready to be encrypted under the armor key with key usage 51.
func MarshalKrbFastReq(r KrbFastReq) ([]byte, error) {
	bd, err := r.Body.der()
	if err != nil {
		return nil, err
	}
	body, err := asn1.Marshal(bd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(derKrbFastReq{
		Options: r.Options.bitString(),
		PAData:  paDataDER(r.PAData),
		Body:    ctxWrap(2, body),
	})
}

// UnmarshalKrbFastReq decodes it.
func UnmarshalKrbFastReq(b []byte) (KrbFastReq, error) {
	var d derKrbFastReq
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return KrbFastReq{}, derErr("KrbFastReq", err)
	}
	return d.value()
}

// MarshalKrbFastResponse encodes the reply that goes inside the
// tunnel, ready to be encrypted under the armor key with key usage
// 52.
func MarshalKrbFastResponse(r KrbFastResponse) ([]byte, error) {
	d, err := r.der()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(d)
}

// UnmarshalKrbFastResponse decodes it.
func UnmarshalKrbFastResponse(b []byte) (KrbFastResponse, error) {
	var d derKrbFastResponse
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return KrbFastResponse{}, derErr(
			"KrbFastResponse", err)
	}
	return d.value()
}

func (r KrbFastArmoredReq) der() derKrbFastArmoredReq {
	return derKrbFastArmoredReq{
		Armor: derKrbFastArmor{
			Type: r.Armor.Type, Value: r.Armor.Value,
		},
		ReqChecksum: derChecksum{
			Type:     r.ReqChecksum.Type,
			Checksum: r.ReqChecksum.Checksum,
		},
		EncPart: r.EncPart.der(),
	}
}

func (d derKrbFastArmoredReq) value() (KrbFastArmoredReq, error) {
	return KrbFastArmoredReq{
		Armor: KrbFastArmor{
			Type: d.Armor.Type, Value: d.Armor.Value,
		},
		ReqChecksum: Checksum{
			Type:     d.ReqChecksum.Type,
			Checksum: d.ReqChecksum.Checksum,
		},
		EncPart: d.EncPart.value(),
	}, nil
}

func (d derKrbFastReq) value() (KrbFastReq, error) {
	opts, err := flagsFromBitString(d.Options)
	if err != nil {
		return KrbFastReq{}, err
	}
	var body derKDCReqBody
	if _, err := asn1.Unmarshal(d.Body.Bytes, &body); err != nil {
		return KrbFastReq{}, derErr("KDC-REQ-BODY", err)
	}
	b, err := body.value()
	if err != nil {
		return KrbFastReq{}, err
	}
	return KrbFastReq{
		Options: opts,
		PAData:  paDataValues(d.PAData),
		Body:    b,
	}, nil
}

func (r KrbFastResponse) der() (derKrbFastResponse, error) {
	fin, err := r.Finished.der()
	if err != nil {
		return derKrbFastResponse{}, err
	}
	return derKrbFastResponse{
		PAData:     paDataDER(r.PAData),
		Strengthen: derKey(r.StrengthenKey),
		Finished:   fin,
		Nonce:      r.Nonce,
	}, nil
}

func (d derKrbFastResponse) value() (KrbFastResponse, error) {
	fin, err := d.Finished.value()
	if err != nil {
		return KrbFastResponse{}, err
	}
	return KrbFastResponse{
		PAData:        paDataValues(d.PAData),
		StrengthenKey: d.Strengthen.value(),
		Finished:      fin,
		Nonce:         d.Nonce,
	}, nil
}

// der renders a KrbFastFinished, or the zero value when there is
// none.
//
// The absent case is not an error: an error reply carries no finished
// field, and Go's asn1 omits an optional field exactly when it is the
// zero value, so a zero Timestamp is how absence is expressed.
func (f KrbFastFinished) der() (derKrbFastFinished, error) {
	if f.Timestamp.IsZero() {
		return derKrbFastFinished{}, nil
	}
	return derKrbFastFinished{
		Timestamp: kerberosTime(f.Timestamp),
		Usec:      f.Usec,
		CRealm:    ctxGstring(2, f.CRealm),
		CName:     f.CName.der(),
		Cksum: derChecksum{
			Type:     f.TicketChecksum.Type,
			Checksum: f.TicketChecksum.Checksum,
		},
	}, nil
}

func (d derKrbFastFinished) value() (KrbFastFinished, error) {
	if d.Timestamp.IsZero() {
		return KrbFastFinished{}, nil
	}
	crealm, err := ctxGstringValue(d.CRealm)
	if err != nil {
		return KrbFastFinished{}, err
	}
	cname, err := d.CName.value()
	if err != nil {
		return KrbFastFinished{}, err
	}
	return KrbFastFinished{
		Timestamp: d.Timestamp,
		Usec:      d.Usec,
		CRealm:    crealm,
		CName:     cname,
		TicketChecksum: Checksum{
			Type:     d.Cksum.Type,
			Checksum: d.Cksum.Checksum,
		},
	}, nil
}
