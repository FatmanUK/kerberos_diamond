package wire

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// KDCReqBody is the body of an AS-REQ or TGS-REQ.
//
// One realm, two principals: the body carries a single realm field
// that belongs to *both* the client and the server name. Upstream has
// no realm field on its request structure at all and reconstructs
// this with a shadow struct (asn1_k_encode.c:443-545), writing the
// one wire realm into both principals on decode. Keeping Realm as its
// own field here says plainly that it is shared, rather than hiding
// it in one of the names and silently losing it from the other.
type KDCReqBody struct {
	Options Flags

	// CName is absent in a TGS-REQ and present in an AS-REQ.
	CName *PrincipalName

	Realm string

	// SName is optional on the wire. For an AS-REQ it is the
	// krbtgt being asked for.
	SName *PrincipalName

	// From and RTime are absent when zero.
	From  time.Time
	Till  time.Time
	RTime time.Time

	// Nonce is int32 on the wire, not the UInt32 RFC 4120 names:
	// upstream encodes it with int32 (asn1_k_encode.c:456). A
	// client masks its nonce to 31 bits, so the distinction only
	// shows up against a peer that does not.
	Nonce int32

	// EType is the client's enctype list, in its own order of
	// preference. That order is honoured rather than re-sorted:
	// the KDC picks the first entry it can satisfy.
	EType []int32

	// Addresses, EncAuthorizationData and AdditionalTickets are
	// kept as raw DER. The AS exchange does not read them, but a
	// SEQUENCE with unparsed trailing fields is a decode error in
	// encoding/asn1, so they have to be declared to be tolerated.
	Addresses            asn1.RawValue
	EncAuthorizationData asn1.RawValue
	AdditionalTickets    asn1.RawValue
}

// derKDCReqBody is grouped into blank-line-separated runs because
// gofmt aligns struct tags per run: one run would push the two
// generalized-time tags past 70 columns.
type derKDCReqBody struct {
	Options asn1.BitString   `asn1:"explicit,tag:0"`
	CName   derPrincipalName `asn1:"explicit,optional,tag:1"`
	Realm   asn1.RawValue    `asn1:"explicit,tag:2"`
	SName   derPrincipalName `asn1:"explicit,optional,tag:3"`

	From  time.Time `asn1:"explicit,optional,generalized,tag:4"`
	Till  time.Time `asn1:"explicit,generalized,tag:5"`
	RTime time.Time `asn1:"explicit,optional,generalized,tag:6"`

	Nonce int32   `asn1:"explicit,tag:7"`
	EType []int32 `asn1:"explicit,tag:8"`

	Addresses asn1.RawValue `asn1:"explicit,optional,tag:9"`
	EncAuthz  asn1.RawValue `asn1:"explicit,optional,tag:10"`
	AddlTkts  asn1.RawValue `asn1:"explicit,optional,tag:11"`
}

// ASReq is an AS-REQ: a client asking for a ticket with no ticket of
// its own to show.
type ASReq struct {
	// PAData is empty for the one-round-trip case, which is what
	// a client sends to a principal with no preauth requirement.
	PAData []PAData

	Body KDCReqBody
}

// derASReq's context tags start at 1, not 0: pvno [1], msg-type [2],
// padata [3], req-body [4] (asn1_k_encode.c:785-793). There is no
// [0].
type derASReq struct {
	Pvno    int32         `asn1:"explicit,tag:1"`
	MsgType int32         `asn1:"explicit,tag:2"`
	PAData  []derPAData   `asn1:"explicit,optional,tag:3"`
	Body    derKDCReqBody `asn1:"explicit,tag:4"`
}

// MarshalASReq encodes an AS-REQ.
func MarshalASReq(r ASReq) ([]byte, error) {
	body, err := r.Body.der()
	if err != nil {
		return nil, err
	}
	// msg-type is set explicitly. Upstream keeps a second encoder
	// purely because libkrb5 leaves the field unset and the
	// constant has to be substituted (asn1_k_encode.c:797); there
	// is nothing to imitate there.
	return asn1.MarshalWithParams(derASReq{
		Pvno:    Pvno,
		MsgType: MsgASReq,
		PAData:  paDataDER(r.PAData),
		Body:    body,
	}, appParams(tagASReq))
}

// UnmarshalASReq decodes an AS-REQ.
func UnmarshalASReq(b []byte) (ASReq, error) {
	var d derASReq
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagASReq)); err != nil {
		return ASReq{}, fmt.Errorf("AS-REQ: %w", err)
	}
	if err := checkPvno(d.Pvno); err != nil {
		return ASReq{}, err
	}
	if d.MsgType != MsgASReq {
		return ASReq{}, fmt.Errorf(
			"%w: msg-type is %d, want %d",
			ErrMalformed, d.MsgType, MsgASReq)
	}
	body, err := d.Body.value()
	if err != nil {
		return ASReq{}, err
	}
	return ASReq{
		PAData: paDataValues(d.PAData),
		Body:   body,
	}, nil
}

// appParams builds the encoding/asn1 parameter string for an
// [APPLICATION n] wrapper.
func appParams(tag int) string {
	return fmt.Sprintf("application,explicit,tag:%d", tag)
}

func (b KDCReqBody) der() (derKDCReqBody, error) {
	if b.Till.IsZero() {
		return derKDCReqBody{}, fmt.Errorf(
			"%w: till is required", ErrMalformed)
	}
	d := derKDCReqBody{
		Options:   b.Options.bitString(),
		Realm:     ctxGstring(2, b.Realm),
		From:      optTime(b.From),
		Till:      kerberosTime(b.Till),
		RTime:     optTime(b.RTime),
		Nonce:     b.Nonce,
		EType:     b.EType,
		Addresses: b.Addresses,
		EncAuthz:  b.EncAuthorizationData,
		AddlTkts:  b.AdditionalTickets,
	}
	if b.CName != nil {
		d.CName = b.CName.der()
	}
	if b.SName != nil {
		d.SName = b.SName.der()
	}
	return d, nil
}

func (d derKDCReqBody) value() (KDCReqBody, error) {
	opts, err := flagsFromBitString(d.Options)
	if err != nil {
		return KDCReqBody{}, err
	}
	realm, err := ctxGstringValue(d.Realm)
	if err != nil {
		return KDCReqBody{}, err
	}
	b := KDCReqBody{
		Options:              opts,
		Realm:                realm,
		From:                 d.From,
		Till:                 d.Till,
		RTime:                d.RTime,
		Nonce:                d.Nonce,
		EType:                d.EType,
		Addresses:            d.Addresses,
		EncAuthorizationData: d.EncAuthz,
		AdditionalTickets:    d.AddlTkts,
	}
	if err := d.names(&b); err != nil {
		return KDCReqBody{}, err
	}
	return b, nil
}

// names fills in whichever of the two optional principal names were
// present.
//
// An absent name decodes as a zero derPrincipalName, which is
// indistinguishable from a present one with no components -- so
// emptiness is the test, and it is the same test upstream makes.
func (d derKDCReqBody) names(b *KDCReqBody) error {
	if len(d.CName.Components) > 0 {
		n, err := d.CName.value()
		if err != nil {
			return err
		}
		b.CName = &n
	}
	if len(d.SName.Components) > 0 {
		n, err := d.SName.value()
		if err != nil {
			return err
		}
		b.SName = &n
	}
	return nil
}
