package wire

import (
	"encoding/asn1"
)

// TGSReq is a TGS-REQ: a client spending a ticket it already has to
// ask for another.
//
// It is the *same* structure as an AS-REQ. Upstream encodes both from
// one krb5_kdc_req with only the application tag and the msg-type
// differing (asn1_k_encode.c:794-795), so this is an alias rather
// than a copy -- a second struct would be two places to get the
// context tags wrong instead of one.
//
// What differs is the content, not the shape: PAData carries a
// PA-TGS-REQ holding an AP-REQ, and CName is absent because the
// ticket says who the client is.
type TGSReq = ASReq

// TGSRep is a TGS-REP, likewise the same KDC-REP structure as an
// AS-REP (asn1_k_encode.c:744-745).
type TGSRep = ASRep

// MarshalTGSReq encodes a TGS-REQ.
func MarshalTGSReq(r TGSReq) ([]byte, error) {
	body, err := r.Body.der()
	if err != nil {
		return nil, err
	}
	return asn1.MarshalWithParams(derASReq{
		Pvno:    Pvno,
		MsgType: MsgTGSReq,
		PAData:  paDataDER(r.PAData),
		Body:    body,
	}, appParams(tagTGSReq))
}

// UnmarshalTGSReq decodes a TGS-REQ.
func UnmarshalTGSReq(b []byte) (TGSReq, error) {
	var d derASReq
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagTGSReq)); err != nil {
		return TGSReq{}, derErr("TGS-REQ", err)
	}
	if err := checkPvno(d.Pvno); err != nil {
		return TGSReq{}, err
	}
	if d.MsgType != MsgTGSReq {
		return TGSReq{}, msgTypeErr(d.MsgType, MsgTGSReq)
	}
	body, err := d.Body.value()
	if err != nil {
		return TGSReq{}, err
	}
	return TGSReq{
		PAData: paDataValues(d.PAData),
		Body:   body,
	}, nil
}

// MarshalTGSRep encodes a TGS-REP.
func MarshalTGSRep(r TGSRep) ([]byte, error) {
	tkt, err := MarshalTicket(r.Ticket)
	if err != nil {
		return nil, err
	}
	return asn1.MarshalWithParams(derASRep{
		Pvno:    Pvno,
		MsgType: MsgTGSRep,
		PAData:  paDataDER(r.PAData),
		CRealm:  ctxGstring(3, r.CRealm),
		CName:   r.CName.der(),
		Ticket:  ctxWrap(5, tkt),
		EncPart: r.EncPart.der(),
	}, appParams(tagTGSRep))
}

// UnmarshalTGSRep decodes a TGS-REP.
func UnmarshalTGSRep(b []byte) (TGSRep, error) {
	var d derASRep
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagTGSRep)); err != nil {
		return TGSRep{}, derErr("TGS-REP", err)
	}
	if err := checkPvno(d.Pvno); err != nil {
		return TGSRep{}, err
	}
	if d.MsgType != MsgTGSRep {
		return TGSRep{}, msgTypeErr(d.MsgType, MsgTGSRep)
	}
	return d.value()
}

// MarshalEncTGSRepPart encodes a TGS-REP's sealed half.
//
// It is MarshalEncASRepPart, and deliberately so: upstream writes
// both with application tag 26, which is the whole of the quirk that
// function documents. Having the name here means a TGS call site does
// not have to look as though it is borrowing the AS encoder.
func MarshalEncTGSRepPart(e EncKDCRepPart) ([]byte, error) {
	return MarshalEncASRepPart(e)
}
