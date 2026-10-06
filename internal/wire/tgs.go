package wire

import (
	"encoding/asn1"
	"fmt"
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

// ReqBodyBytes returns the DER of a KDC-REQ's req-body field, exactly
// as it appeared in the message.
//
// This exists because the authenticator's checksum in a TGS-REQ is
// over those bytes and not over a re-encoding. Upstream reaches into
// the raw stream for them with fetch_asn1_field(pkt, 1, 4, ...)
// (kdc/kdc_util.c:246-248, :968-1040) and only falls back to
// re-encoding the decoded body if the checksum over the raw bytes
// fails to verify -- which says plainly that it does not trust the
// two to agree. A KDC that checksummed its own re-encoding would
// reject every request from a peer whose DER differed in any respect.
//
// The returned slice aliases msg; it is not copied.
func ReqBodyBytes(msg []byte) ([]byte, error) {
	inner, err := appContent(msg)
	if err != nil {
		return nil, err
	}
	return ctxField(inner, 4)
}

// appContent steps past an [APPLICATION n] wrapper and the SEQUENCE
// inside it, returning the SEQUENCE's content.
func appContent(msg []byte) ([]byte, error) {
	body, err := tlvContent(msg)
	if err != nil {
		return nil, err
	}
	return tlvContent(body)
}

// ctxField returns the content of the context-tagged element with the
// given tag number, searching only the top level of a SEQUENCE's
// content.
func ctxField(seq []byte, tag int) ([]byte, error) {
	want := byte(0xA0 | tag)
	for len(seq) > 0 {
		id := seq[0]
		n, hdr, err := tlvLength(seq)
		if err != nil {
			return nil, err
		}
		if id == want {
			return seq[hdr : hdr+n], nil
		}
		seq = seq[hdr+n:]
	}
	return nil, fmt.Errorf("%w: no field [%d] in the body",
		ErrMalformed, tag)
}

// tlvContent returns one DER element's content.
func tlvContent(b []byte) ([]byte, error) {
	n, hdr, err := tlvLength(b)
	if err != nil {
		return nil, err
	}
	return b[hdr : hdr+n], nil
}

// tlvLength reads one DER element's length, returning the content
// length and the size of the identifier and length octets together.
//
// Indefinite length is rejected rather than handled: DER forbids it,
// and a message using it is not something this KDC should be guessing
// about.
func tlvLength(b []byte) (n, hdr int, err error) {
	if len(b) < 2 {
		return 0, 0, fmt.Errorf(
			"%w: %d bytes where a TLV should be",
			ErrMalformed, len(b))
	}
	l := int(b[1])
	if l < 0x80 {
		n, hdr = l, 2
	} else if l == 0x80 {
		return 0, 0, fmt.Errorf(
			"%w: indefinite length is not DER",
			ErrMalformed)
	} else {
		count := l & 0x7F
		if count > 4 || len(b) < 2+count {
			return 0, 0, fmt.Errorf(
				"%w: bad length of %d octets",
				ErrMalformed, count)
		}
		for _, c := range b[2 : 2+count] {
			n = n<<8 | int(c)
		}
		hdr = 2 + count
	}
	if n < 0 || hdr+n > len(b) {
		return 0, 0, fmt.Errorf(
			"%w: element claims %d bytes, %d remain",
			ErrMalformed, n, len(b)-hdr)
	}
	return n, hdr, nil
}
