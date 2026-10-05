package wire

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// ASRep is an AS-REP: the ticket, plus a copy of what is in it
// encrypted under the client's own key so the client can read it.
type ASRep struct {
	// PAData in a reply is the unencrypted padata, distinct from
	// EncKDCRepPart.EncPAData.
	PAData []PAData

	CRealm  string
	CName   PrincipalName
	Ticket  Ticket
	EncPart EncryptedData
}

// derASRep is KDC-REP (asn1_k_encode.c:731-744) wrapped in
// APPLICATION 11. Unlike KDC-REQ, this one does start at [0].
//
// Ticket is a RawValue because the field is a context tag around an
// already APPLICATION-tagged type, and encoding/asn1 cannot stack two
// tags on one field. The ticket is marshalled on its own and carried
// here as FullBytes.
type derASRep struct {
	Pvno    int32       `asn1:"explicit,tag:0"`
	MsgType int32       `asn1:"explicit,tag:1"`
	PAData  []derPAData `asn1:"explicit,optional,tag:2"`

	CRealm asn1.RawValue    `asn1:"explicit,tag:3"`
	CName  derPrincipalName `asn1:"explicit,tag:4"`

	Ticket  asn1.RawValue    `asn1:"explicit,tag:5"`
	EncPart derEncryptedData `asn1:"explicit,tag:6"`
}

// EncKDCRepPart is the reply's sealed half. For an AS-REP it is
// encrypted under the client's long-term key with key usage 3.
type EncKDCRepPart struct {
	Key EncryptionKey

	// LastReq must have at least one entry: upstream's seqof is
	// declared non-empty. The KDC's own filler is a single {type
	// 0, time 0} entry (kdc_util.c:677-688).
	LastReq []LastReqEntry

	Nonce int32

	// KeyExpiration is absent when zero.
	KeyExpiration time.Time

	Flags    Flags
	AuthTime time.Time

	// StartTime is absent when zero, and that is the whole of the
	// encoder's rule: the C encoder's predicate is starttime != 0
	// (asn1_k_encode.c:388-391), and it writes the field even
	// when it equals authtime. What zeroes it when the two match
	// is the KDC (do_as_req.c:706-711), so that behaviour belongs
	// in internal/kdc and deliberately is not here -- a codec
	// that applied it could not re-encode a message it had just
	// decoded.
	//
	// On decode an absent starttime is *initialised to AuthTime*
	// (asn1_k_encode.c:392-399), not left zero, so this field is
	// always populated after a successful decode. That asymmetry
	// is why the encoder cannot infer absence from it.
	StartTime time.Time

	EndTime time.Time

	// RenewTill goes on the wire only when FlagRenewable is set
	// in Flags (asn1_k_encode.c:402-405,422). Setting it without
	// the flag drops it silently, and that is deliberate here: it
	// is what upstream does, and a Go encoder that wrote the
	// field anyway would produce a reply no C client agrees with.
	RenewTill time.Time

	SRealm string
	SName  PrincipalName

	// CAddr passes through as raw DER; the AS exchange issues
	// none.
	CAddr asn1.RawValue

	// EncPAData is the *encrypted* padata, distinct from the
	// AS-REP's cleartext padata. RFC 6806's reply checksum
	// travels here, and a client that asked for one refuses the
	// reply without it (krb5int_fast_verify_nego,
	// lib/krb5/krb/fast.c :635-673).
	EncPAData []PAData
}

type derEncKDCRepPart struct {
	Key     derEncryptionKey  `asn1:"explicit,tag:0"`
	LastReq []derLastReqEntry `asn1:"explicit,tag:1"`
	Nonce   int32             `asn1:"explicit,tag:2"`

	// As in derEncTicketPart, the DER field names are clipped and
	// grouped so gofmt's tag column stays inside 70 columns.
	KeyExp time.Time `asn1:"explicit,optional,generalized,tag:3"`

	Flags asn1.BitString `asn1:"explicit,tag:4"`

	Auth  time.Time `asn1:"explicit,generalized,tag:5"`
	Start time.Time `asn1:"explicit,optional,generalized,tag:6"`
	End   time.Time `asn1:"explicit,generalized,tag:7"`
	Renew time.Time `asn1:"explicit,optional,generalized,tag:8"`

	SRealm asn1.RawValue    `asn1:"explicit,tag:9"`
	SName  derPrincipalName `asn1:"explicit,tag:10"`

	CAddr     asn1.RawValue `asn1:"explicit,optional,tag:11"`
	EncPAData []derPAData   `asn1:"explicit,optional,tag:12"`
}

// errEmptyLastReq rejects a reply carrying no last-req entries.
// Upstream declares the sequence non-empty (asn1_k_encode.c:357), so
// an empty one is not a thing a C peer will decode.
var errEmptyLastReq = fmt.Errorf(
	"%w: last-req is empty", ErrMalformed)

// MarshalASRep encodes an AS-REP.
func MarshalASRep(r ASRep) ([]byte, error) {
	tkt, err := MarshalTicket(r.Ticket)
	if err != nil {
		return nil, err
	}
	return asn1.MarshalWithParams(derASRep{
		Pvno:    Pvno,
		MsgType: MsgASRep,
		PAData:  paDataDER(r.PAData),
		CRealm:  ctxGstring(3, r.CRealm),
		CName:   r.CName.der(),
		Ticket:  ctxWrap(5, tkt),
		EncPart: r.EncPart.der(),
	}, appParams(tagASRep))
}

// UnmarshalASRep decodes an AS-REP.
func UnmarshalASRep(b []byte) (ASRep, error) {
	var d derASRep
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagASRep)); err != nil {
		return ASRep{}, derErr("AS-REP", err)
	}
	if err := checkPvno(d.Pvno); err != nil {
		return ASRep{}, err
	}
	if d.MsgType != MsgASRep {
		return ASRep{}, msgTypeErr(d.MsgType, MsgASRep)
	}
	return d.value()
}

func (d derASRep) value() (ASRep, error) {
	crealm, err := ctxGstringValue(d.CRealm)
	if err != nil {
		return ASRep{}, err
	}
	cname, err := d.CName.value()
	if err != nil {
		return ASRep{}, err
	}
	tkt, err := UnmarshalTicket(ctxUnwrap(d.Ticket))
	if err != nil {
		return ASRep{}, err
	}
	return ASRep{
		PAData:  paDataValues(d.PAData),
		CRealm:  crealm,
		CName:   cname,
		Ticket:  tkt,
		EncPart: d.EncPart.value(),
	}, nil
}

// MarshalEncASRepPart encodes the reply's sealed half.
//
// It writes APPLICATION 26, the EncTGSRepPart tag, not the 25 that
// RFC 4120 assigns to EncASRepPart. That is not a mistake: upstream
// binds encode_krb5_enc_kdc_rep_part to enc_tgs_rep_part
// unconditionally (asn1_k_encode.c:1133), so 26 is what every MIT KDC
// has ever sent and what every client is built to read.
func MarshalEncASRepPart(e EncKDCRepPart) ([]byte, error) {
	d, err := e.der()
	if err != nil {
		return nil, err
	}
	return asn1.MarshalWithParams(d, appParams(tagEncTGSRepPart))
}

// UnmarshalEncKDCRepPart decodes the reply's sealed half, accepting
// either application tag.
//
// 26 is tried first because it is what MIT writes; 25 is the tag the
// RFC specifies and some other implementations use. Accepting only 25
// would fail against every MIT KDC in existence, which is why the
// fallback exists in upstream too (asn1_k_encode.c:1136-1155).
func UnmarshalEncKDCRepPart(b []byte) (EncKDCRepPart, error) {
	var d derEncKDCRepPart
	_, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagEncTGSRepPart))
	if err != nil {
		_, err = asn1.UnmarshalWithParams(
			b, &d, appParams(tagEncASRepPart))
	}
	if err != nil {
		return EncKDCRepPart{}, derErr(
			"EncKDCRepPart", err)
	}
	return d.value()
}

func (e EncKDCRepPart) der() (derEncKDCRepPart, error) {
	if len(e.LastReq) == 0 {
		return derEncKDCRepPart{}, errEmptyLastReq
	}
	renew := time.Time{}
	if e.Flags.Has(FlagRenewable) {
		renew = optTime(e.RenewTill)
	}
	return derEncKDCRepPart{
		Key:       derKey(e.Key),
		LastReq:   derLastReqs(e.LastReq),
		Nonce:     e.Nonce,
		KeyExp:    optTime(e.KeyExpiration),
		Flags:     e.Flags.bitString(),
		Auth:      kerberosTime(e.AuthTime),
		Start:     optTime(e.StartTime),
		End:       kerberosTime(e.EndTime),
		Renew:     renew,
		SRealm:    ctxGstring(9, e.SRealm),
		SName:     e.SName.der(),
		CAddr:     e.CAddr,
		EncPAData: paDataDER(e.EncPAData),
	}, nil
}

func (d derEncKDCRepPart) value() (EncKDCRepPart, error) {
	fl, err := flagsFromBitString(d.Flags)
	if err != nil {
		return EncKDCRepPart{}, err
	}
	srealm, err := ctxGstringValue(d.SRealm)
	if err != nil {
		return EncKDCRepPart{}, err
	}
	sname, err := d.SName.value()
	if err != nil {
		return EncKDCRepPart{}, err
	}
	return EncKDCRepPart{
		Key:           d.Key.value(),
		LastReq:       lastReqValues(d.LastReq),
		Nonce:         d.Nonce,
		KeyExpiration: d.KeyExp,
		Flags:         fl,
		AuthTime:      d.Auth,
		StartTime:     d.Start,
		EndTime:       d.End,
		RenewTill:     d.Renew,
		SRealm:        srealm,
		SName:         sname,
		CAddr:         d.CAddr,
		EncPAData:     paDataValues(d.EncPAData),
	}, nil
}

// EffectiveStartTime is when the ticket becomes valid: StartTime if
// it was on the wire, and AuthTime otherwise. That default is
// upstream's (asn1_k_encode.c:392-399); reading StartTime directly
// and finding zero would place the ticket's validity in 1970.
func (e EncKDCRepPart) EffectiveStartTime() time.Time {
	if e.StartTime.IsZero() {
		return e.AuthTime
	}
	return e.StartTime
}
