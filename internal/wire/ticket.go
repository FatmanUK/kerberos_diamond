package wire

import (
	"encoding/asn1"
	"time"
)

// Ticket is a Kerberos ticket: a server name in the clear and
// everything else sealed under that server's key.
type Ticket struct {
	Realm   string
	SName   PrincipalName
	EncPart EncryptedData
}

// derTicket is APPLICATION 1 around the SEQUENCE
// (asn1_k_encode.c:360-369). tkt-vno [0] is the protocol version, so
// it is Pvno and not a separate ticket version.
type derTicket struct {
	TktVno  int32            `asn1:"explicit,tag:0"`
	Realm   asn1.RawValue    `asn1:"explicit,tag:1"`
	SName   derPrincipalName `asn1:"explicit,tag:2"`
	EncPart derEncryptedData `asn1:"explicit,tag:3"`
}

// EncTicketPart is a ticket's sealed half: what the KDC decided and
// the client cannot alter.
type EncTicketPart struct {
	Flags     Flags
	Key       EncryptionKey
	CRealm    string
	CName     PrincipalName
	Transited TransitedEncoding

	AuthTime time.Time

	// StartTime and RenewTill are absent when zero, and the two
	// places this differs from EncKDCRepPart are both worth
	// knowing.
	//
	// Renew-till here is gated only on being non-zero
	// (asn1_k_encode.c:711,713), where EncKDCRepPart's is gated
	// on the RENEWABLE flag -- so the ticket and the reply can
	// disagree about whether the same ticket has one.
	//
	// Starttime here has a NULL decode initialiser
	// (opt_kerberos_time, :187 and DEFOPTIONALZEROTYPE at
	// asn1_encode.h:380), where EncKDCRepPart's is initialised to
	// authtime. So an absent starttime really does stay zero on
	// this structure. EffectiveStartTime applies the protocol's
	// default either way.
	StartTime time.Time
	EndTime   time.Time
	RenewTill time.Time

	// CAddr and AuthorizationData pass through as raw DER. The AS
	// exchange issues neither.
	CAddr             asn1.RawValue
	AuthorizationData asn1.RawValue
}

type derEncTicketPart struct {
	Flags     asn1.BitString       `asn1:"explicit,tag:0"`
	Key       derEncryptionKey     `asn1:"explicit,tag:1"`
	CRealm    asn1.RawValue        `asn1:"explicit,tag:2"`
	CName     derPrincipalName     `asn1:"explicit,tag:3"`
	Transited derTransitedEncoding `asn1:"explicit,tag:4"`

	// The DER field names are clipped so that gofmt's tag column
	// stays inside 70: "explicit,optional,generalized" is 44
	// columns of struct tag on its own.
	Auth  time.Time `asn1:"explicit,generalized,tag:5"`
	Start time.Time `asn1:"explicit,optional,generalized,tag:6"`
	End   time.Time `asn1:"explicit,generalized,tag:7"`
	Renew time.Time `asn1:"explicit,optional,generalized,tag:8"`

	CAddr     asn1.RawValue `asn1:"explicit,optional,tag:9"`
	AuthzData asn1.RawValue `asn1:"explicit,optional,tag:10"`
}

// MarshalTicket encodes a Ticket.
func MarshalTicket(t Ticket) ([]byte, error) {
	return asn1.MarshalWithParams(derTicket{
		TktVno:  Pvno,
		Realm:   ctxGstring(1, t.Realm),
		SName:   t.SName.der(),
		EncPart: t.EncPart.der(),
	}, appParams(tagTicket))
}

// UnmarshalTicket decodes a Ticket.
func UnmarshalTicket(b []byte) (Ticket, error) {
	var d derTicket
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagTicket)); err != nil {
		return Ticket{}, derErr("Ticket", err)
	}
	if err := checkPvno(d.TktVno); err != nil {
		return Ticket{}, err
	}
	realm, err := ctxGstringValue(d.Realm)
	if err != nil {
		return Ticket{}, err
	}
	sname, err := d.SName.value()
	if err != nil {
		return Ticket{}, err
	}
	return Ticket{
		Realm:   realm,
		SName:   sname,
		EncPart: d.EncPart.value(),
	}, nil
}

// MarshalEncTicketPart encodes a ticket's sealed half, ready to be
// encrypted under the server's key with key usage 2.
func MarshalEncTicketPart(e EncTicketPart) ([]byte, error) {
	return asn1.MarshalWithParams(derEncTicketPart{
		Flags:     e.Flags.bitString(),
		Key:       derKey(e.Key),
		CRealm:    ctxGstring(2, e.CRealm),
		CName:     e.CName.der(),
		Transited: derTransited(e.Transited),
		Auth:      kerberosTime(e.AuthTime),
		Start:     optTime(e.StartTime),
		End:       kerberosTime(e.EndTime),
		Renew:     optTime(e.RenewTill),
		CAddr:     e.CAddr,
		AuthzData: e.AuthorizationData,
	}, appParams(tagEncTktPt))
}

// UnmarshalEncTicketPart decodes a ticket's sealed half.
func UnmarshalEncTicketPart(b []byte) (EncTicketPart, error) {
	var d derEncTicketPart
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagEncTktPt)); err != nil {
		return EncTicketPart{}, derErr(
			"EncTicketPart", err)
	}
	return d.value()
}

func (d derEncTicketPart) value() (EncTicketPart, error) {
	fl, err := flagsFromBitString(d.Flags)
	if err != nil {
		return EncTicketPart{}, err
	}
	crealm, err := ctxGstringValue(d.CRealm)
	if err != nil {
		return EncTicketPart{}, err
	}
	cname, err := d.CName.value()
	if err != nil {
		return EncTicketPart{}, err
	}
	return EncTicketPart{
		Flags:             fl,
		Key:               d.Key.value(),
		CRealm:            crealm,
		CName:             cname,
		Transited:         d.Transited.value(),
		AuthTime:          d.Auth,
		StartTime:         d.Start,
		EndTime:           d.End,
		RenewTill:         d.Renew,
		CAddr:             d.CAddr,
		AuthorizationData: d.AuthzData,
	}, nil
}

// EffectiveStartTime is when the ticket becomes valid: StartTime if
// it was on the wire, and AuthTime otherwise.
//
// Upstream's decoder does not fill this one in -- unlike
// EncKDCRepPart's -- so every C caller that compares against a
// ticket's start time has to apply the default itself. Doing it here
// means a Go caller cannot forget to.
func (e EncTicketPart) EffectiveStartTime() time.Time {
	if e.StartTime.IsZero() {
		return e.AuthTime
	}
	return e.StartTime
}
