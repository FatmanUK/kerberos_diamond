package wire

import (
	"encoding/asn1"
	"math/big"
	"time"
)

// Authenticator proves to a server that the client holds the session
// key from the ticket it presented, and that this is not a replay.
//
// It is encrypted under that session key, so possessing a ticket is
// not enough: a captured ticket without the session key cannot be
// used.
type Authenticator struct {
	CRealm string
	CName  PrincipalName

	// Cksum is over the message the authenticator accompanies. In
	// a TGS-REQ it covers the KDC-REQ-BODY, keyed with the TGT's
	// session key under key usage 6, and is what stops the body
	// being altered in flight.
	Cksum *Checksum

	// CUsec is mandatory here, unlike the microsecond companions
	// elsewhere: a cusec of 0 goes on the wire
	// (asn1_k_encode.c:689).
	CUsec int32
	CTime time.Time

	// SubKey, when present, replaces the ticket's session key for
	// the reply. SeqNumber is absent when zero.
	SubKey    *EncryptionKey
	SeqNumber uint32

	// AuthorizationData passes through as raw DER.
	AuthorizationData asn1.RawValue
}

// derAuthenticator is APPLICATION 2 around the SEQUENCE
// (asn1_k_encode.c:685-704).
//
// SeqNumber is a *big.Int because upstream encodes it *unsigned*
// (encode_seqno, :123-131) while encoding/asn1 has no unsigned
// support at all. A sequence number above 2^31-1 written as a Go
// int32 would be a negative INTEGER -- which upstream's decoder does
// accept, for interoperability with old implementations (:133-146),
// but which is not what it writes.
type derAuthenticator struct {
	Vno    int32            `asn1:"explicit,tag:0"`
	CRealm asn1.RawValue    `asn1:"explicit,tag:1"`
	CName  derPrincipalName `asn1:"explicit,tag:2"`
	Cksum  derChecksum      `asn1:"explicit,optional,tag:3"`
	CUsec  int32            `asn1:"explicit,tag:4"`

	CTime time.Time `asn1:"explicit,generalized,tag:5"`

	SubKey derEncryptionKey `asn1:"explicit,optional,tag:6"`
	Seq    *big.Int         `asn1:"explicit,optional,tag:7"`
	Authz  asn1.RawValue    `asn1:"explicit,optional,tag:8"`
}

// MarshalAuthenticator encodes an Authenticator.
func MarshalAuthenticator(a Authenticator) ([]byte, error) {
	d := derAuthenticator{
		Vno:    Pvno,
		CRealm: ctxGstring(1, a.CRealm),
		CName:  a.CName.der(),
		CUsec:  a.CUsec,
		CTime:  kerberosTime(a.CTime),
		Seq:    seqnoDER(a.SeqNumber),
		Authz:  a.AuthorizationData,
	}
	if a.Cksum != nil {
		d.Cksum = derChecksum{
			Type:     a.Cksum.Type,
			Checksum: a.Cksum.Checksum,
		}
	}
	if a.SubKey != nil {
		d.SubKey = derKey(*a.SubKey)
	}
	return asn1.MarshalWithParams(d, appParams(tagAuthenticator))
}

// UnmarshalAuthenticator decodes an Authenticator.
func UnmarshalAuthenticator(b []byte) (Authenticator, error) {
	var d derAuthenticator
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagAuthenticator)); err != nil {
		return Authenticator{}, derErr("Authenticator", err)
	}
	if err := checkPvno(d.Vno); err != nil {
		return Authenticator{}, err
	}
	return d.value()
}

func (d derAuthenticator) value() (Authenticator, error) {
	crealm, err := ctxGstringValue(d.CRealm)
	if err != nil {
		return Authenticator{}, err
	}
	cname, err := d.CName.value()
	if err != nil {
		return Authenticator{}, err
	}
	seq, err := seqnoValue(d.Seq)
	if err != nil {
		return Authenticator{}, err
	}
	a := Authenticator{
		CRealm:            crealm,
		CName:             cname,
		CUsec:             d.CUsec,
		CTime:             d.CTime,
		SeqNumber:         seq,
		AuthorizationData: d.Authz,
	}
	if len(d.Cksum.Checksum) > 0 {
		a.Cksum = &Checksum{
			Type:     d.Cksum.Type,
			Checksum: d.Cksum.Checksum,
		}
	}
	if len(d.SubKey.KeyValue) > 0 {
		k := d.SubKey.value()
		a.SubKey = &k
	}
	return a, nil
}

// AP options, from RFC 4120 section 5.5.1. They share KerberosFlags'
// bit numbering, so bit 0 is again the most significant.
const (
	APOptUseSessionKey  Flags = 1 << (31 - 1)
	APOptMutualRequired Flags = 1 << (31 - 2)
)

// APReq presents a ticket and proves possession of its session key.
// In a TGS-REQ it travels as the PA-TGS-REQ padata.
type APReq struct {
	Options Flags
	Ticket  Ticket

	// Authenticator is encrypted under the ticket's session key
	// -- key usage 7 in a TGS-REQ, 11 in an application exchange.
	Authenticator EncryptedData
}

// derAPReq is APPLICATION 14 (asn1_k_encode.c:751-760).
type derAPReq struct {
	Vno     int32          `asn1:"explicit,tag:0"`
	MsgType int32          `asn1:"explicit,tag:1"`
	Options asn1.BitString `asn1:"explicit,tag:2"`

	Ticket        asn1.RawValue    `asn1:"explicit,tag:3"`
	Authenticator derEncryptedData `asn1:"explicit,tag:4"`
}

// MarshalAPReq encodes an AP-REQ.
func MarshalAPReq(r APReq) ([]byte, error) {
	tkt, err := MarshalTicket(r.Ticket)
	if err != nil {
		return nil, err
	}
	return asn1.MarshalWithParams(derAPReq{
		Vno:           Pvno,
		MsgType:       MsgAPReq,
		Options:       r.Options.bitString(),
		Ticket:        ctxWrap(3, tkt),
		Authenticator: r.Authenticator.der(),
	}, appParams(tagAPReq))
}

// UnmarshalAPReq decodes an AP-REQ.
func UnmarshalAPReq(b []byte) (APReq, error) {
	var d derAPReq
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagAPReq)); err != nil {
		return APReq{}, derErr("AP-REQ", err)
	}
	if err := checkPvno(d.Vno); err != nil {
		return APReq{}, err
	}
	if d.MsgType != MsgAPReq {
		return APReq{}, msgTypeErr(d.MsgType, MsgAPReq)
	}
	opts, err := flagsFromBitString(d.Options)
	if err != nil {
		return APReq{}, err
	}
	tkt, err := UnmarshalTicket(ctxUnwrap(d.Ticket))
	if err != nil {
		return APReq{}, err
	}
	return APReq{
		Options:       opts,
		Ticket:        tkt,
		Authenticator: d.Authenticator.value(),
	}, nil
}

// seqnoDER encodes a sequence number the way upstream does: unsigned,
// so a value above 2^31-1 is a positive INTEGER and not the negative
// one a signed encoder would write. Zero is absent
// (DEFOPTIONALZEROTYPE, asn1_k_encode.c:154).
func seqnoDER(n uint32) *big.Int {
	if n == 0 {
		return nil
	}
	return new(big.Int).SetUint64(uint64(n))
}

// seqnoValue reads a sequence number back.
//
// A negative value is accepted and cast, which is what upstream does
// deliberately for interoperability with old implementations that
// encoded these signed (decode_seqno, asn1_k_encode.c:133-146).
func seqnoValue(b *big.Int) (uint32, error) {
	if b == nil {
		return 0, nil
	}
	if !b.IsInt64() {
		return 0, seqnoRangeErr
	}
	v := b.Int64()
	if v < -0x80000000 || v > 0xFFFFFFFF {
		return 0, seqnoRangeErr
	}
	return uint32(int32(v)), nil
}
