package wire

import (
	"encoding/asn1"
	"math/big"
	"time"
)

// APRep answers an AP-REQ that asked for mutual authentication.
//
// Nothing in a KDC exchange produces one: it is the application half
// of Kerberos, and the reason this project has it is the
// password-change protocol, where the reply carries an AP-REP
// whatever the client asked for (schpw.c:139).
type APRep struct {
	// EncPart is encrypted under the ticket's session key, or the
	// authenticator's subkey when it sent one, at key usage 12.
	EncPart EncryptedData
}

// derAPRep is APPLICATION 15 (asn1_k_encode.c:762-770).
type derAPRep struct {
	Vno     int32            `asn1:"explicit,tag:0"`
	MsgType int32            `asn1:"explicit,tag:1"`
	EncPart derEncryptedData `asn1:"explicit,tag:2"`
}

// MarshalAPRep encodes an AP-REP.
func MarshalAPRep(r APRep) ([]byte, error) {
	return asn1.MarshalWithParams(derAPRep{
		Vno:     Pvno,
		MsgType: MsgAPRep,
		EncPart: r.EncPart.der(),
	}, appParams(tagAPRep))
}

// UnmarshalAPRep decodes an AP-REP.
func UnmarshalAPRep(b []byte) (APRep, error) {
	var d derAPRep
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagAPRep)); err != nil {
		return APRep{}, derErr("AP-REP", err)
	}
	if err := checkPvno(d.Vno); err != nil {
		return APRep{}, err
	}
	if d.MsgType != MsgAPRep {
		return APRep{}, msgTypeErr(d.MsgType, MsgAPRep)
	}
	return APRep{EncPart: d.EncPart.value()}, nil
}

// EncAPRepPart is the AP-REP's sealed half, and what makes the
// authentication mutual: it echoes the client's own timestamp, which
// only the holder of the session key could have read.
type EncAPRepPart struct {
	// CTime and CUsec are the client's, copied from the
	// authenticator. CUsec is mandatory here, as it is in the
	// authenticator.
	CTime time.Time
	CUsec int32

	// SubKey, when present, is a key the *server* chose, which
	// replaces the client's for anything that follows.
	SubKey *EncryptionKey

	// SeqNumber is absent when zero, the same convention the
	// authenticator uses.
	SeqNumber uint32
}

// derEncAPRepPart is APPLICATION 27 (asn1_k_encode.c:772-781).
//
// Seq is a *big.Int for the reason derAuthenticator's is: upstream
// encodes a sequence number unsigned and encoding/asn1 has no
// unsigned support.
type derEncAPRepPart struct {
	CTime  time.Time        `asn1:"explicit,generalized,tag:0"`
	CUsec  int32            `asn1:"explicit,tag:1"`
	SubKey derEncryptionKey `asn1:"explicit,optional,tag:2"`
	Seq    *big.Int         `asn1:"explicit,optional,tag:3"`
}

// MarshalEncAPRepPart encodes an AP-REP's sealed half.
func MarshalEncAPRepPart(p EncAPRepPart) ([]byte, error) {
	d := derEncAPRepPart{
		CTime: p.CTime.UTC().Truncate(time.Second),
		CUsec: p.CUsec,
		Seq:   seqnoDER(p.SeqNumber),
	}
	if p.SubKey != nil {
		d.SubKey = derKey(*p.SubKey)
	}
	return asn1.MarshalWithParams(d,
		appParams(tagEncAPRepPart))
}

// UnmarshalEncAPRepPart decodes an AP-REP's sealed half.
func UnmarshalEncAPRepPart(b []byte) (EncAPRepPart, error) {
	var d derEncAPRepPart
	if _, err := asn1.UnmarshalWithParams(
		b, &d, appParams(tagEncAPRepPart)); err != nil {
		return EncAPRepPart{}, derErr("EncAPRepPart", err)
	}
	seq, err := seqnoValue(d.Seq)
	if err != nil {
		return EncAPRepPart{}, err
	}
	p := EncAPRepPart{
		CTime:     d.CTime,
		CUsec:     d.CUsec,
		SeqNumber: seq,
	}
	if len(d.SubKey.KeyValue) > 0 {
		k := d.SubKey.value()
		p.SubKey = &k
	}
	return p, nil
}
