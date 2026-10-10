package spake

import (
	"encoding/asn1"
	"errors"

	"github.com/FatmanUK/kerberos_diamond/internal/wire"
)

// PAType is PA-SPAKE's padata number (KRB5_PADATA_SPAKE).
const PAType int32 = 151

// MsgType is which arm of the PA-SPAKE CHOICE a message is
// (asn1_k_encode.c:1757-1766).
type MsgType int

const (
	// MsgSupport is the client saying which groups it has.
	MsgSupport MsgType = 0

	// MsgChallenge is the KDC's reply: a group, its public
	// element, and the second factors it will accept.
	MsgChallenge MsgType = 1

	// MsgResponse is the client's public element and its factor
	// reply, sealed with K'[1].
	MsgResponse MsgType = 2

	// MsgEncData is a further second-factor round, which neither
	// this project nor upstream implements -- verify_encdata
	// refuses it outright and says in a comment what would go
	// there (spake_kdc.c:481-498).
	MsgEncData MsgType = 3
)

// SFNone is the only second-factor type there is: "no second factor",
// which the KDC offers and the client answers with (SPAKE_SF_NONE).
// Upstream hardcodes it on both sides and marks the place a real
// factor would go.
const SFNone int32 = 1

// ErrBadMessage reports a PA-SPAKE value that is not one.
var ErrBadMessage = errors.New("spake: malformed message")

// Factor is one second-factor offer or reply (krb5_spake_factor,
// asn1_k_encode.c:1721-1726).
type Factor struct {
	Type int32

	// Data is absent for SF-NONE, which is the only type in use.
	Data []byte
}

// Support is the client's list of groups, most preferred first.
type Support struct {
	Groups []int32
}

// Challenge is the KDC's reply.
type Challenge struct {
	Group   int32
	PubKey  []byte
	Factors []Factor
}

// Response is the client's reply.
type Response struct {
	PubKey []byte

	// Factor is a SPAKEFactor sealed with K'[1] at key usage 65.
	// Decrypting it is what proves the client derived the same
	// keys, which is what proves it knew the password -- so the
	// integrity check failing is a wrong password and is reported
	// as a pre-authentication failure rather than as corruption
	// (spake_kdc.c:428-432).
	Factor wire.EncryptedData
}

// Message is a decoded PA-SPAKE value, which is a CHOICE: exactly one
// of the four is set, and Type says which.
type Message struct {
	Type      MsgType
	Support   *Support
	Challenge *Challenge
	Response  *Response
	EncData   *wire.EncryptedData
}

type derFactor struct {
	Type int32  `asn1:"explicit,tag:0"`
	Data []byte `asn1:"explicit,optional,tag:1"`
}

type derSupport struct {
	Groups []int32 `asn1:"explicit,tag:0"`
}

type derChallenge struct {
	Group   int32       `asn1:"explicit,tag:0"`
	PubKey  []byte      `asn1:"explicit,tag:1"`
	Factors []derFactor `asn1:"explicit,tag:2"`
}

type derResponse struct {
	PubKey []byte        `asn1:"explicit,tag:0"`
	Factor asn1.RawValue `asn1:"explicit,tag:1"`
}

// MarshalFactor encodes a SPAKEFactor, which is what the response's
// sealed field holds.
func MarshalFactor(f Factor) ([]byte, error) {
	return asn1.Marshal(derFactor{
		Type: f.Type, Data: f.Data,
	})
}

// UnmarshalFactor decodes one.
func UnmarshalFactor(b []byte) (Factor, error) {
	var d derFactor
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return Factor{}, ErrBadMessage
	}
	return Factor{Type: d.Type, Data: d.Data}, nil
}

// MarshalMessage encodes a PA-SPAKE value.
//
// The CHOICE is a context tag around the arm, which encoding/asn1
// cannot express directly -- so the arm is encoded and then wrapped,
// which is the same thing the DEFCTAGGEDTYPE macros do
// (asn1_k_encode.c:1757-1760).
func MarshalMessage(m Message) ([]byte, error) {
	body, err := marshalArm(m)
	if err != nil {
		return nil, err
	}
	return wire.CtxWrap(int(m.Type), body), nil
}

// marshalArm encodes whichever arm is set.
func marshalArm(m Message) ([]byte, error) {
	switch {
	case m.Type == MsgSupport && m.Support != nil:
		return asn1.Marshal(derSupport{
			Groups: m.Support.Groups,
		})
	case m.Type == MsgChallenge && m.Challenge != nil:
		return marshalChallenge(*m.Challenge)
	case m.Type == MsgResponse && m.Response != nil:
		return marshalResponse(*m.Response)
	case m.Type == MsgEncData && m.EncData != nil:
		return wire.MarshalEncryptedData(*m.EncData)
	}
	return nil, ErrBadMessage
}

// marshalChallenge encodes the KDC's reply.
func marshalChallenge(c Challenge) ([]byte, error) {
	d := derChallenge{Group: c.Group, PubKey: c.PubKey}
	for _, f := range c.Factors {
		d.Factors = append(d.Factors, derFactor{
			Type: f.Type, Data: f.Data,
		})
	}
	return asn1.Marshal(d)
}

// marshalResponse encodes the client's reply.
func marshalResponse(r Response) ([]byte, error) {
	ed, err := wire.MarshalEncryptedData(r.Factor)
	if err != nil {
		return nil, err
	}
	// The tag goes inside the RawValue: encoding/asn1 emits
	// FullBytes verbatim and ignores the field's `explicit' tag,
	// so a bare EncryptedData here would encode with no [1]
	// around it and decode as absent. wire.CtxContent reads it
	// back whichever way round it is.
	return asn1.Marshal(derResponse{
		PubKey: r.PubKey,
		Factor: wire.CtxRaw(1, ed),
	})
}

// UnmarshalMessage decodes a PA-SPAKE value.
//
// The arm number is the context tag, and an unknown one is a
// malformed message rather than something to ignore: a CHOICE with an
// arm nobody recognises cannot be acted on, and guessing which of the
// four was meant would be worse than refusing.
func UnmarshalMessage(b []byte) (Message, error) {
	tag, body, ok := wire.CtxTagOf(b)
	if !ok {
		return Message{}, ErrBadMessage
	}
	m := Message{Type: MsgType(tag)}
	switch m.Type {
	case MsgSupport:
		return unmarshalSupport(m, body)
	case MsgChallenge:
		return unmarshalChallenge(m, body)
	case MsgResponse:
		return unmarshalResponse(m, body)
	case MsgEncData:
		ed, err := wire.UnmarshalEncryptedData(body)
		if err != nil {
			return Message{}, ErrBadMessage
		}
		m.EncData = &ed
		return m, nil
	}
	return Message{}, ErrBadMessage
}

// unmarshalSupport decodes the client's group list.
func unmarshalSupport(
	m Message,
	body []byte,
) (Message, error) {
	var d derSupport
	if _, err := asn1.Unmarshal(body, &d); err != nil {
		return Message{}, ErrBadMessage
	}
	m.Support = &Support{Groups: d.Groups}
	return m, nil
}

// unmarshalChallenge decodes the KDC's reply.
func unmarshalChallenge(
	m Message,
	body []byte,
) (Message, error) {
	var d derChallenge
	if _, err := asn1.Unmarshal(body, &d); err != nil {
		return Message{}, ErrBadMessage
	}
	c := &Challenge{Group: d.Group, PubKey: d.PubKey}
	for _, f := range d.Factors {
		c.Factors = append(c.Factors, Factor{
			Type: f.Type, Data: f.Data,
		})
	}
	m.Challenge = c
	return m, nil
}

// unmarshalResponse decodes the client's reply.
func unmarshalResponse(
	m Message,
	body []byte,
) (Message, error) {
	var d derResponse
	if _, err := asn1.Unmarshal(body, &d); err != nil {
		return Message{}, ErrBadMessage
	}
	ed, err := wire.UnmarshalEncryptedData(
		wire.CtxContent(d.Factor))
	if err != nil {
		return Message{}, ErrBadMessage
	}
	m.Response = &Response{PubKey: d.PubKey, Factor: ed}
	return m, nil
}
