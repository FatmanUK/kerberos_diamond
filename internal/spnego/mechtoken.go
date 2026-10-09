package spnego

import (
	"encoding/binary"
	"errors"
)

// The RFC 4121 token identifiers for context establishment
// (gssapiP_krb5.h:97-99). Two octets, big-endian, immediately after
// the framing.
const (
	TokIDAPReq uint16 = 0x0100
	TokIDAPRep uint16 = 0x0200
	TokIDError uint16 = 0x0300
)

// Errors a caller distinguishes, because an HTTP acceptor answers
// differently for each: bad framing is a malformed request, the wrong
// mechanism is a renegotiation, and the wrong token id is a client at
// the wrong point in the conversation.
var (
	ErrBadToken  = errors.New("spnego: bad token framing")
	ErrWrongMech = errors.New("spnego: not a Kerberos mechanism")
	ErrWrongTok  = errors.New("spnego: wrong token id")
)

// MechToken is RFC 2743 §3.1 framing: an APPLICATION 0 wrapper
// holding the mechanism OID and then the mechanism's own token, which
// for Kerberos begins with a two-octet identifier.
type MechToken struct {
	Mech  OID
	TokID uint16
	Body  []byte
}

// Marshal writes the framing (g_make_token_header,
// generic/util_token.c:52-64).
func (t MechToken) Marshal() []byte {
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], t.TokID)
	body := append(derValue(tagOID, t.Mech), id[:]...)
	body = append(body, t.Body...)
	return derValue(tagAppConstr, body)
}

// ParseFramed reads RFC 2743 framing and returns the mechanism OID
// and everything after it.
//
// The length check is upstream's and is stricter than it looks: the
// outermost DER length must account for *the whole input*, not merely
// fit inside it (g_verify_token_header, generic/util_token.c:104-121,
// and parse_init_token, accept_sec_context.c:641-646). Trailing
// octets after a well-formed token are a refusal, not something to
// ignore, which matters here because an HTTP header's base64 is
// decoded by somebody else and a sloppy encoder's padding would
// otherwise travel into the AP-REQ parser.
func ParseFramed(b []byte) (OID, []byte, error) {
	r := &reader{b: b}
	body, ok := r.value(tagAppConstr)
	if !ok || r.err != nil || !r.done() {
		return nil, nil, ErrBadToken
	}
	in := &reader{b: body}
	oid, ok := in.value(tagOID)
	if !ok || in.err != nil {
		return nil, nil, ErrBadToken
	}
	return OID(oid), in.b, nil
}

// ParseMechToken reads the framing and the two-octet RFC 4121 token
// identifier that follows it for a Kerberos mechanism.
func ParseMechToken(b []byte) (MechToken, error) {
	var t MechToken
	oid, rest, err := ParseFramed(b)
	if err != nil {
		return t, err
	}
	if !IsKerberos(oid) {
		return t, ErrWrongMech
	}
	if len(rest) < 2 {
		return t, ErrBadToken
	}
	t.Mech = oid
	t.TokID = binary.BigEndian.Uint16(rest[:2])
	t.Body = rest[2:]
	return t, nil
}

// APReqToken reads an initiator's context-establishment token and
// returns the AP-REQ inside it.
func APReqToken(b []byte) ([]byte, OID, error) {
	t, err := ParseMechToken(b)
	if err != nil {
		return nil, nil, err
	}
	if t.TokID != TokIDAPReq {
		return nil, nil, ErrWrongTok
	}
	return t.Body, t.Mech, nil
}

// APRepToken wraps an AP-REP for the reply, under the same mechanism
// OID the initiator used (accept_sec_context.c:1101). Answering under
// the OID that arrived is what makes Microsoft's broken spelling
// work: a client that sent it compares what comes back against what
// it sent.
func APRepToken(mech OID, apRep []byte) []byte {
	return MechToken{
		Mech:  mech,
		TokID: TokIDAPRep,
		Body:  apRep,
	}.Marshal()
}
