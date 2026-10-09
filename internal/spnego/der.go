package spnego

import "errors"

// The DER tags SPNEGO's own encoding uses (gssapiP_spnego.h:35-43).
// They are named rather than written in place because the
// context-specific ones are indistinguishable from each other at a
// glance, and getting [2] mechToken confused with [3] mechListMIC
// would be a silent authentication failure.
const (
	tagOID       byte = 0x06
	tagOctetStr  byte = 0x04
	tagSeq       byte = 0x30
	tagBitStr    byte = 0x03
	tagEnum      byte = 0x0a
	tagContext   byte = 0xa0
	tagAppConstr byte = 0x60
)

var errDER = errors.New("spnego: malformed DER")

// reader walks a DER encoding. It is deliberately tiny and
// deliberately not encoding/asn1: SPNEGO's NegotiationToken is a
// CHOICE of two context tags holding sequences of optional fields,
// and encoding/asn1 cannot express a CHOICE at all. The alternative
// is one struct per arm with RawValue fields and a hand-written
// discriminator, which is more code than this and less clear about
// what it refuses.
type reader struct {
	b   []byte
	err error
}

// peek reports whether the next value carries this tag. An absent
// optional field is not an error, which is the whole reason the
// reader works this way (k5_der_get_value leaves its input untouched
// and returns false, spnego_mech.c:3457-3473).
func (r *reader) peek(tag byte) bool {
	return r.err == nil && len(r.b) > 0 && r.b[0] == tag
}

// value consumes a value with this tag and returns its contents. A
// tag that is not there is reported as missing rather than malformed,
// so a caller can tell a field it may omit from one it may not.
func (r *reader) value(tag byte) ([]byte, bool) {
	if !r.peek(tag) {
		return nil, false
	}
	n, hdr, err := derLength(r.b)
	if err != nil {
		r.err = err
		return nil, false
	}
	if hdr+n > len(r.b) {
		r.err = errDER
		return nil, false
	}
	out := r.b[hdr : hdr+n]
	r.b = r.b[hdr+n:]
	return out, true
}

// done reports that nothing is left, which the outermost SEQUENCE
// requires: a trailing field nobody read is a field that was meant to
// mean something.
func (r *reader) done() bool {
	return r.err == nil && len(r.b) == 0
}

// derLength reads a tag and a definite length, returning the content
// length and the header size.
//
// Indefinite length (0x80) is refused. DER forbids it, and a BER
// encoder that used it would be telling us the length is wherever two
// zero octets happen to appear -- which inside an authentication
// token is an invitation rather than a tolerance.
func derLength(b []byte) (n, hdr int, err error) {
	if len(b) < 2 {
		return 0, 0, errDER
	}
	if b[1] < 0x80 {
		return int(b[1]), 2, nil
	}
	count := int(b[1] & 0x7f)
	if count == 0 || count > 4 || len(b) < 2+count {
		return 0, 0, errDER
	}
	for _, c := range b[2 : 2+count] {
		n = n<<8 | int(c)
	}
	if n < 0 {
		return 0, 0, errDER
	}
	return n, 2 + count, nil
}

// derValue writes a tag, a length and contents.
func derValue(tag byte, body []byte) []byte {
	out := derTagLen(tag, len(body))
	return append(out, body...)
}

// derTagLen writes a tag and a definite length in the shortest form,
// which is what DER requires and what k5_der_add_taglen emits.
func derTagLen(tag byte, n int) []byte {
	if n < 0x80 {
		return []byte{tag, byte(n)}
	}
	var size []byte
	for v := n; v > 0; v >>= 8 {
		size = append([]byte{byte(v)}, size...)
	}
	out := []byte{tag, byte(0x80 | len(size))}
	return append(out, size...)
}
