// Package wire encodes and decodes the Kerberos 5 protocol messages.
//
// Only what the AS exchange touches is here. The approach is
// encoding/asn1 for the structure, with this package owning the
// places it cannot express:
//
// GeneralString. Kerberos realms and name components are
// GeneralString (tag 27), and encoding/asn1 will *read* one into a Go
// string but writes a Go string as PrintableString (tag 19). Every
// such field is therefore an asn1.RawValue on the DER side.
//
// That brings its own trap, and it is the reason this package has a
// DER length encoder in it. encoding/asn1 treats an asn1.RawValue as
// opaque, but not symmetrically: on decode it matches the field's
// explicit context tag and hands over the whole context-tagged
// element, while on encode makeField returns the RawValue's bytes
// before it reaches any tagging code, so explicit,tag:N is silently
// ignored. A RawValue field that is directly context-tagged must
// therefore carry its own wrapper -- ctxGstring builds it -- while a
// RawValue *inside* a SEQUENCE OF needs no wrapper and gstring is
// right for those. Getting this backwards produces a message that
// decodes fine in Go and is rejected by every C peer.
//
// Optional-when-zero. Upstream decides a field's presence from its C
// value rather than tracking it, so a timestamp of exactly zero is
// omitted and a zero kvno is absent. The exported types here use the
// Go zero value the same way, and say so field by field.
//
// Application tags. The outer messages are [APPLICATION n] wrapped
// around a SEQUENCE, which encoding/asn1 handles through
// MarshalWithParams rather than a struct tag, so each message has a
// marshal function rather than being a bare struct.
//
// The exported types are Go-shaped; the DER shapes are unexported
// structs beside them. That split is deliberate: the quirks live in
// the conversion, where they can be named and tested, rather than
// leaking into every caller.
package wire

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

// Pvno is the Kerberos protocol version, 5, carried in every message.
const Pvno = 5

// Kerberos message types, from the application tag numbers each
// message is wrapped in.
const (
	MsgASReq    = 10
	MsgASRep    = 11
	MsgTGSReq   = 12
	MsgTGSRep   = 13
	MsgAPReq    = 14
	MsgKRBError = 30
)

// The application tag numbers themselves. Most match the message
// type, and the two that do not are the interesting ones.
const (
	tagTicket        = 1
	tagAuthenticator = 2
	tagEncTktPt      = 3
	tagASReq         = 10
	tagASRep         = 11
	tagTGSReq        = 12
	tagTGSRep        = 13
	tagAPReq         = 14
	tagKRBError      = 30

	// tagEncASRepPart is 25 by RFC 4120, and 26 is what MIT
	// actually writes -- see asTagEncASRepPart in asrep.go.
	tagEncASRepPart    = 25
	tagEncTGSRepPart   = 26
	tagGeneralString   = 27
	flagsBitStringBits = 32
)

// ErrMalformed reports a message that is not valid DER, or is valid
// DER of the wrong shape.
var ErrMalformed = errors.New("malformed message")

// derErr wraps a decoder failure so that every rejection from this
// package matches ErrMalformed.
//
// Without this, a message that is not DER at all comes back carrying
// only encoding/asn1's own error while a message that is DER of the
// wrong shape carries ErrMalformed -- so a caller distinguishing "the
// peer sent rubbish" from "we could not answer" gets the first case
// wrong. internal/transport answers one with 400 and the other with
// 500, which is where it shows.
func derErr(what string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrMalformed, what, err)
}

// msgTypeErr reports a message whose msg-type is not the one its
// application tag promised.
func msgTypeErr(got, want int32) error {
	return fmt.Errorf("%w: msg-type is %d, want %d",
		ErrMalformed, got, want)
}

// seqnoRangeErr reports a sequence number outside the range upstream
// accepts, which is INT32_MIN to 0xFFFFFFFF -- wider than either a
// signed or an unsigned 32-bit integer alone, because the decoder
// tolerates both encodings (asn1_k_encode.c:140-144).
var seqnoRangeErr = fmt.Errorf(
	"%w: sequence number out of range", ErrMalformed)

// gstring wraps a Go string as a bare DER GeneralString, for the
// elements of a SEQUENCE OF where encoding/asn1 adds no tag of its
// own.
func gstring(s string) asn1.RawValue {
	return asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   tagGeneralString,
		Bytes: []byte(s),
	}
}

// gstrings wraps a slice of strings.
func gstrings(ss []string) []asn1.RawValue {
	out := make([]asn1.RawValue, len(ss))
	for i, s := range ss {
		out[i] = gstring(s)
	}
	return out
}

// gstringValue reads a bare DER GeneralString back.
//
// A GeneralString is in principle an ISO 2022 string with escape
// sequences; upstream treats it as a flat byte copy with no
// validation at all (k5_asn1_encode_bytestring), and so does this.
// Being stricter would reject names that every other implementation
// accepts.
func gstringValue(r asn1.RawValue) (string, error) {
	if r.Class != asn1.ClassUniversal ||
		r.Tag != tagGeneralString {
		return "", fmt.Errorf(
			"%w: want GeneralString, got class %d tag %d",
			ErrMalformed, r.Class, r.Tag)
	}
	return string(r.Bytes), nil
}

// gstringValues reads a sequence of them.
func gstringValues(rs []asn1.RawValue) ([]string, error) {
	out := make([]string, len(rs))
	for i, r := range rs {
		s, err := gstringValue(r)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// ctxGstring builds a GeneralString already wrapped in its own
// constructed context tag, for a field encoding/asn1 will not tag.
func ctxGstring(tag int, s string) asn1.RawValue {
	return ctxWrap(tag, derTLV(tagGeneralString, []byte(s)))
}

// optCtxGstring is ctxGstring for an OPTIONAL field. Upstream's
// opt_gstring_data is guarded by nonempty_data, so a zero-length
// string is omitted rather than written as a GeneralString of no
// octets; the zero RawValue is what encoding/asn1 recognises as the
// field's zero value and skips.
func optCtxGstring(tag int, s string) asn1.RawValue {
	if s == "" {
		return asn1.RawValue{}
	}
	return ctxGstring(tag, s)
}

// ctxGstringValue reads a context-tagged GeneralString.
func ctxGstringValue(r asn1.RawValue) (string, error) {
	var inner asn1.RawValue
	rest, err := asn1.Unmarshal(r.Bytes, &inner)
	if err != nil {
		return "", derErr("GeneralString", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf(
			"%w: %d trailing octets after GeneralString",
			ErrMalformed, len(rest))
	}
	return gstringValue(inner)
}

// optCtxGstringValue reads an OPTIONAL context-tagged GeneralString.
// The second result reports whether the field was on the wire at all,
// which matters in a KRB-ERROR: an absent cname is a different
// statement from an empty one.
func optCtxGstringValue(r asn1.RawValue) (string, bool, error) {
	if r.FullBytes == nil {
		return "", false, nil
	}
	s, err := ctxGstringValue(r)
	return s, err == nil, err
}

// ctxWrap wraps an encoded DER element in a constructed context tag.
//
// Context tag numbers in these messages are all well below 31, so the
// identifier octet is always a single byte; a larger one would need
// multi-byte form and is a programming error here rather than
// something to encode. Both Bytes and FullBytes are filled in, so
// that a RawValue built here is indistinguishable from one
// encoding/asn1 decoded. Setting only FullBytes would marshal
// correctly -- makeField returns those bytes untouched -- and then
// read back as empty through ctxUnwrap, which is how user-to-user's
// second ticket went missing the first time.
func ctxWrap(tag int, body []byte) asn1.RawValue {
	if tag < 0 || tag > 30 {
		panic("wire: context tag out of range")
	}
	id := byte(0xA0 | tag)
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      body,
		FullBytes:  derTLV(id, body),
	}
}

// ctxUnwrap returns the element inside a context tag.
func ctxUnwrap(r asn1.RawValue) []byte { return r.Bytes }

// derTLV builds one DER tag-length-value.
func derTLV(id byte, body []byte) []byte {
	out := append([]byte{id}, derLength(len(body))...)
	return append(out, body...)
}

// derLength encodes a DER length: the short form below 128, otherwise
// a count byte with the high bit set followed by big-endian octets.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var be []byte
	for v := n; v > 0; v >>= 8 {
		be = append([]byte{byte(v)}, be...)
	}
	return append([]byte{byte(0x80 | len(be))}, be...)
}

// kerberosTime normalises a mandatory timestamp for the wire.
//
// Kerberos' GeneralizedTime is exactly "YYYYMMDDhhmmssZ": UTC, and
// whole seconds, with sub-second precision carried in a separate
// integer field when it is carried at all. Truncating here means a
// caller cannot accidentally encode a fractional second, which
// upstream's decoder would refuse.
//
// An unset time becomes the Unix epoch, not Go's year 1. Upstream
// holds timestamps as a 32-bit count of seconds and writes 0 as the
// literal "19700101000000Z", so the epoch is the only thing an unset
// mandatory timestamp can be. Optional fields are a different
// question -- see optTime.
func kerberosTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return t.UTC().Truncate(time.Second)
}

// optTime normalises a timestamp that is OPTIONAL on the wire.
//
// Upstream decides presence from the C value rather than tracking it:
// DEFOPTIONALZEROTYPE omits a field whose integer is 0
// (asn1_encode.h:380), and a krb5_timestamp of 0 is the Unix epoch.
// So upstream cannot express an optional timestamp of exactly the
// epoch, and neither does this: both an unset time and the epoch are
// absent.
//
// It also lines up with encoding/asn1, which omits an optional field
// only when it equals its type's zero value -- time.Time{}, which is
// year 1, not 1970.
func optTime(t time.Time) time.Time {
	if t.IsZero() || t.Unix() == 0 {
		return time.Time{}
	}
	return kerberosTime(t)
}
