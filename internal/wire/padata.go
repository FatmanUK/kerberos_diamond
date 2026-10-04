package wire

import (
	"encoding/asn1"
	"time"
)

// PAEncTSEnc is the plaintext of a PA-ENC-TIMESTAMP: the client's
// clock, encrypted under its long-term key with key usage 1. Proving
// knowledge of the key is the whole of the preauth.
type PAEncTSEnc struct {
	PATimestamp time.Time

	// PAUSec is absent when zero, so the microsecond field cannot
	// distinguish "zero" from "not sent"
	// (asn1_k_encode.c:934-935).
	PAUSec int32
}

type derPAEncTSEnc struct {
	Stamp time.Time `asn1:"explicit,generalized,tag:0"`
	USec  int32     `asn1:"explicit,optional,tag:1"`
}

// MarshalPAEncTSEnc encodes a PA-ENC-TS-ENC.
func MarshalPAEncTSEnc(p PAEncTSEnc) ([]byte, error) {
	return asn1.Marshal(derPAEncTSEnc{
		Stamp: kerberosTime(p.PATimestamp),
		USec:  p.PAUSec,
	})
}

// UnmarshalPAEncTSEnc decodes a PA-ENC-TS-ENC.
func UnmarshalPAEncTSEnc(b []byte) (PAEncTSEnc, error) {
	var d derPAEncTSEnc
	if _, err := asn1.Unmarshal(b, &d); err != nil {
		return PAEncTSEnc{}, derErr("PA-ENC-TS-ENC", err)
	}
	return PAEncTSEnc{
		PATimestamp: d.Stamp,
		PAUSec:      d.USec,
	}, nil
}

// ETypeInfo2Entry tells a client which enctype and salt to run
// string-to-key with. It is what makes the preauth round trip
// possible: without it the client would have to guess the salt.
type ETypeInfo2Entry struct {
	EType int32

	// Salt is a pointer because absent and empty are different
	// here. Upstream's presence predicate is length !=
	// KRB5_ETYPE_NO_SALT, which is -1, so a zero-length salt is
	// *present* (asn1_k_encode.c:598-622) -- the one place in
	// this package where empty does not mean absent.
	Salt *string

	// S2KParams carries the PBKDF2 iteration count for the AES
	// enctypes, and is absent when the default of 4096 applies.
	S2KParams []byte
}

type derETypeInfo2Entry struct {
	EType     int32         `asn1:"explicit,tag:0"`
	Salt      asn1.RawValue `asn1:"explicit,optional,tag:1"`
	S2KParams []byte        `asn1:"explicit,optional,tag:2"`
}

// MarshalETypeInfo2 encodes a PA-ETYPE-INFO2 sequence. It is a bare
// SEQUENCE OF with no application tag, carried as a PA-DATA value.
func MarshalETypeInfo2(es []ETypeInfo2Entry) ([]byte, error) {
	ds := make([]derETypeInfo2Entry, len(es))
	for i, e := range es {
		ds[i] = derETypeInfo2Entry{
			EType:     e.EType,
			S2KParams: e.S2KParams,
		}
		if e.Salt != nil {
			ds[i].Salt = ctxGstring(1, *e.Salt)
		}
	}
	return asn1.Marshal(ds)
}

// UnmarshalETypeInfo2 decodes a PA-ETYPE-INFO2 sequence.
func UnmarshalETypeInfo2(b []byte) ([]ETypeInfo2Entry, error) {
	var ds []derETypeInfo2Entry
	if _, err := asn1.Unmarshal(b, &ds); err != nil {
		return nil, derErr("PA-ETYPE-INFO2", err)
	}
	out := make([]ETypeInfo2Entry, len(ds))
	for i, d := range ds {
		salt, ok, err := optCtxGstringValue(d.Salt)
		if err != nil {
			return nil, err
		}
		out[i] = ETypeInfo2Entry{
			EType:     d.EType,
			S2KParams: d.S2KParams,
		}
		if ok {
			out[i].Salt = &salt
		}
	}
	return out, nil
}
