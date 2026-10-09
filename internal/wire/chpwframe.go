package wire

import (
	"encoding/binary"
	"fmt"
)

// The password-change protocol's two request versions (schpw.c:17 and
// :73-81).
//
// Version 1 changes the sender's own password and carries it raw. The
// RFC 3244 version carries a ChangePasswdData and can name somebody
// else's. A *reply* is always version 1 whichever was asked for
// (schpw.c:364), which reads as a bug and is not: the reply format
// never differed between them.
const (
	ChangePWVersion1   uint16 = 0x0001
	ChangePWVersionSet uint16 = 0xff80
)

// The result codes a reply carries, from krb5.hin:1877-1887. The
// first five are RFC 3244's predecessor and the last three are
// Microsoft's extensions, which is why the numbering looks like two
// lists joined.
const (
	KPasswdSuccess       uint16 = 0
	KPasswdMalformed     uint16 = 1
	KPasswdHardError     uint16 = 2
	KPasswdAuthError     uint16 = 3
	KPasswdSoftError     uint16 = 4
	KPasswdAccessDenied  uint16 = 5
	KPasswdBadVersion    uint16 = 6
	KPasswdInitialNeeded uint16 = 7
)

// ChangePWFrame is the password-change protocol's envelope, which is
// not ASN.1 at all: six octets of big-endian header and then two
// messages end to end (schpw.c:46-99 reads it, :352-385 writes it).
//
//	0  uint16  the whole frame's length, which must agree
//	2  uint16  the version
//	4  uint16  the AP-REQ's length
//	6  the AP-REQ, then the rest
type ChangePWFrame struct {
	Version uint16

	// APReq is the DER AP-REQ, or empty in a reply that could not
	// be authenticated -- in which case Rest is a KRB-ERROR
	// rather than a KRB-PRIV (schpw.c:311-318).
	APReq []byte

	// Rest is everything after the AP-REQ: a KRB-PRIV, or that
	// KRB-ERROR. The frame says nothing about which, and the
	// AP-REQ's length being zero is the only signal.
	Rest []byte
}

// MarshalChangePWFrame encodes the envelope.
func MarshalChangePWFrame(f ChangePWFrame) ([]byte, error) {
	n := 6 + len(f.APReq) + len(f.Rest)
	if n > 0xFFFF {
		return nil, fmt.Errorf(
			"%w: %d-octet change-password frame",
			ErrMalformed, n)
	}
	out := make([]byte, 6, n)
	binary.BigEndian.PutUint16(out[0:], uint16(n))
	binary.BigEndian.PutUint16(out[2:], f.Version)
	binary.BigEndian.PutUint16(out[4:], uint16(len(f.APReq)))
	out = append(out, f.APReq...)
	return append(out, f.Rest...), nil
}

// UnmarshalChangePWFrame decodes the envelope and checks the three
// things upstream checks: that the frame is long enough, that the
// length field agrees with it, and that the AP-REQ fits inside with
// something left over.
//
// One divergence, and it is a fix rather than a choice. Upstream
// refuses a frame shorter than *four* octets (schpw.c:47) and then
// reads six, so a four-octet frame whose length field says four
// passes the check and the read of the AP-REQ length runs two octets
// past the buffer. Six is the real minimum and is what this requires.
func UnmarshalChangePWFrame(b []byte) (ChangePWFrame, error) {
	if len(b) < 6 {
		return ChangePWFrame{}, fmt.Errorf(
			"%w: %d-octet change-password frame",
			ErrMalformed, len(b))
	}
	n := binary.BigEndian.Uint16(b[0:])
	if int(n) != len(b) {
		return ChangePWFrame{}, fmt.Errorf(
			"%w: change-password frame says %d octets, "+
				"has %d", ErrMalformed, n, len(b))
	}
	alen := int(binary.BigEndian.Uint16(b[4:]))
	// Upstream's bound is 6+alen >= len(b), not >, so a frame
	// whose AP-REQ fills it exactly is truncated: there would be
	// no KRB-PRIV left to read (schpw.c:88).
	if 6+alen >= len(b) {
		return ChangePWFrame{}, fmt.Errorf(
			"%w: change-password AP-REQ of %d octets in "+
				"%d", ErrMalformed, alen, len(b))
	}
	return ChangePWFrame{
		Version: binary.BigEndian.Uint16(b[2:]),
		APReq:   b[6 : 6+alen],
		Rest:    b[6+alen:],
	}, nil
}

// ChangePWResult is a reply's sealed payload: a result code and a
// human-readable string, with no length or terminator between them
// (schpw.c:274-284).
func MarshalChangePWResult(code uint16, text string) []byte {
	out := make([]byte, 2, 2+len(text))
	binary.BigEndian.PutUint16(out, code)
	return append(out, text...)
}

// UnmarshalChangePWResult reads one back.
func UnmarshalChangePWResult(
	b []byte,
) (uint16, string, error) {
	if len(b) < 2 {
		return 0, "", fmt.Errorf(
			"%w: %d-octet change-password result",
			ErrMalformed, len(b))
	}
	return binary.BigEndian.Uint16(b), string(b[2:]), nil
}
