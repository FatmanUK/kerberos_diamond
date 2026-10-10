package pac

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// ClientInfo is the one buffer this package builds from scratch
// rather than passing through: a timestamp and the client's name
// (insert_client_info, pac_sign.c:33-96).
//
// Three things in ten octets plus a name, and each is in a different
// world's conventions. The timestamp is an **NT time** -- tenths of a
// microsecond since 1601 -- little-endian in 64 bits. The length is
// the name's length in **octets of UTF-16**, not characters, so it is
// always even. And the name is UTF-16LE with **no terminating NUL**,
// which is the detail a reimplementation adds by habit.
type ClientInfo struct {
	AuthTime time.Time
	Name     string
}

// SetClientInfo adds the CLIENT_INFO buffer, or *validates* the one
// already there.
//
// Validating rather than rebuilding is upstream's behaviour
// (pac_sign.c:47-52) and it is what makes the plain TGS copy path
// work: a PAC arriving in a presented ticket already has a
// CLIENT_INFO naming the client, and re-issuing the ticket must not
// quietly replace it with a different name. So a mismatch is an
// error, which upstream reports as KRB5KRB_AP_WRONG_PRINC.
func (p *PAC) SetClientInfo(ci ClientInfo) error {
	if _, err := p.locate(TypeClientInfo); err == nil {
		return p.VerifyClientInfo(ci)
	}
	name := utf16le(ci.Name)
	span, err := p.add(TypeClientInfo,
		clientInfoHdr+len(name))
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(span, ntTime(ci.AuthTime))
	binary.LittleEndian.PutUint16(span[8:], uint16(len(name)))
	copy(span[clientInfoHdr:], name)
	return nil
}

// ClientInfo reads the buffer back (krb5_pac_get_client_info,
// pac.c:359-406).
func (p *PAC) ClientInfo() (ClientInfo, error) {
	raw, err := p.Get(TypeClientInfo)
	if err != nil {
		return ClientInfo{}, err
	}
	if len(raw) < clientInfoHdr {
		return ClientInfo{}, fmt.Errorf(
			"%w: client info is %d octets",
			ErrMalformed, len(raw))
	}
	n := int(binary.LittleEndian.Uint16(raw[8:]))
	// An odd length is refused outright rather than rounded,
	// because UTF-16 has no odd length and half a code unit means
	// the buffer was built by something that did not know that
	// (:393-395).
	if n%2 != 0 || len(raw) < clientInfoHdr+n {
		return ClientInfo{}, fmt.Errorf(
			"%w: a %d-octet name in %d octets",
			ErrMalformed, n, len(raw))
	}
	at, err := unNTTime(binary.LittleEndian.Uint64(raw))
	if err != nil {
		return ClientInfo{}, err
	}
	name := raw[clientInfoHdr : clientInfoHdr+n]
	return ClientInfo{AuthTime: at,
		Name: fromUTF16le(name)}, nil
}

// VerifyClientInfo checks the buffer against what the ticket says
// (k5_pac_validate_client, pac.c:408-437).
//
// Both halves have to match: a PAC whose name agrees and whose
// authtime does not was issued in a different ticket, which is
// exactly what lifting a PAC out of one ticket and into another
// produces.
func (p *PAC) VerifyClientInfo(want ClientInfo) error {
	got, err := p.ClientInfo()
	if err != nil {
		return err
	}
	if !got.AuthTime.Equal(want.AuthTime) ||
		got.Name != want.Name {
		return fmt.Errorf(
			"%w: client info is %q at %v, want %q at %v",
			ErrModified, got.Name, got.AuthTime,
			want.Name, want.AuthTime)
	}
	return nil
}

// ntTime converts a Unix time to Microsoft's
// (k5_seconds_since_1970_to_time, pac.c:350-357).
//
// Upstream truncates the seconds to 32 bits first, deliberately, so
// the conversion is exactly reversible for every timestamp a Kerberos
// ticket can carry.
func ntTime(t time.Time) uint64 {
	return (uint64(uint32(t.Unix())) + ntEpoch) * 10000000
}

// unNTTime is the other direction (k5_time_to_seconds_since_1970,
// pac.c:338-348).
//
// A value that does not land inside a uint32 of Unix seconds is
// refused rather than wrapped: upstream answers ERANGE, and a wrapped
// authtime would make VerifyClientInfo compare the wrong moment.
func unNTTime(nt uint64) (time.Time, error) {
	secs := nt/10000000 - ntEpoch
	if secs > 0xFFFFFFFF {
		return time.Time{}, fmt.Errorf(
			"%w: NT time %d is out of range",
			ErrMalformed, nt)
	}
	return time.Unix(int64(secs), 0).UTC(), nil
}

// utf16le encodes a string the way the buffer wants it: code units
// little-endian, no NUL.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

// fromUTF16le reverses it.
func fromUTF16le(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(units))
}
