// Package keytab reads and writes MIT's keytab file format.
//
// It exists because a keytab is the one thing a realm has to hand a
// *service*, and there is no database-shaped substitute for it. An
// administrator can be given credentials for Postgres and provision
// principals that way, which is why a kadmin protocol can wait; a
// service reads a file in this format with its own Kerberos library
// and nothing else will do. A realm that cannot produce one has users
// and no services.
//
// The format is lib/krb5/keytab/kt_file.c, and everything here is
// version 2 (0x0502). Version 1 (0x0501) differs in three ways --
// host byte order throughout, no name-type field, and a component
// count that includes the realm -- and is DCE compatibility nothing
// has written for decades. Reading one is refused rather than guessed
// at.
package keytab

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The two version numbers (kt_file.c:70-71).
const (
	version2 = 0x0502
	version1 = 0x0501
)

// ErrMalformed reports a file this package cannot read.
var ErrMalformed = errors.New("malformed keytab")

// Entry is one key in a keytab.
type Entry struct {
	Realm      string
	Components []string

	// NameType is the principal's name type, which this version
	// of the format carries and version 1 did not.
	NameType int32

	// Timestamp is when the entry was written. Upstream fills it
	// in from the clock at write time and nothing reads it.
	Timestamp time.Time

	KVNO    int32
	EncType int32
	Key     []byte
}

// Marshal writes a whole keytab.
//
// Entries are appended in order with no holes. Upstream can leave one
// behind -- a deleted entry is marked by writing the *negative* of
// its length over the length field, and its reader skips those
// (kt_file.c:1016-1026) -- but nothing here deletes, so nothing here
// writes one.
func Marshal(entries []Entry) ([]byte, error) {
	out := []byte{version2 >> 8, version2 & 0xFF}
	for _, e := range entries {
		body, err := e.marshal()
		if err != nil {
			return nil, err
		}
		out = binary.BigEndian.AppendUint32(out,
			uint32(len(body)))
		out = append(out, body...)
	}
	return out, nil
}

// marshal writes one entry's body, which is everything the length
// field in front of it counts.
func (e Entry) marshal() ([]byte, error) {
	if len(e.Components) == 0 || e.Realm == "" ||
		len(e.Key) == 0 {
		return nil, fmt.Errorf(
			"%w: entry with no name, realm or key",
			ErrMalformed)
	}
	var b []byte
	b = binary.BigEndian.AppendUint16(b,
		uint16(len(e.Components)))
	b = appendCounted(b, e.Realm)
	for _, c := range e.Components {
		b = appendCounted(b, c)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(e.NameType))
	b = binary.BigEndian.AppendUint32(b,
		uint32(e.Timestamp.Unix()))
	// The key version goes in twice -- see Unmarshal.
	b = append(b, byte(e.KVNO))
	b = binary.BigEndian.AppendUint16(b, uint16(e.EncType))
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.Key)))
	b = append(b, e.Key...)
	return binary.BigEndian.AppendUint32(b, uint32(e.KVNO)), nil
}

func appendCounted(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// Unmarshal reads a whole keytab.
//
// The key version number is the trap in this format, and upstream
// documents it twice. The field is a single octet, which cannot hold
// a modern version, so a 32-bit copy is appended after the key and
// read back only when four or more octets of the entry remain
// (kt_file.c:1084-1095) -- a zero there meaning "no extension, just
// padding". Upstream's own size calculation always makes room for it
// (krb5_ktfileint_size_entry), so anything it writes has one; but a
// reader has to cope with both, and a writer that emitted only the
// octet would produce a file that worked until a principal passed
// version 255 and then silently selected the wrong key.
//
// There is a second-order consequence upstream guards against with a
// heuristic: "If a small kvno was written at the same time or later
// than a large kvno, the kvno probably wrapped" (:261-265), naming
// three separate historical 8-bit limits as the cause. Nothing here
// needs it, because nothing here writes a bare octet, and it is not
// ported.
func Unmarshal(b []byte) ([]Entry, error) {
	rest, err := checkVersion(b)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for len(rest) > 0 {
		e, next, done, err := readEntry(rest)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		if e != nil {
			out = append(out, *e)
		}
		rest = next
	}
	return out, nil
}

// checkVersion reads the two-octet header.
func checkVersion(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf(
			"%w: %d octets", ErrMalformed, len(b))
	}
	switch vno := int(b[0])<<8 | int(b[1]); vno {
	case version2:
		return b[2:], nil
	case version1:
		return nil, fmt.Errorf(
			"%w: version 1 keytabs are not read",
			ErrMalformed)
	default:
		return nil, fmt.Errorf("%w: version %#x",
			ErrMalformed, vno)
	}
}

// readEntry reads one length-prefixed record. A nil entry with no
// error is a hole; done reports the zero length upstream treats as
// the end of the file (kt_file.c:1029-1031).
func readEntry(
	b []byte,
) (e *Entry, rest []byte, done bool, err error) {
	if len(b) < 4 {
		return nil, nil, false, fmt.Errorf(
			"%w: %d octets before an entry",
			ErrMalformed, len(b))
	}
	size := int32(binary.BigEndian.Uint32(b))
	b = b[4:]
	hole := size < 0
	if hole {
		// A negative length marks a deleted entry and its
		// magnitude is how far to skip. INT32_MIN inverts to
		// itself, which upstream refuses outright
		// (:1017-1018) rather than looping forever.
		if size == -size {
			return nil, nil, false, fmt.Errorf(
				"%w: unskippable hole", ErrMalformed)
		}
		size = -size
	} else if size == 0 {
		return nil, nil, true, nil
	}
	if int(size) > len(b) {
		return nil, nil, false, fmt.Errorf(
			"%w: entry of %d octets with %d left",
			ErrMalformed, size, len(b))
	}
	if hole {
		return nil, b[size:], false, nil
	}
	parsed, err := parseEntry(b[:size])
	if err != nil {
		return nil, nil, false, err
	}
	return parsed, b[size:], false, nil
}
