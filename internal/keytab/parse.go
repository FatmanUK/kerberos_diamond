package keytab

import (
	"encoding/binary"
	"fmt"
	"time"
)

// parseEntry reads one entry's body.
func parseEntry(b []byte) (*Entry, error) {
	r := &reader{b: b}
	count := int(r.uint16())
	if count <= 0 {
		return nil, r.fail("component count %d", count)
	}
	e := &Entry{Realm: r.counted()}
	for i := 0; i < count; i++ {
		e.Components = append(e.Components, r.counted())
	}
	e.NameType = int32(r.uint32())
	e.Timestamp = time.Unix(int64(r.uint32()), 0).UTC()
	kvno := int32(r.uint8())
	e.EncType = int32(r.uint16())
	e.Key = r.bytes(int(r.uint16()))
	// The 32-bit key version, read only when four or more octets
	// of this entry remain, and ignored when it is zero -- then
	// the octet above is the whole of it.
	if len(r.b) >= 4 {
		if wide := int32(r.uint32()); wide != 0 {
			kvno = wide
		}
	}
	e.KVNO = kvno
	if r.err != nil {
		return nil, r.err
	}
	return e, nil
}

// reader walks an entry's body, remembering the first fault rather
// than returning one from every step.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(f string, a ...any) error {
	if r.err == nil {
		r.err = fmt.Errorf("%w: "+f,
			append([]any{ErrMalformed}, a...)...)
	}
	return r.err
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.fail("wanted %d octets, had %d", n, len(r.b))
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) uint8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) uint16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *reader) uint32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// counted reads a uint16-prefixed string. A zero length is refused,
// as upstream refuses it for a realm and for every component
// (kt_file.c:1037-1040 and :1061-1064).
func (r *reader) counted() string {
	n := int(r.uint16())
	if r.err == nil && n == 0 {
		r.fail("zero-length name component")
		return ""
	}
	return string(r.bytes(n))
}
