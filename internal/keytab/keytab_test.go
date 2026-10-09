package keytab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// A keytab this package wrote reads back as what went in. There is no
// published reference encoding for this format -- it is not ASN.1 and
// upstream's test programs do not emit one -- so the real anchor is a
// stock kinit -k consuming a file written here, which internal/golden
// does. This is the shape check underneath it.
func TestRoundTrip(t *testing.T) {
	in := []Entry{
		{
			Realm:      "KDIAMOND.TEST",
			Components: []string{"host", "a.test"},
			NameType:   3,
			Timestamp:  time.Unix(1700000000, 0).UTC(),
			KVNO:       2,
			EncType:    18,
			Key:        bytes.Repeat([]byte{0xAB}, 32),
		},
		{
			Realm:      "KDIAMOND.TEST",
			Components: []string{"host", "a.test"},
			NameType:   3,
			Timestamp:  time.Unix(1700000001, 0).UTC(),
			KVNO:       2,
			EncType:    17,
			Key:        bytes.Repeat([]byte{0xCD}, 16),
		},
	}
	out, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != 0x05 || out[1] != 0x02 {
		t.Errorf("version is %#x %#x, want 05 02",
			out[0], out[1])
	}
	got, err := Unmarshal(out)
	if err != nil {
		t.Fatal(err)
	}
	assertEntries(t, got, in)
}

// A principal's name type, realm and every component survive, and so
// does the order of entries: a service with two enctypes has two
// entries and a client picks between them.
func assertEntries(t *testing.T, got, want []Entry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d entries, want %d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Realm != w.Realm || g.NameType != w.NameType ||
			g.KVNO != w.KVNO || g.EncType != w.EncType {
			t.Errorf("entry %d is %+v, want %+v", i, g, w)
		}
		if !bytes.Equal(g.Key, w.Key) {
			t.Errorf("entry %d key %x", i, g.Key)
		}
		if len(g.Components) != len(w.Components) {
			t.Errorf("entry %d names %v", i, g.Components)
			continue
		}
		for j := range w.Components {
			if g.Components[j] != w.Components[j] {
				t.Errorf("entry %d part %d is %q",
					i, j, g.Components[j])
			}
		}
		if !g.Timestamp.Equal(w.Timestamp) {
			t.Errorf("entry %d time %v", i, g.Timestamp)
		}
	}
}

// The key version is written twice -- a single octet and then a
// 32-bit copy after the key -- and the wide one is what a reader must
// believe. This is the trap the format carries and the reason
// upstream has a wraparound heuristic at all: a file with only the
// octet works until a principal passes 255.
func TestTheWideKeyVersionWins(t *testing.T) {
	in := []Entry{{
		Realm:      "KDIAMOND.TEST",
		Components: []string{"host", "a"},
		NameType:   3,
		KVNO:       300,
		EncType:    18,
		Key:        bytes.Repeat([]byte{1}, 32),
	}}
	out, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].KVNO != 300 {
		t.Errorf("kvno is %d, want 300", got[0].KVNO)
	}
	// And the octet really did wrap, which is what makes the wide
	// copy necessary rather than decorative: 300 & 0xFF is 44,
	// and a reader that trusted the octet would pick the wrong
	// key.
	narrow := len(out) - 4 - 32 - 2 - 2 - 1
	if last := out[narrow]; last != 44 {
		t.Errorf("the narrow kvno is %d, want 44", last)
	}
}

// A zero in the wide field means "no extension, just padding", and
// then the octet is the whole of the version (kt_file.c:1091-1094).
// Upstream always writes a non-zero one when the version is non-zero,
// so this is a file some other writer produced.
func TestAZeroWideVersionLeavesTheOctet(t *testing.T) {
	out, err := Marshal([]Entry{{
		Realm:      "KDIAMOND.TEST",
		Components: []string{"host", "a"},
		NameType:   3,
		KVNO:       7,
		EncType:    18,
		Key:        bytes.Repeat([]byte{1}, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Zero the trailing wide copy, leaving the octet at 7.
	for i := len(out) - 4; i < len(out); i++ {
		out[i] = 0
	}
	got, err := Unmarshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].KVNO != 7 {
		t.Errorf("kvno is %d, want 7", got[0].KVNO)
	}
}

// A deleted entry is a hole, marked by the *negative* of its length
// written over the length field, and a reader skips it
// (kt_file.c:1016-1026). Nothing here writes one, so the case has to
// be built by hand -- and it has to be read, because a file any
// kadmin has ever removed a key from contains one.
func TestAHoleIsSkipped(t *testing.T) {
	good := Entry{
		Realm:      "KDIAMOND.TEST",
		Components: []string{"host", "a"},
		NameType:   3,
		KVNO:       1,
		EncType:    18,
		Key:        bytes.Repeat([]byte{2}, 32),
	}
	out, err := Marshal([]Entry{good, good})
	if err != nil {
		t.Fatal(err)
	}
	// Negate the first entry's length in place.
	size := int32(binary.BigEndian.Uint32(out[2:]))
	binary.BigEndian.PutUint32(out[2:], uint32(-size))

	got, err := Unmarshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d entries survived a hole, want 1",
			len(got))
	}
	if got[0].KVNO != 1 {
		t.Errorf("the wrong entry survived: %+v", got[0])
	}
}

// Version 1 is refused rather than guessed at. It is host byte order
// throughout with no name-type field and a component count that
// includes the realm, so reading it as version 2 would produce
// plausible nonsense.
func TestVersionOneIsRefused(t *testing.T) {
	_, err := Unmarshal([]byte{0x05, 0x01, 0, 0, 0, 0})
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("got %v, want ErrMalformed", err)
	}
}

// Everything a truncated or nonsensical file can be. Each is reported
// rather than producing a partial entry, because a keytab is read by
// a service at start-up and a half-read one would fail much later as
// an authentication error.
func TestMalformedFiles(t *testing.T) {
	for _, c := range []struct {
		why string
		in  []byte
	}{
		{"empty", nil},
		{"one octet", []byte{0x05}},
		{"an unknown version", []byte{0x06, 0x02}},
		{"a truncated length", []byte{0x05, 0x02, 0, 0}},
		{"a length past the end",
			[]byte{0x05, 0x02, 0, 0, 0xFF, 0xFF, 1, 2}},
		{"an unskippable hole", []byte{
			0x05, 0x02, 0x80, 0, 0, 0, 1, 2, 3, 4}},
	} {
		t.Run(c.why, func(t *testing.T) {
			if _, err := Unmarshal(c.in); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// An entry with nothing in it is refused at write time too, because
// the format cannot express it: a zero-length realm or component is
// what upstream's reader treats as the end of the file.
func TestEmptyEntriesAreRefused(t *testing.T) {
	for _, e := range []Entry{
		{Realm: "R", Key: []byte{1}},
		{Components: []string{"host"}, Key: []byte{1}},
		{Realm: "R", Components: []string{"host"}},
	} {
		if _, err := Marshal([]Entry{e}); err == nil {
			t.Errorf("%+v was accepted", e)
		}
	}
}
