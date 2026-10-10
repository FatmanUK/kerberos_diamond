package pac

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// hx decodes one of the fixtures, which are written with spaces the
// way internal/wire's reference encodings are.
func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(
		strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex in a fixture: %v", err)
	}
	return b
}

// The Windows 2003 PAC parses, and its table is what the C says it
// is: four buffers in the order LOGON_INFO, CLIENT_INFO, server
// checksum, privsvr checksum, with the logon info at the length
// t_pac.c:86 names.
//
// Its checksums cannot be verified here, and that is recorded rather
// than worked around: both of its keys are arcfour-hmac, which is
// ETYPE_DEPRECATED upstream and a declared non-goal. What it anchors
// is the framing and the CLIENT_INFO buffer, against bytes a Windows
// domain controller produced.
func TestTheWindows2003PACParses(t *testing.T) {
	p, err := Parse(hx(t, refSavedPAC))
	if err != nil {
		t.Fatal(err)
	}
	want := []uint32{TypeLogonInfo, TypeClientInfo,
		TypeServerChecksum, TypePrivsvrChecksum}
	if got := p.Types(); !equal(got, want) {
		t.Errorf("buffers %v, want %v", got, want)
	}
	logon, err := p.Get(TypeLogonInfo)
	if err != nil {
		t.Fatal(err)
	}
	if len(logon) != refSavedPACType1Len {
		t.Errorf("logon info is %d octets, want %d",
			len(logon), refSavedPACType1Len)
	}
	ci, err := p.ClientInfo()
	if err != nil {
		t.Fatal(err)
	}
	if ci.Name != refSavedPACClient {
		t.Errorf("client is %q, want %q",
			ci.Name, refSavedPACClient)
	}
	if got := ci.AuthTime.Unix(); got != refSavedPACAuthTime {
		t.Errorf("authtime is %d, want %d",
			got, refSavedPACAuthTime)
	}
}

// Re-encoding what was parsed gives the same octets back, which is
// the check that nothing in the table was silently narrowed on the
// way in -- the offsets are 64-bit on the wire and this package keeps
// them that way.
func TestTheHeaderRoundTrips(t *testing.T) {
	in := hx(t, refSavedPAC)
	p, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.encodeHeader(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Bytes(), in) {
		t.Error("re-encoding the header changed the PAC")
	}
}

// The two blobs from upstream's fuzzing corpus are refused
// (t_pac.c:434-442). Each is refused for two independent reasons --
// an absurd buffer count and a length that could not hold it -- so a
// parser checking only one of them would still pass, which is why the
// error is required to be ErrMalformed rather than merely non-nil.
func TestTheFuzzBlobsAreRefused(t *testing.T) {
	for _, s := range []string{refFuzz1, refFuzz2} {
		if _, err := Parse(hx(t, s)); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
	// And the degenerate inputs around them: nothing at all, a
	// header with no buffers (upstream's lower bound is **one**,
	// not zero), and a non-zero version.
	for _, c := range []struct {
		why string
		in  string
	}{
		{"empty", ""},
		{"a header alone", "00 00 00 00 00 00 00 00"},
		{"no buffers", "00 00 00 00 00 00 00 00"},
		{"version 1", "01 00 00 00 01 00 00 00"},
	} {
		if _, err := Parse(hx(t, c.in)); err == nil {
			t.Errorf("%s parsed", c.why)
		}
	}
}

// Add grows the format from the middle, which is the one piece of
// arithmetic here that is easy to get wrong: every existing payload
// moves sixteen octets later and every recorded offset moves with it.
//
// Three buffers of awkward lengths, then each read back: if an offset
// were bumped wrongly the contents would come back shifted, and if
// the padding were counted into the size they would come back long.
func TestAddMovesEveryExistingBuffer(t *testing.T) {
	p := New()
	payloads := map[uint32][]byte{
		TypeLogonInfo:      []byte("one"),
		TypeUPNDNSInfo:     bytes.Repeat([]byte{0xAB}, 16),
		TypeAttributesInfo: []byte("a nine..."),
	}
	for _, typ := range []uint32{TypeLogonInfo,
		TypeUPNDNSInfo, TypeAttributesInfo} {
		if err := p.Add(typ, payloads[typ]); err != nil {
			t.Fatal(err)
		}
	}
	for typ, want := range payloads {
		got, err := p.Get(typ)
		if err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("type %d: got %q, want %q",
				typ, got, want)
		}
	}
	// Every offset is eight-aligned and inside the data, which
	// the parser would also insist on -- so what was built here
	// parses.
	if err := p.encodeHeader(); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(p.Bytes()); err != nil {
		t.Errorf("what Add built does not parse: %v", err)
	}
}

// A duplicate type is refused, which upstream reports as EEXIST
// (pac.c:51-52), and a PAC carrying two of one type does not parse
// its way to an answer either -- locate refuses rather than picking
// the first, because a PAC with two server checksums has no answer to
// which one is the server checksum.
func TestADuplicateTypeIsRefused(t *testing.T) {
	p := New()
	if err := p.Add(TypeLogonInfo, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(TypeLogonInfo, []byte("y")); err == nil {
		t.Error("a second buffer of one type was accepted")
	}
}

// The NT timestamp converts both ways for every moment a ticket can
// carry, and the conversion is exactly reversible because upstream
// truncates the seconds to 32 bits on the way in
// (k5_seconds_since_1970_to_time, pac.c:350-357).
func TestNTTimeRoundTrips(t *testing.T) {
	for _, secs := range []int64{
		0, 1, 1120440609, 1538430362, 0xFFFFFFFF,
	} {
		in := time.Unix(secs, 0).UTC()
		back, err := unNTTime(ntTime(in))
		if err != nil {
			t.Fatalf("%v: %v", in, err)
		}
		if !back.Equal(in) {
			t.Errorf("%v came back as %v", in, back)
		}
	}
}

// equal compares two type lists, which is all the comparison the
// tests here need.
func equal(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
