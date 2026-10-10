package ndr

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(
		strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return b
}

// Decoding a buffer Active Directory produced and re-encoding it
// reproduces the octets, which is upstream's own test
// (t_ndr.c:165-171) and is the whole anchor for this package.
//
// It has to be the anchor rather than a round trip against itself,
// because the layout is not derivable from the specification: an
// RPC_UNICODE_STRING's length fields move depending on where the
// string sits in the struct, and neither implementation decodes that
// generically. What both read and write is the exact shape Windows
// emits, and only Windows' bytes can say whether they do.
func TestTheADBuffersRoundTrip(t *testing.T) {
	for _, c := range adBuffers() {
		t.Run(c.why, func(t *testing.T) {
			in := hx(t, c.blob)
			di, err := Unmarshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if di.ProxyTarget != c.target {
				t.Errorf("target %q, want %q",
					di.ProxyTarget, c.target)
			}
			assertServices(t, di, c.through)
			out, err := Marshal(di)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, in) {
				t.Errorf("re-encoded to\n % X\n"+
					"want\n % X", out, in)
			}
		})
	}
}

type adBuffer struct {
	why     string
	blob    string
	target  string
	through []string
}

// adBuffers is the table of captured buffers and what each decodes
// to.
func adBuffers() []adBuffer {
	const svc1 = "svc1/adserver.ad.test@AD.TEST"
	const svc2 = "svc2/adserver.ad.test@AD.TEST"
	return []adBuffer{
		{"one transited service", refDIShort,
			"svc2/adserver.ad.test", []string{svc1}},
		// An odd number of characters, so the string is
		// padded to a multiple of four -- which is the branch
		// in wcharPointer and the one place a length is not
		// simply twice a count.
		{"an odd-length target", refDILong,
			"longsvc/adserver.ad.test",
			[]string{svc1}},
		{"two transited services", refDIDouble,
			"longsvc/adserver.ad.test",
			[]string{svc1, svc2}},
	}
}

func assertServices(
	t *testing.T,
	di DelegationInfo,
	want []string,
) {
	t.Helper()
	if len(di.TransitedServices) != len(want) {
		t.Fatalf("%d transited services: %v",
			len(di.TransitedServices),
			di.TransitedServices)
	}
	for i := range want {
		if di.TransitedServices[i] != want[i] {
			t.Errorf("service %d is %q, want %q", i,
				di.TransitedServices[i], want[i])
		}
	}
}

// **The target carries no realm and the transited services do**,
// which is visible in the captured bytes above and is the asymmetry a
// reimplementation would tidy away (update_delegation_info,
// kdc_authdata.c:412-427).
//
// It is not arbitrary. The proxy target is a service in the realm
// issuing the ticket, so its realm is implied; a transited service
// may be in another realm, and the chain is only meaningful if each
// hop says where it was.
func TestTheRealmAsymmetryIsReal(t *testing.T) {
	di, err := Unmarshal(hx(t, refDIShort))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(di.ProxyTarget, "@") {
		t.Errorf("the target carries a realm: %q",
			di.ProxyTarget)
	}
	if !strings.Contains(di.TransitedServices[0], "@") {
		t.Errorf("a transited service carries none: %q",
			di.TransitedServices[0])
	}
}

// The two fuzzing blobs are refused (t_ndr.c:118-128), and so are the
// degenerate inputs around them.
//
// The checks that catch them are the two headers and the payload
// length, which is why those are checked at all: everything else in
// the fixed part is a pointer with no meaning or a length redundant
// with a count, and a decoder that validated none of it would read a
// corrupt buffer as an empty one.
func TestMalformedBuffersAreRefused(t *testing.T) {
	for _, c := range []struct {
		why  string
		blob string
	}{
		{"upstream's first fuzz case", refDIFuzz1},
		{"upstream's second fuzz case", refDIFuzz2},
		{"nothing at all", ""},
		{"a header alone",
			"01 10 08 00 CC CC CC CC 00 00 00 00 " +
				"00 00 00 00"},
		{"the wrong version",
			"02 10 08 00 CC CC CC CC 00 00 00 00 " +
				"00 00 00 00"},
		{"big-endian",
			"01 00 08 00 CC CC CC CC 00 00 00 00 " +
				"00 00 00 00"},
	} {
		if _, err := Unmarshal(hx(t, c.blob)); err == nil {
			t.Errorf("%s parsed", c.why)
		}
	}
}

// A buffer this package built is one it can read back, which is the
// weaker check the published blobs make unnecessary -- except for
// shapes they do not cover: no transited services at all, which is
// what a first delegation hop starts from.
func TestAnEmptyChainRoundTrips(t *testing.T) {
	in := DelegationInfo{ProxyTarget: "host/a.b"}
	der, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(der)%8 != 0 {
		t.Errorf("not padded to eight: %d octets", len(der))
	}
	back, err := Unmarshal(der)
	if err != nil {
		t.Fatal(err)
	}
	if back.ProxyTarget != in.ProxyTarget ||
		len(back.TransitedServices) != 0 {
		t.Errorf("round trip changed it: %+v", back)
	}
}
