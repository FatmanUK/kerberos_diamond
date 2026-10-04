package wire

import (
	"bytes"
	"encoding/asn1"
	"testing"
	"time"
)

// Bit 0 is the most significant bit of the first octet, so a flag's
// numeric value is 1 << (31 - bit). Asserting the numbers directly is
// the only way to catch a transposition: every value below is a valid
// 32-bit integer, so nothing else would complain.
func TestFlagBitPositions(t *testing.T) {
	cases := []struct {
		name string
		flag Flags
		want uint32
	}{
		{"Forwardable bit 1", FlagForwardable, 0x40000000},
		{"Renewable bit 8", FlagRenewable, 0x00800000},
		{"Initial bit 9", FlagInitial, 0x00400000},
		{"PreAuthent bit 10", FlagPreAuthent, 0x00200000},
		{"OKAsDelegate bit 13", FlagOKAsDelegate, 0x00040000},
		{"EncPARep bit 15", FlagEncPARep, 0x00010000},
		{"Anonymous bit 16", FlagAnonymous, 0x00008000},
		{"Canonicalize bit 15", OptCanonicalize, 0x00010000},
		{"RequestAnon bit 16", OptRequestAnon, 0x00008000},
		{"RenewableOK bit 27", OptRenewableOK, 0x00000010},
		{"Renew bit 30", OptRenew, 0x00000002},
		{"Validate bit 31", OptValidate, 0x00000001},
	}
	for _, tc := range cases {
		if uint32(tc.flag) != tc.want {
			t.Errorf("%s is %08X, want %08X",
				tc.name, uint32(tc.flag), tc.want)
		}
	}
}

// A flags value of zero is five content octets, not one: upstream
// writes an unused-bits byte of zero followed by the whole 32-bit
// word, never trimming to the highest set bit.
func TestFlagsAreAlwaysThirtyTwoBits(t *testing.T) {
	b, err := asn1.Marshal(Flags(0).bitString())
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x03, 0x05, 0x00, 0, 0, 0, 0}
	if !bytes.Equal(b, want) {
		t.Errorf("got % X, want % X", b, want)
	}
}

// A peer that trims its BIT STRING is accepted, with the missing
// low-order bits read as zero. Upstream copies up to four octets from
// the most significant end and zero-extends, so rejecting a short one
// would be stricter than the C.
func TestShortFlagsAreZeroExtended(t *testing.T) {
	got, err := flagsFromBitString(asn1.BitString{
		Bytes:     []byte{0xFE},
		BitLength: 8,
	})
	if err != nil {
		t.Fatalf("short BIT STRING rejected: %v", err)
	}
	if got != 0xFE000000 {
		t.Errorf("got %08X, want FE000000", uint32(got))
	}
}

func TestOverlongFlagsAreRejected(t *testing.T) {
	_, err := flagsFromBitString(asn1.BitString{
		Bytes:     []byte{1, 2, 3, 4, 5},
		BitLength: 40,
	})
	if err == nil {
		t.Error("accepted a 5-octet KerberosFlags")
	}
}

// An unset mandatory timestamp is the Unix epoch, which upstream
// writes as the literal "19700101000000Z". Go's zero time is year 1,
// and encoding it would produce a date no C peer parses.
func TestUnsetMandatoryTimeIsTheEpoch(t *testing.T) {
	got := kerberosTime(time.Time{})
	if got.Unix() != 0 {
		t.Errorf("got %v, want the Unix epoch", got)
	}
	b, err := asn1.MarshalWithParams(got, "generalized")
	if err != nil {
		t.Fatal(err)
	}
	if want := "19700101000000Z"; string(b[2:]) != want {
		t.Errorf("encoded %q, want %q", b[2:], want)
	}
}

// An optional timestamp of exactly the epoch is absent, because
// upstream cannot tell it from unset: its predicate is value != 0 on
// a count of seconds since 1970.
func TestOptionalEpochTimeIsAbsent(t *testing.T) {
	if got := optTime(time.Unix(0, 0)); !got.IsZero() {
		t.Errorf("epoch kept as %v, want absent", got)
	}
	in := time.Unix(1, 0)
	if got := optTime(in); !got.Equal(in) {
		t.Errorf("one second past the epoch dropped")
	}
}

// Sub-second precision cannot go on the wire -- microseconds travel
// in a separate integer field -- and upstream's decoder refuses a
// fractional GeneralizedTime, so the encoder truncates rather than
// rounds.
func TestFractionalSecondsAreTruncated(t *testing.T) {
	in := time.Date(2026, 10, 4, 15, 30, 45, 999999999, time.UTC)
	got := kerberosTime(in)
	if got.Nanosecond() != 0 {
		t.Errorf("kept %d ns", got.Nanosecond())
	}
	if got.Second() != 45 {
		t.Errorf("rounded to second %d, want 45",
			got.Second())
	}
}

func TestDERLength(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7F}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xFF}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		got := derLength(tc.n)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("derLength(%d) = % X, want % X",
				tc.n, got, tc.want)
		}
	}
}

// A context-tagged GeneralString has to be built by hand because
// encoding/asn1 ignores explicit,tag:N when it marshals a RawValue.
// This checks the bytes rather than just the round trip, since a
// missing wrapper round-trips within this package and is rejected by
// every C peer.
func TestCtxGstringCarriesItsOwnContextTag(t *testing.T) {
	r := ctxGstring(2, "ATHENA.MIT.EDU")
	want := []byte{0xA2, 0x10, 0x1B, 0x0E}
	if !bytes.HasPrefix(r.FullBytes, want) {
		t.Fatalf("got % X, want prefix % X",
			r.FullBytes, want)
	}
	// What a decoder hands back is the context element with the
	// inner TLV in Bytes, so reading has to strip two layers.
	back := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      r.FullBytes[2:],
	}
	s, err := ctxGstringValue(back)
	if err != nil {
		t.Fatalf("ctxGstringValue: %v", err)
	}
	if s != "ATHENA.MIT.EDU" {
		t.Errorf("read back %q", s)
	}
}

func TestOptCtxGstringOmitsEmpty(t *testing.T) {
	if r := optCtxGstring(11, ""); r.FullBytes != nil {
		t.Errorf("empty string encoded as % X", r.FullBytes)
	}
	s, ok, err := optCtxGstringValue(asn1.RawValue{})
	if err != nil || ok || s != "" {
		t.Errorf("absent field read as (%q, %v, %v)",
			s, ok, err)
	}
}

// The KKDCP envelope has no upstream reference encoding, so this is a
// round trip plus an assertion on the shape: a plain SEQUENCE with no
// application tag, kerb-message at [0].
func TestKDCProxyMessageRoundTrips(t *testing.T) {
	in := KDCProxyMessage{
		KerbMessage: Frame(
			[]byte{0x6A, 0x03, 0x02, 0x01, 0x05}),
		TargetDomain: "KDIAMOND.TEST",
	}
	b, err := MarshalKDCProxyMessage(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if b[0] != 0x30 {
		t.Errorf("first byte is %02X, want 30", b[0])
	}
	out, err := UnmarshalKDCProxyMessage(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(out.KerbMessage, in.KerbMessage) {
		t.Errorf("kerb-message is % X", out.KerbMessage)
	}
	if out.TargetDomain != in.TargetDomain {
		t.Errorf("target-domain is %q", out.TargetDomain)
	}
	if out.DCLocatorHint != 0 {
		t.Errorf("dclocator-hint is %d", out.DCLocatorHint)
	}
}

// kerb-message carries the TCP payload including its 4-byte
// big-endian length prefix, not the bare DER message. Omitting the
// prefix is the first thing to check when a client rejects a reply.
func TestFrameCarriesABigEndianLengthPrefix(t *testing.T) {
	msg := bytes.Repeat([]byte{0xAB}, 300)
	framed := Frame(msg)
	want := []byte{0x00, 0x00, 0x01, 0x2C}
	if !bytes.HasPrefix(framed, want) {
		t.Errorf("prefix is % X, want % X", framed[:4], want)
	}
	back, err := Unframe(framed)
	if err != nil {
		t.Fatalf("Unframe: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Error("message changed through the frame")
	}
}

func TestUnframeRejectsABadLength(t *testing.T) {
	cases := []struct {
		name   string
		framed []byte
	}{
		{"too short", []byte{0, 0, 1}},
		{"claims more than follows",
			[]byte{0, 0, 0, 8, 1, 2, 3}},
		{"claims fewer than follow",
			[]byte{0, 0, 0, 1, 1, 2, 3}},
		{"over the limit",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 1}},
	}
	for _, tc := range cases {
		if _, err := Unframe(tc.framed); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestCheckPvnoRejectsOtherVersions(t *testing.T) {
	if err := checkPvno(Pvno); err != nil {
		t.Errorf("rejected pvno 5: %v", err)
	}
	if err := checkPvno(4); err == nil {
		t.Error("accepted pvno 4")
	}
}

// Bit 14 is skipped: upstream defines no flag at 0x00020000 and does
// not even list it among the commented-out reserved values that
// resume at 0x00004000. Continuing the constant run through it would
// put enc-pa-rep and anonymous one bit too high, and nothing in a
// round trip would notice.
func TestBitFourteenIsNotAFlag(t *testing.T) {
	for _, f := range []Flags{
		FlagReserved, FlagForwardable, FlagForwarded,
		FlagProxiable, FlagProxy, FlagMayPostdate,
		FlagPostdated, FlagInvalid, FlagRenewable,
		FlagInitial, FlagPreAuthent, FlagHWAuthent,
		FlagTransitedPolicyChecked, FlagOKAsDelegate,
		FlagEncPARep, FlagAnonymous,
	} {
		if f == 0x00020000 {
			t.Error("a ticket flag claims bit 14")
		}
	}
}

// An AS-REQ carrying a TGS-only option is refused, and the set is not
// the obvious one: cname-in-addl-tkt is in it and the adjacent
// canonicalize bit is not.
func TestASInvalidOptions(t *testing.T) {
	in := []Flags{
		OptForwarded, OptProxy, OptRenew, OptValidate,
		OptEncTktInSKey, OptCNameInAddlTkt,
	}
	for _, o := range in {
		if ASInvalidOptions&o == 0 {
			t.Errorf("%08X is not refused", uint32(o))
		}
	}
	out := []Flags{
		OptForwardable, OptProxiable, OptAllowPostdate,
		OptPostdated, OptRenewable, OptRenewableOK,
		OptCanonicalize, OptRequestAnon,
	}
	for _, o := range out {
		if ASInvalidOptions&o != 0 {
			t.Errorf("%08X is refused but should not be",
				uint32(o))
		}
	}
}
