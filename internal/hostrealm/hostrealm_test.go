package hostrealm

import (
	"strings"
	"testing"
)

// The fixture from upstream's own test for this and nothing else
// (tests/t_hostrealm.py:13), transcribed into the one-line form. Two
// of its three entries differ only by a leading dot, which is what
// makes it the right fixture: the precedence between those two is the
// whole of the search order.
const upstreamMap = ".x=DOTMATCH;x=MATCH;.1=NUMMATCH"

// Every assertion upstream makes about the profile module
// (t_hostrealm.py:53-61), case for case.
//
// Two of them read differently there than here, and the difference is
// not a disagreement. Upstream runs four modules, so 4.3.2.1 and
// b:c.x "fall through" from the profile module to a test module that
// answers with the host's components. A KDC has only the profile
// module (hostrealm.c:69-94 registers four; only this one implements
// host_realm at all), so falling through means nothing answers, and
// that is the empty realm.
func TestRealmReadsUpstreamsExample(t *testing.T) {
	m, err := Parse(upstreamMap)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host, want string
	}{
		{"x", "MATCH"},
		{".x", "DOTMATCH"},
		{"b.x", "DOTMATCH"},
		{".b.c.x", "DOTMATCH"},
		{"b.1", "NUMMATCH"},
		// An address is never looked up, so these two reach
		// no entry at all.
		{"4.3.2.1", ""},
		{"b:c.x", ""},
		// Cleaning folds case and strips one trailing dot
		// before anything is matched.
		{"X.", "MATCH"},
		// No module answering is the referral realm, which
		// find_referral_tgs reads as "no referral".
		{"", ""},
	} {
		if got := m.Realm(c.host); got != c.want {
			t.Errorf("%q is %q, want %q",
				c.host, got, c.want)
		}
	}
}

// A bare entry and a dot-prefixed one are not the same pattern, and
// neither contains the other.
//
// The walk for b.x is b.x, then .x, then x -- so a *bare* entry for x
// matches b.x as well, at the last step. But the walk for x alone is
// just x, so a dot-prefixed entry never matches the domain itself.
// That asymmetry is why upstream's fixture carries both and gets
// MATCH for x while getting DOTMATCH for b.x: at any level where both
// could match, the dotted form is tried first.
func TestADottedEntryAndABareOneDifferBothWays(t *testing.T) {
	dotted, err := Parse(".x=DOT")
	if err != nil {
		t.Fatal(err)
	}
	if got := dotted.Realm("x"); got != "" {
		t.Errorf("a dotted entry matched the domain "+
			"itself: %q", got)
	}
	if got := dotted.Realm("b.x"); got != "DOT" {
		t.Errorf("b.x is %q, want DOT", got)
	}
	bare, err := Parse("x=BARE")
	if err != nil {
		t.Fatal(err)
	}
	if got := bare.Realm("x"); got != "BARE" {
		t.Errorf("x is %q, want BARE", got)
	}
	if got := bare.Realm("b.x"); got != "BARE" {
		t.Errorf("b.x is %q, want BARE", got)
	}
}

// A single label is a real pattern. Upstream's own referral test maps
// "d" and looks up "x.d" (tests/t_referral.py:5-11), so an
// implementation that required a dot somewhere would fail the case
// the feature was written for.
func TestASingleLabelIsAPattern(t *testing.T) {
	m, err := Parse("d=REFREALM")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Realm("x.d"); got != "REFREALM" {
		t.Errorf("x.d is %q, want REFREALM", got)
	}
}

// Upstream's address test is looser than parsing one, and the
// looseness is load-bearing: a name is IPv4 only if it is digits and
// dots with *exactly* three dots, and IPv6 only if it holds a colon
// (k5_is_numeric_address, hostrealm.c:316-339).
//
// So 1.2.3 and 1.2.3.4.5 are not addresses and *are* looked up, while
// ::1 is an address and is not. A net.ParseIP here would disagree on
// all three, and the disagreement would be invisible: the symptom is
// a referral that should have been offered and was not. These three
// are derived from reading that function rather than from a published
// case, which is why they are a separate test from the one above.
func TestUpstreamsAddressTestIsReproducedAsWritten(t *testing.T) {
	m, err := Parse("3=THREE;5=FIVE;.1=ONE")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host, want string
	}{
		{"1.2.3", "THREE"},
		{"1.2.3.4.5", "FIVE"},
		{"::1", ""},
		{"4.3.2.1", ""},
	} {
		if got := m.Realm(c.host); got != c.want {
			t.Errorf("%q is %q, want %q",
				c.host, got, c.want)
		}
	}
}

// The zero value is usable and answers nothing, so no caller needs to
// check for it. That is the common case: a realm with no host-based
// services elsewhere configures no map at all.
func TestTheZeroValueMatchesNothing(t *testing.T) {
	var m Map
	if got := m.Realm("www.example.test"); got != "" {
		t.Errorf("a nil map answered %q", got)
	}
	if m.String() != "" {
		t.Errorf("a nil map rendered as %q", m.String())
	}
}

// Unset is not an error, and is not an empty map either: Parse
// returns nil so the field reads as "no configuration".
func TestUnsetIsNotAnError(t *testing.T) {
	m, err := Parse("   ")
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		t.Errorf("got %v, want nil", m)
	}
}

// A malformed entry is reported rather than ignored. Silently
// dropping one would leave a deployment believing it had configured a
// mapping it had not, and the symptom would be a refused ticket much
// later, with nothing pointing at the configuration.
func TestParseRejectsMalformedEntries(t *testing.T) {
	for _, in := range []string{
		"example.test", "=EXAMPLE.TEST", "example.test=",
		".x=X;broken", "  =  ",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

// An empty entry between semicolons is skipped rather than refused,
// which keeps a trailing separator from being a configuration error.
// ParsePaths does the same for the same reason.
func TestEmptyEntriesAreSkipped(t *testing.T) {
	m, err := Parse(";.x=X;;")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m.Realm("b.x") != "X" {
		t.Errorf("got %v", m)
	}
}

// Round-tripping keeps a configuration readable in a log line or an
// error, which is the only reason String exists.
func TestRoundTripThroughString(t *testing.T) {
	m, err := Parse(upstreamMap)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(m.String())
	if err != nil {
		t.Fatalf("re-reading %q: %v", m.String(), err)
	}
	if len(again) != len(m) {
		t.Fatalf("%d entries became %d", len(m), len(again))
	}
	for pattern, realm := range m {
		if again[pattern] != realm {
			t.Errorf("%s=%s became %s=%s", pattern,
				realm, pattern, again[pattern])
		}
	}
}

// A pattern is matched case-insensitively from either side: the host
// is folded by clean_hostname and the pattern is folded when it is
// read. A realm name is not folded, because it is case-sensitive.
func TestCaseIsFoldedOnBothSides(t *testing.T) {
	m, err := Parse(".Example.TEST=Mixed.Case")
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Realm("WWW.EXAMPLE.test"); got != "Mixed.Case" {
		t.Errorf("got %q, want Mixed.Case", got)
	}
	if strings.Contains(m.String(), "Example") {
		t.Errorf("the pattern kept its case: %q", m.String())
	}
}
