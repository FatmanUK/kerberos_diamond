package store

import (
	"strings"
	"testing"
)

// Names must round-trip exactly, because the unparsed form is the
// database key: a name that re-renders differently becomes a
// different row and the failure reads as "client not found".
var nameCases = []struct {
	name       string
	realm      string
	components []string
	want       string
}{
	{"one component", "KDIAMOND.TEST",
		[]string{"user"}, "user@KDIAMOND.TEST"},
	{"krbtgt", "KDIAMOND.TEST",
		[]string{"krbtgt", "KDIAMOND.TEST"},
		"krbtgt/KDIAMOND.TEST@KDIAMOND.TEST"},
	{"host service", "KDIAMOND.TEST",
		[]string{"host", "kdc.example.org"},
		"host/kdc.example.org@KDIAMOND.TEST"},
	{"escaped at", "KDIAMOND.TEST",
		[]string{"a@b"}, `a\@b@KDIAMOND.TEST`},
	{"escaped slash", "KDIAMOND.TEST",
		[]string{"a/b"}, `a\/b@KDIAMOND.TEST`},
	{"escaped backslash", "KDIAMOND.TEST",
		[]string{`a\b`}, `a\\b@KDIAMOND.TEST`},
	{"escaped tab", "KDIAMOND.TEST",
		[]string{"a\tb"}, `a\tb@KDIAMOND.TEST`},
	{"escaped newline", "KDIAMOND.TEST",
		[]string{"a\nb"}, `a\nb@KDIAMOND.TEST`},
	{"escaped nul", "KDIAMOND.TEST",
		[]string{"a\x00b"}, `a\0b@KDIAMOND.TEST`},
}

func TestNameRoundTrip(t *testing.T) {
	for _, tc := range nameCases {
		t.Run(tc.name, func(t *testing.T) {
			got := UnparseName(tc.realm, tc.components)
			if got != tc.want {
				t.Fatalf("got %q, want %q",
					got, tc.want)
			}
			cs, realm, err := ParseName(got)
			if err != nil {
				t.Fatalf("ParseName: %v", err)
			}
			if realm != tc.realm {
				t.Errorf("realm %q, want %q",
					realm, tc.realm)
			}
			if strings.Join(cs, "\x1f") !=
				strings.Join(tc.components, "\x1f") {
				t.Errorf("components %q, want %q",
					cs, tc.components)
			}
		})
	}
}

// The realm is what follows the *last* unescaped "@". Upstream's
// parser resets its write position on each one and carries on
// (lib/krb5/krb/parse.c:147-151), so a second "@" restarts the realm
// rather than being rejected.
func TestLastAtWins(t *testing.T) {
	cs, realm, err := ParseName("user@FIRST@SECOND")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	if realm != "SECOND" {
		t.Errorf("realm is %q, want SECOND", realm)
	}
	if len(cs) != 1 || cs[0] != "user" {
		t.Errorf("components are %q", cs)
	}
}

func TestParseNameRejectsTheUnparseable(t *testing.T) {
	for _, name := range []string{
		"user",      // no realm
		"a@REALM/b", // component after the realm
	} {
		if _, _, err := ParseName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
}

// An unescaped separator inside a component would split it, so the
// escape has to survive the round trip rather than merely be written.
func TestEscapedSeparatorsDoNotSplit(t *testing.T) {
	cs, realm, err := ParseName(`a\/b\@c@KDIAMOND.TEST`)
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	if realm != "KDIAMOND.TEST" {
		t.Errorf("realm is %q", realm)
	}
	if len(cs) != 1 {
		t.Fatalf("split into %d components: %q", len(cs), cs)
	}
	if cs[0] != "a/b@c" {
		t.Errorf("component is %q, want %q", cs[0], "a/b@c")
	}
}

func TestWireNameRoundTrips(t *testing.T) {
	name := UnparseName("KDIAMOND.TEST",
		[]string{"krbtgt", "KDIAMOND.TEST"})
	p, realm, err := WireName(name)
	if err != nil {
		t.Fatalf("WireName: %v", err)
	}
	if realm != "KDIAMOND.TEST" {
		t.Errorf("realm is %q", realm)
	}
	if got := p.String(); got != "krbtgt/KDIAMOND.TEST" {
		t.Errorf("name is %q", got)
	}
	if UnparseName(realm, p.Components) != name {
		t.Error("round trip through the wire form changed it")
	}
}
