package transit

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

// expansionVectors is upstream's own transit-tests script
// (lib/krb5/krb/transit-tests), which drives t_expand -x and compares
// its output against a fixed list.
//
// This is the only anchor there is for any of this file. The script's
// own header says it tests expansion and not validation, and nothing
// upstream publishes an expected value for add_to_transited at all --
// kdc/rtest.c prints its answer and asserts nothing. So these nine
// cases carry the whole weight of "the expansion agrees with the C",
// and the comparison is of sorted lists because the script sorts both
// sides before comparing: the order the realms come out in is not
// part of the contract.
var expansionVectors = []struct {
	crealm, srealm, transit string
	want                    []string
	bad                     bool
}{
	{"ATHENA.MIT.EDU", "HACK.FOOBAR.COM",
		",EDU,BLORT.COM,COM,",
		[]string{"MIT.EDU", "EDU", "BLORT.COM", "COM",
			"FOOBAR.COM"}, false},
	{"ATHENA.MIT.EDU", "EDU", ",",
		[]string{"MIT.EDU"}, false},
	// The same answer with the ends swapped: a range has two ends
	// and no direction, which process_intermediates arranges by
	// sorting them on length before it looks at either.
	{"EDU", "ATHENA.MIT.EDU", ",",
		[]string{"MIT.EDU"}, false},
	{"x", "x", "/COM,/HP,/APOLLO, /COM/DEC",
		[]string{"/COM", "/COM/HP", "/COM/HP/APOLLO",
			"/COM/DEC"}, false},
	{"x", "x", "EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.",
		[]string{"EDU", "MIT.EDU", "ATHENA.MIT.EDU",
			"WASHINGTON.EDU",
			"CS.WASHINGTON.EDU"}, false},
	// Mixed name styles either side of a range: there is no
	// hierarchy spanning an X.500 name and a domain one, so the
	// range cannot be expanded and the path is refused.
	{"ATHENA.MIT.EDU", "/COM/HP/APOLLO", ",EDU,/COM,",
		nil, true},
	// The same field with a space before /COM, which detaches it
	// from the previous component and makes both ranges
	// expandable.
	{"ATHENA.MIT.EDU", "/COM/HP/APOLLO", ",EDU, /COM,",
		[]string{"EDU", "MIT.EDU", "/COM", "/COM/HP"}, false},
	{"ATHENA.MIT.EDU", "CS.CMU.EDU", ",EDU,",
		[]string{"EDU", "MIT.EDU", "CMU.EDU"}, false},
	{"XYZZY.ATHENA.MIT.EDU", "XYZZY.CS.CMU.EDU", ",EDU,",
		[]string{"EDU", "MIT.EDU", "ATHENA.MIT.EDU",
			"CMU.EDU", "CS.CMU.EDU"}, false},
}

func TestExpansionMatchesUpstreamsVectors(t *testing.T) {
	for _, v := range expansionVectors {
		got, err := Expand(v.crealm, v.srealm, v.transit)
		if v.bad {
			if !errors.Is(err, ErrIllegalPath) {
				t.Errorf("%q expanded to %v (%v)",
					v.transit, got, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", v.transit, err)
			continue
		}
		if a, b := sorted(got), sorted(v.want); a != b {
			t.Errorf("(%s) (%s) (%s)\n got %s\nwant %s",
				v.crealm, v.srealm, v.transit, a, b)
		}
	}
}

// sorted renders a realm list the way upstream's script compares
// them: sorted, because the order is not part of the contract.
func sorted(in []string) string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return strings.Join(out, " ")
}

// An empty field names no realms at all, which is the base case every
// single-hop ticket carries.
func TestEmptyFieldNamesNothing(t *testing.T) {
	got, err := Expand("A.TEST", "B.TEST", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("an empty field expanded to %v", got)
	}
}

// A quoted comma is part of a realm name and not a separator.
// Upstream reads the escape (chk_trans.c:212-213) though
// add_to_transited's own comment says it does not write one, so this
// is a field only another implementation produces -- which is exactly
// why reading it has to work.
func TestQuotedCommaIsLiteral(t *testing.T) {
	got, err := Expand("A.TEST", "B.TEST", `ODD\,NAME`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "ODD,NAME" {
		t.Errorf("got %q, want one realm ODD,NAME", got)
	}
}

// A component longer than the encoding allows is refused rather than
// truncated: a truncated realm name is a *different* realm name, and
// one that might well be in the allowed list.
func TestAnOverlongComponentIsRefused(t *testing.T) {
	_, err := Expand("A.TEST", "B.TEST",
		strings.Repeat("X", maxLen+1))
	if !errors.Is(err, ErrIllegalPath) {
		t.Errorf("got %v, want ErrIllegalPath", err)
	}
}
