package transit

import (
	"errors"
	"strings"
	"testing"
)

// Nothing upstream asserts an expected realm tree either --
// t_walk_rtree.c prints and exits -- so these cases come from reading
// walk_rtree.c. The shape is what matters: the path runs up from the
// client to the realms' common ancestor and back down to the server.
var treeVectors = []struct {
	name           string
	client, server string
	want           string
}{
	{"a child reaching its parent walks up once",
		"SUB.EXAMPLE.TEST", "EXAMPLE.TEST",
		"SUB.EXAMPLE.TEST@SUB.EXAMPLE.TEST " +
			"EXAMPLE.TEST@SUB.EXAMPLE.TEST"},
	{"two siblings meet at their parent",
		"A.EXAMPLE.TEST", "B.EXAMPLE.TEST",
		"A.EXAMPLE.TEST@A.EXAMPLE.TEST " +
			"EXAMPLE.TEST@A.EXAMPLE.TEST " +
			"B.EXAMPLE.TEST@EXAMPLE.TEST"},
	{"a grandchild walks up twice",
		"SUB.OTHER.EXAMPLE.TEST", "EXAMPLE.TEST",
		"SUB.OTHER.EXAMPLE.TEST@SUB.OTHER.EXAMPLE.TEST " +
			"OTHER.EXAMPLE.TEST@SUB.OTHER.EXAMPLE.TEST " +
			"EXAMPLE.TEST@OTHER.EXAMPLE.TEST"},
}

func TestTree(t *testing.T) {
	for _, v := range treeVectors {
		got, err := Tree(v.client, v.server)
		if err != nil {
			t.Errorf("%s: %v", v.name, err)
			continue
		}
		if s := render(got); s != v.want {
			t.Errorf("%s:\n got %s\nwant %s",
				v.name, s, v.want)
		}
	}
}

func render(tree []TGSName) string {
	out := make([]string, 0, len(tree))
	for _, h := range tree {
		out = append(out, h.Service+"@"+h.Realm)
	}
	return strings.Join(out, " ")
}

// The suffix has to start where a component starts, or the shorter of
// two names that merely end alike is reported as the other's parent.
// Upstream's own comment names this case (adjtail,
// walk_rtree.c:517-520), and it is the one place in the file where
// the obvious implementation is wrong rather than merely incomplete.
func TestASharedSuffixIsNotAlwaysAnAncestor(t *testing.T) {
	// These two share "BC.EXAMPLE.TEST" and their real common
	// ancestor is EXAMPLE.TEST, so that is where the path must
	// turn round.
	tree, err := Tree("ABC.EXAMPLE.TEST", "XBC.EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range tree {
		if h.Realm == "BC.EXAMPLE.TEST" ||
			h.Service == "BC.EXAMPLE.TEST" {
			t.Fatalf("BC.EXAMPLE.TEST is in the path: %s",
				render(tree))
		}
	}
	allowed, err := Allowed("ABC.EXAMPLE.TEST",
		"XBC.EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed["EXAMPLE.TEST"] {
		t.Errorf("the real ancestor is not allowed: %v",
			allowed)
	}
}

// There is no path from a realm to itself, and upstream says so with
// an error rather than an empty list -- which matters because an
// empty allowed set would refuse every field instead of there being
// nothing to check.
func TestNoPathToItself(t *testing.T) {
	for _, c := range []struct{ client, server string }{
		{"ONE.TEST", "ONE.TEST"},
		{"", "ONE.TEST"},
		{"ONE.TEST", ""},
	} {
		_, err := Tree(c.client, c.server)
		if !errors.Is(err, ErrNoPath) {
			t.Errorf("Tree(%q, %q) gave %v",
				c.client, c.server, err)
		}
	}
}

// Allowed names the realm each hop was issued *by*, not the realm it
// grants tickets for. The distinction is the whole of what the check
// compares against, and getting it backwards would accept exactly the
// realms it should refuse.
func TestAllowedIsTheIssuingRealms(t *testing.T) {
	allowed, err := Allowed("A.EXAMPLE.TEST", "B.EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"A.EXAMPLE.TEST", "EXAMPLE.TEST",
	} {
		if !allowed[want] {
			t.Errorf("%s not allowed: %v", want, allowed)
		}
	}
	// The server's own realm issues nothing in the path -- it is
	// where the path ends -- so it is not in the set.
	if allowed["B.EXAMPLE.TEST"] {
		t.Errorf("the server's realm is allowed: %v", allowed)
	}
}
