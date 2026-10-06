package transit

import (
	"errors"
	"strings"
	"testing"
)

// The example from upstream's own comment (walk_rtree.c:186-210),
// transcribed into the one-line form. It is worth using as the
// fixture because it is the case the feature was added for: ANL.GOV
// reaching NERSC.GOV through ES.NET, and HAL.COM through two hops,
// between realms whose names say nothing about any of it.
const anlPaths = "ANL.GOV>NERSC.GOV=ES.NET;" +
	"ANL.GOV>PNL.GOV=ES.NET;" +
	"ANL.GOV>ES.NET=.;" +
	"ANL.GOV>HAL.COM=K5.MOON,K5.JUPITER;" +
	"ES.NET>ANL.GOV=."

func TestParsePathsReadsUpstreamsExample(t *testing.T) {
	p, err := ParsePaths(anlPaths)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		client, server string
		want           string
	}{
		{"ANL.GOV", "NERSC.GOV", "ES.NET"},
		{"ANL.GOV", "HAL.COM", "K5.MOON K5.JUPITER"},
		// A direct trust is an entry with no hops, which is
		// not the same as no entry: the first forbids the
		// hierarchical guess and the second invites it.
		{"ANL.GOV", "ES.NET", ""},
	} {
		hops, ok := p.hops(c.client, c.server)
		if !ok {
			t.Errorf("%s>%s is missing",
				c.client, c.server)
			continue
		}
		if got := strings.Join(hops, " "); got != c.want {
			t.Errorf("%s>%s is %q, want %q",
				c.client, c.server, got, c.want)
		}
	}
	if _, ok := p.hops("HAL.COM", "ANL.GOV"); ok {
		t.Error("an unconfigured pair was found")
	}
}

// A configured path is walked exactly as written, with no regard for
// what the names look like: ANL.GOV and HAL.COM have nothing in
// common and the path between them is two hops.
func TestAConfiguredPathIsWalkedAsWritten(t *testing.T) {
	p, err := ParsePaths(anlPaths)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := p.Tree("ANL.GOV", "HAL.COM")
	if err != nil {
		t.Fatal(err)
	}
	want := "ANL.GOV@ANL.GOV K5.MOON@ANL.GOV " +
		"K5.JUPITER@K5.MOON HAL.COM@K5.JUPITER"
	if got := render(tree); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

// An entry with no hops means directly connected, so the path is the
// client's own krbtgt and then the server's.
func TestADirectEntryHasNoIntermediates(t *testing.T) {
	p, err := ParsePaths(anlPaths)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := p.Tree("ANL.GOV", "ES.NET")
	if err != nil {
		t.Fatal(err)
	}
	want := "ANL.GOV@ANL.GOV ES.NET@ANL.GOV"
	if got := render(tree); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
}

// Configuration *replaces* the hierarchical guess rather than adding
// to it. These two realms look related, and the entry says the path
// runs somewhere else entirely; the hierarchy must not creep back in.
func TestAConfiguredPathReplacesTheHierarchy(t *testing.T) {
	p, err := ParsePaths("A.EXAMPLE.TEST>B.EXAMPLE.TEST=VIA.TEST")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := p.Allowed("A.EXAMPLE.TEST", "B.EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed["VIA.TEST"] {
		t.Errorf("the configured hop is not allowed: %v",
			allowed)
	}
	if allowed["EXAMPLE.TEST"] {
		t.Errorf("the hierarchical parent crept in: %v",
			allowed)
	}
}

// An unconfigured pair still gets the hierarchy, which is what makes
// the common case need no configuration at all.
func TestAnUnconfiguredPairUsesTheHierarchy(t *testing.T) {
	p, err := ParsePaths("ONE.TEST>TWO.TEST=VIA.TEST")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := p.Allowed("A.EXAMPLE.TEST", "B.EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed["EXAMPLE.TEST"] {
		t.Errorf("the hierarchy was not used: %v", allowed)
	}
}

// A configured path makes a transited field acceptable that the
// hierarchy would refuse, which is the whole point of having one.
func TestCheckAcceptsAConfiguredPath(t *testing.T) {
	const field = "ES.NET"
	if err := Check(field, "ANL.GOV", "NERSC.GOV"); err == nil {
		t.Fatal("the hierarchy accepted an unrelated realm")
	}
	p, err := ParsePaths(anlPaths)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Check(field, "ANL.GOV", "NERSC.GOV"); err != nil {
		t.Errorf("the configured path was refused: %v", err)
	}
}

// The nil Paths is usable and means "no configuration", because that
// is the common case and an error there would make every caller
// check.
func TestTheZeroValueIsTheHierarchy(t *testing.T) {
	var p Paths
	tree, err := p.Tree("SUB.EXAMPLE.TEST", "EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	want := "SUB.EXAMPLE.TEST@SUB.EXAMPLE.TEST " +
		"EXAMPLE.TEST@SUB.EXAMPLE.TEST"
	if got := render(tree); got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	got, err := ParsePaths("  ")
	if got != nil || err != nil {
		t.Errorf("empty config gave (%v, %v)", got, err)
	}
}

// A malformed entry is reported rather than ignored. Silently
// dropping one would leave a deployment believing it had configured a
// path it had not, and the symptom would be a refused ticket much
// later.
func TestParsePathsRejectsMalformedEntries(t *testing.T) {
	for _, in := range []string{
		"A.TEST>B.TEST", "A.TEST=B.TEST", ">B.TEST=.",
		"A.TEST>=.", "A.TEST>B.TEST=",
	} {
		if _, err := ParsePaths(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

// Round-tripping keeps a configuration readable in a log line or an
// error, which is the only reason String exists.
func TestPathsRoundTripThroughString(t *testing.T) {
	p, err := ParsePaths(anlPaths)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParsePaths(p.String())
	if err != nil {
		t.Fatalf("re-reading %q: %v", p.String(), err)
	}
	if len(again) != len(p) {
		t.Fatalf("%d entries became %d", len(p), len(again))
	}
	for k, hops := range p {
		if strings.Join(again[k], ",") !=
			strings.Join(hops, ",") {
			t.Errorf("%s became %v", k, again[k])
		}
	}
}

// There is still no path from a realm to itself, configured or not.
func TestNoConfiguredPathToItself(t *testing.T) {
	p, err := ParsePaths("ONE.TEST>ONE.TEST=VIA.TEST")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Tree("ONE.TEST", "ONE.TEST"); !errors.Is(
		err, ErrNoPath) {
		t.Errorf("got %v, want ErrNoPath", err)
	}
}
