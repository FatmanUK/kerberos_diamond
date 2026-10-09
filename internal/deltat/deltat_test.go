package deltat

import (
	"errors"
	"testing"
	"time"
)

// Every form the grammar allows (deltat.c:752-766, actions at
// :1253-1299), and the one that catches a reimplementation: **a bare
// number is seconds** (rule 18), not minutes and not hours.
func TestEveryFormTheGrammarAllows(t *testing.T) {
	for _, c := range grammarCases() {
		t.Run(c.in, func(t *testing.T) {
			got, err := Parse(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("%v, want %v", got, c.want)
			}
		})
	}
}

// grammarCase is one duration and what it means.
type grammarCase struct {
	in   string
	want time.Duration
}

// grammarCases is every form, written out.
func grammarCases() []grammarCase {
	return []grammarCase{
		{"0", 0},
		{"3600", time.Hour},
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"2h", 2 * time.Hour},
		{"1d", 24 * time.Hour},
		{"1d2h", 26 * time.Hour},
		{"1d2h3m4s", 26*time.Hour + 3*time.Minute +
			4*time.Second},
		{"2h30m", 2*time.Hour + 30*time.Minute},
		{"5m6s", 5*time.Minute + 6*time.Second},
		// Whitespace between components, which is why
		// upstream's lexer has a token for it.
		{"1d 2h 3m 4s", 26*time.Hour + 3*time.Minute +
			4*time.Second},
		// The clock forms: two fields are minutes and
		// seconds, three are hours, minutes and seconds.
		{"30:00", 30 * time.Minute},
		{"2:03:04", 2*time.Hour + 3*time.Minute +
			4*time.Second},
		{"1-02:03:04", 26*time.Hour + 3*time.Minute +
			4*time.Second},
		// And a sign negates the whole thing.
		{"-1h", -time.Hour},
	}
}

// A clock field is **not** range checked, which is upstream's
// behaviour rather than leniency: the grammar multiplies and sums
// without asking whether a minute field is below sixty, and only
// overflow is refused. Refusing `0:90:00' would reject a
// configuration a stock kadmin accepts.
func TestClockFieldsAreNotRangeChecked(t *testing.T) {
	got, err := Parse("0:90:00")
	if err != nil {
		t.Fatal(err)
	}
	if got != 90*time.Minute {
		t.Errorf("%v, want 90m", got)
	}
}

// Units must appear in descending order and at most once each, which
// is the grammar and not a convenience: opt_hms can follow 'd' but
// nothing can precede it (:1253-1266). Accepting `2h1d' would make a
// configuration work here and not against a stock KDC.
func TestUnitsMustBeInOrder(t *testing.T) {
	for _, bad := range []string{
		"2h1d", "4s3m", "1m2h", "1d1d",
	} {
		if d, err := Parse(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, d)
		}
	}
}

// Everything else is a syntax error, including the Go duration forms
// that look plausible.
func TestWhatIsNotADuration(t *testing.T) {
	for _, bad := range []string{
		"", "   ", "x", "1y", "1.5h", "1_000",
		"+1h", "1:2:3:4", ":30", "1-", "99999999999",
	} {
		if d, err := Parse(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, d)
		} else if !errors.Is(err, ErrSyntax) {
			t.Errorf("%q gave %v", bad, err)
		}
	}
}

// String renders the way krb5_deltat_to_string does
// (str_conv.c:259-280): a clock, with a day count in front only when
// there is one.
func TestStringMatchesUpstreamsRendering(t *testing.T) {
	for _, c := range []struct {
		in   time.Duration
		want string
	}{
		{0, "0:00:00"},
		{90 * time.Second, "0:01:30"},
		{26*time.Hour + time.Minute, "1 days 2:01:00"},
		{-time.Hour, "-1:00:00"},
	} {
		if got := String(c.in); got != c.want {
			t.Errorf("%v rendered %q, want %q", c.in,
				got, c.want)
		}
	}
}
