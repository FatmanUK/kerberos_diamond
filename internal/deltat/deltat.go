// Package deltat parses kadmin's duration format.
//
// Every lifetime an operator types at kadmin goes through
// krb5_string_to_deltat, whose grammar is lib/krb5/krb/x-deltat.y
// (built as deltat.c in the tree). It is not Go's duration format and
// the two disagree on the common cases: `1d' is a day here and a
// parse error to Go, and `1h30m' means the same in both only by
// coincidence.
//
// The grammar, from the rule table (deltat.c:752-766 with the actions
// at :1253-1299):
//
//	deltat : num 'd' [hms]
//	       | num 'h' [ms]
//	       | num 'm' [s]
//	       | num 's'
//	       | num '-' num ':' num ':' num
//	       | num ':' num ':' num
//	       | num ':' num
//	       | num
//
// So `1d', `1d2h', `1d 2h 3m 4s', `2h30m', `30m', `1-02:03:04',
// `2:03:04', `30:00' are all durations, and **a bare number is
// seconds** (rule 18, :1295-1299). A leading minus negates the whole
// thing.
//
// Whitespace is allowed between components, which is why upstream's
// lexer has a token for it, and is why `maxlife 1 d' parses.
package deltat

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrSyntax reports a duration that is not one.
var ErrSyntax = errors.New("deltat: not a duration")

// Parse reads a kadmin duration.
func Parse(s string) (time.Duration, error) {
	in := strings.TrimSpace(s)
	if in == "" {
		return 0, fmt.Errorf("%w: empty", ErrSyntax)
	}
	neg := false
	if in[0] == '-' {
		neg, in = true, in[1:]
	}
	d, err := parseBody(in)
	if err != nil {
		return 0, err
	}
	if neg {
		d = -d
	}
	return d, nil
}

// parseBody parses a duration with its sign removed.
//
// The colon forms are tried first because they are unambiguous: a
// string containing a colon is one of them and nothing else.
func parseBody(in string) (time.Duration, error) {
	if strings.ContainsAny(in, ":-") {
		return parseColons(in)
	}
	return parseUnits(in)
}

// parseUnits reads the suffixed forms, in the order the grammar
// allows them: days, then hours, then minutes, then seconds, each at
// most once and never out of order.
//
// The order is part of the grammar rather than a convenience. `2h1d'
// is not a duration to kadmin, because opt_hms can follow 'd' but
// nothing can precede it (:1253-1266), and accepting it here would
// mean a configuration that worked against this KDC and not against a
// stock one.
func parseUnits(in string) (time.Duration, error) {
	units := []struct {
		suffix byte
		scale  time.Duration
	}{
		{'d', 24 * time.Hour},
		{'h', time.Hour},
		{'m', time.Minute},
		{'s', time.Second},
	}
	var total time.Duration
	rest, seen := in, false
	for _, u := range units {
		n, tail, ok, err := takeUnit(rest, u.suffix)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		total += time.Duration(n) * u.scale
		rest, seen = tail, true
	}
	if !seen {
		return bareSeconds(in)
	}
	if strings.TrimSpace(rest) != "" {
		return 0, fmt.Errorf("%w: %q", ErrSyntax, in)
	}
	return total, nil
}

// takeUnit reads a leading number followed by one unit letter.
func takeUnit(
	in string,
	suffix byte,
) (int64, string, bool, error) {
	in = strings.TrimSpace(in)
	i := 0
	for i < len(in) && in[i] >= '0' && in[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(in) || in[i] != suffix {
		return 0, in, false, nil
	}
	n, err := digits(in[:i])
	if err != nil {
		return 0, in, false, err
	}
	return n, in[i+1:], true, nil
}

// bareSeconds is rule 18: a number on its own is seconds.
func bareSeconds(in string) (time.Duration, error) {
	n, err := digits(strings.TrimSpace(in))
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

// parseColons reads the three clock forms:
//
//	d-h:m:s   a day count, a hyphen, then a clock
//	h:m:s
//	m:s
//
// Which one a string is depends only on how many colons it has, which
// is how the grammar distinguishes them too (:1283-1294).
func parseColons(in string) (time.Duration, error) {
	days := int64(0)
	if i := strings.IndexByte(in, '-'); i >= 0 {
		n, err := digits(strings.TrimSpace(in[:i]))
		if err != nil {
			return 0, err
		}
		days, in = n, in[i+1:]
	}
	parts := strings.Split(in, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("%w: %q", ErrSyntax, in)
	}
	// Two fields are minutes and seconds, three are hours,
	// minutes and seconds -- so a leading hour field is supplied
	// when it is absent rather than the list being read from the
	// other end.
	if len(parts) == 2 {
		parts = append([]string{"0"}, parts...)
	}
	return clock(days, parts)
}

// clock turns a day count and three clock fields into a duration.
//
// The fields are not range-checked, and that is upstream's behaviour:
// `0:90:00' is ninety minutes, because the grammar multiplies and
// sums without asking whether a minute field is below sixty (the DO
// macro at :1283-1294 does the arithmetic and only overflow is
// refused). A reimplementation that refused it would reject
// configurations a stock kadmin accepts.
func clock(days int64, parts []string) (time.Duration, error) {
	scales := []time.Duration{
		time.Hour, time.Minute, time.Second,
	}
	total := time.Duration(days) * 24 * time.Hour
	for i, p := range parts {
		n, err := digits(strings.TrimSpace(p))
		if err != nil {
			return 0, err
		}
		total += time.Duration(n) * scales[i]
	}
	return total, nil
}

// digits reads an unsigned decimal number, refusing anything else.
//
// strconv.ParseInt would accept a leading sign and underscores,
// neither of which upstream's lexer produces a token for.
func digits(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: empty number", ErrSyntax)
	}
	var n int64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: %q", ErrSyntax, s)
		}
		n = n*10 + int64(s[i]-'0')
		if n > maxDeltat {
			return 0, fmt.Errorf(
				"%w: %q overflows", ErrSyntax, s)
		}
	}
	return n, nil
}

// maxDeltat is upstream's MAX_TIME, the largest a krb5_deltat holds
// (deltat.c:90-93 derives its limits from it).
const maxDeltat = int64(1)<<31 - 1

// String renders a duration the way krb5_deltat_to_string does
// (str_conv.c:259-280): days then a clock, and the day part omitted
// when it is zero.
func String(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	secs := int64(d / time.Second)
	days := secs / 86400
	secs %= 86400
	out := fmt.Sprintf("%d:%02d:%02d", secs/3600,
		(secs%3600)/60, secs%60)
	if days != 0 {
		out = fmt.Sprintf("%d days %s", days, out)
	}
	if neg {
		out = "-" + out
	}
	return out
}
