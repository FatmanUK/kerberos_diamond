package transit

import (
	"fmt"
	"strings"
)

// Paths is a configured set of realm paths, this project's equivalent
// of krb5.conf's [capaths] section.
//
// It exists because the realm *hierarchy* is a convention about names
// and nothing more. A.EXAMPLE.COM and B.EXAMPLE.COM look related and
// a path between them can be guessed; HAL.COM and ANL.GOV do not, and
// no amount of reading their names says that the route between them
// runs through ES.NET. Upstream's own comment makes the point by
// quoting RFC 1510 (walk_rtree.c:173-178): "If a hierarchical
// organization is not used it may be necessary to consult some
// database in order to construct an authentication path between
// realms."
//
// A nil Paths is usable and means "no configuration", so every method
// here falls back to the hierarchy. That is the common case and the
// reason the zero value is not an error.
type Paths map[string][]string

// ParsePaths reads the KD_CAPATHS form: entries separated by
// semicolons, each "client>server=hop[,hop...]", with a lone "." for
// a direct trust.
//
//	SUB.A.TEST>C.TEST=A.TEST,MID.TEST;A.TEST>B.TEST=.
//
// The shape is upstream's turned into one line, because configuration
// here is environment-only and a profile section has nowhere to live.
// The "." for direct comes straight across: upstream uses it because
// its profile routines cannot hold an empty value
// (walk_rtree.c:213-215), and this keeps it so that a krb5.conf
// [capaths] section can be transcribed without reinterpretation.
func ParsePaths(s string) (Paths, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := Paths{}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		key, hops, err := parseEntry(entry)
		if err != nil {
			return nil, err
		}
		out[key] = hops
	}
	return out, nil
}

// parseEntry reads one "client>server=hops" entry.
func parseEntry(entry string) (string, []string, error) {
	pair, rest, ok := strings.Cut(entry, "=")
	if !ok {
		return "", nil, fmt.Errorf(
			"capaths %q: no \"=\"", entry)
	}
	client, server, ok := strings.Cut(pair, ">")
	if !ok || client == "" || server == "" {
		return "", nil, fmt.Errorf(
			"capaths %q: want client>server", entry)
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", nil, fmt.Errorf(
			"capaths %q: no path", entry)
	}
	// A leading "." means directly connected, which is an empty
	// hop list rather than a hop named ".". Upstream tests only
	// the first character (walk_rtree.c:139), so "." and
	// ".anything" both mean direct; that is reproduced rather
	// than tightened.
	if rest[0] == '.' {
		return key(client, server), nil, nil
	}
	var hops []string
	for _, h := range strings.Split(rest, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hops = append(hops, h)
		}
	}
	return key(client, server), hops, nil
}

// String renders a Paths back into the form ParsePaths reads, for an
// error message or a log line. The entry order is not stable.
func (p Paths) String() string {
	out := make([]string, 0, len(p))
	for k, hops := range p {
		if len(hops) == 0 {
			out = append(out, k+"=.")
			continue
		}
		out = append(out, k+"="+strings.Join(hops, ","))
	}
	return strings.Join(out, ";")
}

func key(client, server string) string {
	return client + ">" + server
}

// hops returns the configured intermediates for a realm pair, and
// whether the pair was configured at all. An entry with no
// intermediates is a direct trust, which is not the same as no entry:
// the first forbids the hierarchical guess and the second invites it.
func (p Paths) hops(client, server string) ([]string, bool) {
	h, ok := p[key(client, server)]
	return h, ok
}
