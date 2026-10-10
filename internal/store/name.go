package store

import (
	"fmt"
	"strings"

	"github.com/FatmanUK/diamond_krb/internal/wire"
)

// UnparseName renders a principal and realm the way krb5_unparse_name
// does, which is what every row of the database is keyed by.
//
// Components are joined with "/" and the realm follows "@". Inside a
// component, "@", "/" and "\" are backslash-escaped and tab, newline,
// backspace and NUL become \t, \n, \b and \0
// (lib/krb5/krb/unparse.c:101-131). Escaping matters even though no
// principal in this project needs it: a name that round-trips wrongly
// becomes a different database key, and the failure shows up as
// "client not found".
func UnparseName(realm string, components []string) string {
	var b strings.Builder
	for i, c := range components {
		if i > 0 {
			b.WriteByte('/')
		}
		writeEscaped(&b, c)
	}
	b.WriteByte('@')
	writeEscaped(&b, realm)
	return b.String()
}

func writeEscaped(b *strings.Builder, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '@', '/', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\b':
			b.WriteString(`\b`)
		case 0:
			b.WriteString(`\0`)
		default:
			b.WriteByte(c)
		}
	}
}

// ErrBadName reports a principal name that cannot be parsed.
var ErrBadName = fmt.Errorf("malformed principal name")

// ParseName splits a fully qualified principal back into its
// components and realm.
//
// The realm is what follows the *last* unescaped "@". That is not a
// simplification: upstream's parser resets its write position when it
// meets an "@" and carries on (lib/krb5/krb/parse.c:147-151), so a
// second one restarts the realm rather than being an error. A "/"
// after the realm has begun trips an assertion upstream, so it is
// rejected here rather than guessed at.
func ParseName(name string) ([]string, string, error) {
	p := nameParser{parts: []string{""}}
	for i := 0; i < len(name); i++ {
		if name[i] == '\\' && i+1 < len(name) {
			i++
			p.add(unescape(name[i]))
			continue
		}
		if err := p.step(name[i], name); err != nil {
			return nil, "", err
		}
	}
	if !p.inRealm {
		return nil, "", fmt.Errorf(
			"%w: %q has no realm", ErrBadName, name)
	}
	return p.parts, p.realm, nil
}

// nameParser accumulates components until the realm begins, then the
// realm.
type nameParser struct {
	parts   []string
	realm   string
	inRealm bool
}

func (p *nameParser) add(s string) {
	if p.inRealm {
		p.realm += s
		return
	}
	p.parts[len(p.parts)-1] += s
}

func (p *nameParser) step(c byte, name string) error {
	switch {
	case c == '@':
		p.inRealm, p.realm = true, ""
	case c == '/' && p.inRealm:
		return fmt.Errorf("%w: %q has a component after "+
			"its realm", ErrBadName, name)
	case c == '/':
		p.parts = append(p.parts, "")
	default:
		p.add(string(c))
	}
	return nil
}

// unescape maps the one character after a backslash. Anything other
// than the four named escapes stands for itself, which is how "\@"
// and "\/" work (lib/krb5/krb/parse.c:157-167).
func unescape(c byte) string {
	switch c {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'b':
		return "\b"
	case '0':
		return "\x00"
	}
	return string(c)
}

// WireName turns a database key back into the PrincipalName and realm
// a message carries.
func WireName(name string) (wire.PrincipalName, string, error) {
	parts, realm, err := ParseName(name)
	if err != nil {
		return wire.PrincipalName{}, "", err
	}
	return wire.PrincipalName{
		Type:       wire.NTPrincipal,
		Components: parts,
	}, realm, nil
}
