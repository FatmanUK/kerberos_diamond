package transit

import "strings"

// Add appends a realm to a transited encoding, keeping it compressed
// (add_to_transited, kdc/kdc_transit.c:144-408).
//
// tgs is the realm that issued the ticket-granting ticket this
// request presented -- which is the realm being added, because it is
// the realm the request has just come *through*. client and server
// are the two ends, and they matter without appearing in the output:
// a realm that is already one of the two ends is not written down,
// because both ends know it.
//
// The compression is the whole of the difficulty. A realm is written
// in full only when it cannot be written relative to its neighbour,
// and deciding that means walking the existing field component by
// component, expanding each one far enough to compare.
//
// Two of upstream's own caveats are reproduced rather than fixed. It
// does not write the null-subfield notation and gets confused reading
// it; and it does not quote commas inside realm names, though the
// *reader* handles the escape. Fixing either here would produce a
// field the C could not read back, which is the opposite of the
// point.
func Add(encoded, tgs, client, server string) (string, error) {
	a := &adder{
		realm: tgs,
		rest:  encoded,
		// A realm that is one of the two ends is already
		// implied, so the walk starts with nothing left to
		// add and only rewrites what it reads.
		added: tgs == client || tgs == server,
	}
	if err := a.walk(); err != nil {
		return "", err
	}
	return a.finish()
}

// adder is one pass of the compression.
//
// prev is the previous component *expanded*, which is what the next
// one's relative form is measured against; cur is the component being
// considered, still in whatever form the field held it.
type adder struct {
	realm string
	rest  string

	// out is the components written so far and n their joined
	// length, which is what upstream bounds rather than the count
	// (strlcat against bufsize, kdc_transit.c:369-378).
	out []string
	n   int

	prev  string
	cur   string
	added bool
}

// walk reads the field component by component, rewriting as it goes.
func (a *adder) walk() error {
	cur, err := a.next()
	if err != nil {
		return err
	}
	a.cur = cur
	for a.cur != "" {
		exp, err := a.expand()
		if err != nil {
			return err
		}
		peek, err := a.next()
		if err != nil {
			return err
		}
		if exp == a.realm {
			// Already in the field, in some form. Nothing
			// to add and nothing to rewrite.
			a.added = true
		}
		if !a.added {
			if err := a.insert(exp, peek); err != nil {
				return err
			}
		}
		if err := a.emit(); err != nil {
			return err
		}
		a.prev, a.cur = exp, peek
	}
	return nil
}

// next reads one component off the front of the remaining field.
//
// A backslash escapes the byte after it, and is *dropped* rather than
// kept: upstream's reader skips the escape character and continues
// (kdc_transit.c:199-205), so a quoted comma comes back as a bare one
// and is then indistinguishable from a separator on the next pass.
// That is upstream's behaviour and this matches it.
//
// A component longer than the limit is a refusal and not a
// truncation, which is why this can fail at all.
func (a *adder) next() (string, error) {
	var b strings.Builder
	for i := 0; i < len(a.rest); i++ {
		switch a.rest[i] {
		case '\\':
			continue
		case ',':
			a.rest = a.rest[i+1:]
			return b.String(), nil
		default:
			if b.Len() >= maxLen {
				return "", ErrIllegalPath
			}
			b.WriteByte(a.rest[i])
		}
	}
	a.rest = ""
	return b.String(), nil
}

// expand resolves the current component against the previous one,
// which is the same compression maybeJoin reads -- with one extra
// form the reader handles elsewhere: a leading space detaches the
// component entirely.
func (a *adder) expand() (string, error) {
	c := a.cur
	switch {
	case c[0] == ' ':
		return c[1:], nil
	case c[0] == '/' && a.prev != "" && a.prev[0] == '/':
		return join(a.prev, c)
	case c[len(c)-1] == '.':
		return join(c, a.prev)
	default:
		return c, nil
	}
}

func join(a, b string) (string, error) {
	if len(a)+len(b)+1 >= maxLen {
		return "", ErrIllegalPath
	}
	return a + b, nil
}

// emit appends the current component to the output.
func (a *adder) emit() error {
	n := a.n + len(a.cur)
	if a.n != 0 {
		n++
	}
	if n >= maxLen {
		return ErrIllegalPath
	}
	a.out = append(a.out, a.cur)
	a.n = n
	return nil
}

// finish writes the realm out in full when no compression was
// possible anywhere in the field.
//
// The leading space is what stops an X.500 name appended after
// something else being read as relative to it, and it is added only
// when there is something before it to be relative to.
func (a *adder) finish() (string, error) {
	joined := strings.Join(a.out, ",")
	if a.added {
		return joined, nil
	}
	tail := a.realm
	if a.realm[0] == '/' && joined != "" {
		tail = " " + a.realm
	}
	if joined == "" {
		return tail, nil
	}
	if len(joined)+len(tail)+1 >= maxLen {
		return "", ErrIllegalPath
	}
	return joined + "," + tail, nil
}
