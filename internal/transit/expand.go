package transit

// Expand lists every realm a transited encoding names, in the order
// upstream visits them.
//
// This is foreach_realm (lib/krb5/krb/chk_trans.c:163-283) with the
// callback made a return value, and it is the whole of what makes the
// encoding readable. Check is a thin layer over it; it exists
// separately because upstream's own test for this is an expansion
// test -- t_expand with the transit-tests script -- and matching that
// is the only anchor available for any of this.
//
// Duplicates are kept. The expansion visits a realm twice when two
// intermediate ranges overlap, and upstream's test sorts without
// de-duplicating, so a port that collapsed them would not match.
func Expand(crealm, srealm, encoded string) ([]string, error) {
	var out []string
	err := foreachRealm(func(r string) error {
		out = append(out, r)
		return nil
	}, crealm, srealm, encoded)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// walker is the state foreachRealm carries across one pass.
//
// It is a struct rather than four locals because the comma case needs
// all of it and splitting that case out is what keeps this inside
// forty lines.
type walker struct {
	fn   func(string) error
	buf  []byte
	last string

	// intermediates records that an empty component was seen -- a
	// doubled comma, or a leading one -- which is how the
	// encoding says "and every realm between these two". lit
	// records that the previous byte was an escape.
	intermediates bool
	lit           bool
}

// foreachRealm is the pass itself.
func foreachRealm(
	fn func(string) error,
	crealm, srealm, encoded string,
) error {
	if encoded == "" {
		return nil
	}
	w := &walker{fn: fn}
	for i := 0; i < len(encoded); i++ {
		err := w.step(encoded[i], i == 0, crealm)
		if err != nil {
			return err
		}
	}
	return w.finish(srealm)
}

// step consumes one byte of the encoding.
func (w *walker) step(c byte, first bool, crealm string) error {
	switch {
	case w.lit:
		w.lit = false
		return w.push(c)
	case c == '\\':
		// A quoted comma or backslash: the next byte is part
		// of a realm name and not punctuation.
		w.lit = true
		return nil
	case c == ',':
		return w.comma(first, crealm)
	case c == ' ' && len(w.buf) == 0:
		// A leading space means the component that follows
		// stands alone, even if it has a trailing dot or a
		// leading slash that would otherwise make it relative
		// to the last one.
		w.last = ""
		return nil
	default:
		return w.push(c)
	}
}

// push adds one byte to the component being read.
func (w *walker) push(c byte) error {
	if len(w.buf) >= maxLen {
		return ErrIllegalPath
	}
	w.buf = append(w.buf, c)
	return nil
}

// comma ends a component, or -- when there is nothing to end --
// records that the next one is preceded by an intermediate range.
func (w *walker) comma(first bool, crealm string) error {
	if len(w.buf) == 0 {
		w.intermediates = true
		if first {
			// A leading comma's range starts at the
			// client's own realm, which is not in the
			// field because both ends already know it.
			w.last = crealm
		}
		return nil
	}
	this, err := maybeJoin(w.last, string(w.buf))
	if err != nil {
		return err
	}
	if err := w.fn(this); err != nil {
		return err
	}
	if w.intermediates {
		err = processIntermediates(w.fn, this, w.last)
		if err != nil {
			return err
		}
	}
	w.intermediates = false
	w.last = this
	w.buf = w.buf[:0]
	return nil
}

// finish handles whatever the field ended with.
//
// A trailing comma is a range running up to the *server's* realm, and
// it is reported whether or not an empty component was seen -- the
// trailing comma is itself the empty component.
func (w *walker) finish(srealm string) error {
	if len(w.buf) == 0 {
		return processIntermediates(w.fn, w.last, srealm)
	}
	this, err := maybeJoin(w.last, string(w.buf))
	if err != nil {
		return err
	}
	if err := w.fn(this); err != nil {
		return err
	}
	if !w.intermediates {
		return nil
	}
	return processIntermediates(w.fn, this, w.last)
}

// maybeJoin expands a component that was written relative to the one
// before it (maybe_join, chk_trans.c:135-160).
//
// Two compressions, one for each realm-name style. A component
// beginning with '/' is an X.500 name with its prefix left off, so
// the previous name goes in front; one *ending* with '.' is a domain
// name with its suffix left off, so the previous name goes behind.
// Anything else stands on its own.
func maybeJoin(last, buf string) (string, error) {
	if buf == "" {
		return buf, nil
	}
	if len(last)+len(buf) > maxLen {
		return "", ErrIllegalPath
	}
	if buf[0] == '/' {
		return last + buf, nil
	}
	if buf[len(buf)-1] == '.' {
		return buf + last, nil
	}
	return buf, nil
}
