package transit

// insert tries to write the new realm compressed against the
// component the walk is looking at (kdc_transit.c:280-367).
//
// Two opportunities, and the order between them is upstream's. If the
// new realm is a *subrealm* of the current one it can be written
// relative to it and slipped in immediately after -- but only when
// the following component is not itself compressed, because inserting
// before a relative name would change what that name expands to. If
// instead the new realm is a *superrealm* of the current one, the
// current one can be rewritten relative to the new one, which goes in
// its place.
//
// exp is the current component expanded; peek is the next component
// as the field holds it, needed only to tell whether it is
// compressed.
func (a *adder) insert(exp, peek string) error {
	if !compressed(peek) {
		if n := subrealm(exp, a.realm); n != 0 {
			a.added = true
			return a.appendRelative(n)
		}
	}
	if n := subrealm(a.realm, exp); n != 0 {
		a.added = true
		return a.replaceWith(exp, n)
	}
	return nil
}

// compressed reports whether a component is written relative to the
// one before it, which is what makes it unsafe to insert ahead of.
func compressed(c string) bool {
	if c == "" {
		return false
	}
	return c[len(c)-1] == '.' || c[0] == '/'
}

// appendRelative writes the new realm after the current component, in
// its relative form.
func (a *adder) appendRelative(n int) error {
	rel := relative(a.realm, n)
	if len(a.cur)+len(rel)+2 >= maxLen {
		return ErrIllegalPath
	}
	a.cur += "," + rel
	return nil
}

// replaceWith puts the new realm where the current component was, and
// writes the current component relative to it.
//
// The new realm is itself compressed against the *previous* component
// first when it can be. If it could not be -- and upstream notes why
// that case is reachable: had the new realm been a superrealm of the
// previous one too, it would have been added on an earlier pass -- an
// X.500 name needs the detaching space for the same reason finish
// does.
func (a *adder) replaceWith(exp string, n int) error {
	head := ""
	if n1 := subrealm(a.prev, a.realm); n1 != 0 {
		head = relative(a.realm, n1)
	} else {
		if a.realm[0] == '/' && a.prev != "" {
			head = " "
		}
		head += a.realm
	}
	rel := relative(exp, n)
	if len(head)+len(rel)+2 >= maxLen {
		return ErrIllegalPath
	}
	a.cur = head + "," + rel
	return nil
}

// relative renders the part of a realm name that subrealm measured: a
// positive count is a prefix, a negative count a suffix.
func relative(realm string, n int) string {
	if n > 0 {
		return realm[:n]
	}
	return realm[len(realm)+n:]
}

// subrealm reports whether r2 is a subrealm of r1, and by how much
// (kdc_transit.c:60-69).
//
// The two realm-name styles nest in opposite directions, which is why
// the sign carries information rather than just the length. An X.500
// name's parent is its prefix, so r1 being a prefix of r2 makes r2 a
// subrealm and the answer is negative -- the length of r2's extra
// suffix. A domain name's parent is its suffix, so r1 being a suffix
// of r2 makes r2 a subrealm and the answer is positive, the length of
// r2's extra prefix. Zero means r2 is not a subrealm of r1 at all.
func subrealm(r1, r2 string) int {
	if len(r2) <= len(r1) {
		return 0
	}
	// The null realm. Upstream reads r1[0] off the terminator and
	// then compares zero bytes, which matches, so an empty r1 is
	// a parent of every domain-style name and of no X.500 one.
	// That is reproduced rather than tidied away: the first pass
	// of the walk has no previous component and relies on it.
	var first byte
	if r1 != "" {
		first = r1[0]
	}
	if first == '/' && r2[0] == '/' {
		if r2[:len(r1)] == r1 {
			return len(r1) - len(r2)
		}
		return 0
	}
	if first != '/' && r2[0] != '/' {
		if r2[len(r2)-len(r1):] == r1 {
			return len(r2) - len(r1)
		}
	}
	return 0
}
