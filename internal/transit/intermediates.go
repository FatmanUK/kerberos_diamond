package transit

// processIntermediates reports the realms between two names
// (chk_trans.c:45-132).
//
// This is what makes the encoding lossy, and worth stating plainly:
// an empty component does not name a realm, it names *a range*. The
// two ends of the range are given, and every realm hierarchically
// between them is implied -- so "ATHENA.MIT.EDU" and "EDU" imply
// "MIT.EDU" without it appearing anywhere in the field.
//
// The two ends must be the same style of name and must share the
// appropriate part: a common prefix for X.500 names, a common suffix
// for domain ones. They do not have to be given in any particular
// order, which is why the first thing this does is sort them by
// length.
func processIntermediates(
	fn func(string) error,
	n1, n2 string,
) error {
	if len(n1) > len(n2) {
		n1, n2 = n2, n1
	}
	if len(n1) == len(n2) {
		// Equal length and both ends of a range: they have to
		// be the same realm, or the range is between two
		// names neither of which contains the other.
		if n1 != n2 {
			return ErrIllegalPath
		}
		return nil
	}
	if n1 == "" {
		// Upstream calls this an internal error rather than a
		// malformed path, and answers the same way
		// regardless.
		return ErrIllegalPath
	}
	if n1[0] == '/' {
		return x500Intermediates(fn, n1, n2)
	}
	return domainIntermediates(fn, n1, n2)
}

// x500Intermediates walks an X.500-style range, where the shorter
// name is a prefix of the longer and each '/' in between is a realm.
func x500Intermediates(
	fn func(string) error,
	short, long string,
) error {
	if long[0] != '/' {
		// One X.500 name and one domain name is not a range
		// at all; it is two unrelated realms.
		return ErrIllegalPath
	}
	if long[:len(short)] != short {
		return ErrIllegalPath
	}
	for i := len(short) + 1; i < len(long); i++ {
		if long[i] != '/' {
			continue
		}
		if err := fn(long[:i]); err != nil {
			return err
		}
	}
	return nil
}

// domainIntermediates walks a domain-style range, where the shorter
// name is a suffix of the longer and each component boundary in
// between is a realm.
//
// The walk is right to left and stops before the longer name itself,
// which is already in the field: only what lies strictly between the
// two ends is implied.
func domainIntermediates(
	fn func(string) error,
	short, long string,
) error {
	if long[0] == '/' {
		return ErrIllegalPath
	}
	if long[len(long)-len(short):] != short {
		return ErrIllegalPath
	}
	for i := len(long) - len(short) - 1; i > 0; i-- {
		if long[i-1] != Separator {
			continue
		}
		if err := fn(long[i:]); err != nil {
			return err
		}
	}
	return nil
}
