package hostrealm

// Services is a list of service names, written the way
// host_based_services and no_host_referral are written in kdc.conf:
// names separated by spaces or commas, or the single wildcard "*".
//
// It is kept as the raw string rather than split into a slice so that
// the membership test can be upstream's own, which is not quite a
// split -- see has. There is no malformed value and so no Parse: an
// unset variable is the empty list, and the empty list matches
// nothing.
type Services string

// Matches reports whether a service name is in the list, or the list
// is the wildcard.
//
// Upstream spells the wildcard at each call site --
// in_list(hostbased, stype) || in_list(hostbased, "*"), and the same
// for no_referral (do_tgs_req.c:458-470) -- so both of its uses are
// "this name, or a star". That is folded in here rather than repeated
// at both of ours.
func (s Services) Matches(name string) bool {
	return s.has(name) || s.has("*")
}

// has is in_list (do_tgs_req.c:415-429): a substring search in which
// every hit must be bounded on the left by the start of the list, a
// space or a comma, and on the right by the end of the list, a space
// or a comma.
//
// Written out rather than replaced by a split on those separators,
// which is what it amounts to for any list a person would write. The
// two differ only where a list holds adjacent separators, and
// reproducing the original costs less than establishing that the
// difference cannot be reached.
//
// The empty list matches nothing, including the empty name. Upstream
// gets there differently: it distinguishes a NULL list from an empty
// one and answers FALSE for NULL (:421-422), and an unconfigured
// value is NULL. Here an unset variable *is* the empty string, so
// that is the case to answer FALSE for -- without which a server name
// whose first component was empty would match an unconfigured list,
// and be offered a referral upstream would refuse.
func (s Services) has(name string) bool {
	if s == "" {
		return false
	}
	list := string(s)
	for i := 0; i+len(name) <= len(list); i++ {
		if list[i:i+len(name)] != name {
			continue
		}
		if i > 0 && !isSeparator(list[i-1]) {
			continue
		}
		j := i + len(name)
		if j < len(list) && !isSeparator(list[j]) {
			continue
		}
		return true
	}
	return false
}

// isSeparator is upstream's test: a comma, or anything isspace
// reports -- which in the C locale is space, tab, newline, vertical
// tab, form feed and carriage return.
func isSeparator(c byte) bool {
	switch c {
	case ',', ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}
