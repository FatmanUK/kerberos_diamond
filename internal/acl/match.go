package acl

import "strings"

// matchClient matches a principal against a pattern and returns what
// its wildcards captured (match_data and match_princ,
// auth_acl.c:466-494).
//
// Component counts must be equal: a pattern is not a prefix, so
// "*/admin" matches "alice/admin" and not "alice". A component of
// exactly "*" matches anything and is captured, in order, for the
// target pattern to refer back to.
//
// The realm is matched like any other part of the name but takes no
// part in the captures, which is upstream's arrangement and the
// reason the backreferences are numbered from the components alone.
func matchClient(pattern, name string) ([]string, bool) {
	pc, pr, ok := split(pattern)
	if !ok {
		return nil, false
	}
	nc, nr, ok := split(name)
	if !ok {
		return nil, false
	}
	if !matchPart(pr, nr) || len(pc) != len(nc) {
		return nil, false
	}
	var caps []string
	for i := range pc {
		if pc[i] == "*" {
			caps = append(caps, nc[i])
			continue
		}
		if pc[i] != nc[i] {
			return nil, false
		}
	}
	return caps, true
}

// matchTarget matches the object of an operation, resolving "*1" to
// "*9" against what the client pattern captured.
//
// The example upstream tests is the whole idea: "*/* d *2/*1" lets
// a/b delete b/a (tests/t_kadmin_acl.py:85,333-334). A reference to a
// capture that was not made never matches, rather than matching
// everything.
func matchTarget(
	pattern, name string,
	caps []string,
) bool {
	pc, pr, ok := split(pattern)
	if !ok {
		return false
	}
	nc, nr, ok := split(name)
	if !ok {
		return false
	}
	if !matchPart(pr, nr) || len(pc) != len(nc) {
		return false
	}
	for i := range pc {
		want, ok := resolve(pc[i], caps)
		if !ok {
			return false
		}
		if want != "*" && want != nc[i] {
			return false
		}
	}
	return true
}

// resolve turns "*1".."*9" into the captured component.
func resolve(part string, caps []string) (string, bool) {
	if len(part) != 2 || part[0] != '*' {
		return part, true
	}
	n := int(part[1] - '0')
	if n < 1 || n > 9 || n > len(caps) {
		return "", false
	}
	return caps[n-1], true
}

// matchPart is one component or realm, with "*" matching anything.
func matchPart(pattern, name string) bool {
	return pattern == "*" || pattern == name
}

// split separates a principal into components and realm.
//
// A name with no realm is refused rather than defaulted, because an
// ACL entry and the name it is matched against must agree about which
// realm they mean -- and the caller has the realm to hand.
func split(name string) ([]string, string, bool) {
	at := strings.LastIndex(name, "@")
	if at < 0 || at == len(name)-1 {
		return nil, "", false
	}
	return strings.Split(name[:at], "/"), name[at+1:], true
}
