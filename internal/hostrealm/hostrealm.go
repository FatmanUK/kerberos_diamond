// Package hostrealm maps a host name to the realm that serves it,
// this project's equivalent of krb5.conf's [domain_realm] section.
//
// It exists for one caller: the host-based referral, where a client
// asks this realm for host/www.elsewhere.test and is told the realm
// to ask instead (find_referral_tgs, kdc/do_tgs_req.c:482-523).
// Without a map there is nothing to answer with, so the whole feature
// is this lookup plus a gate on the request.
//
// Upstream's equivalent is a pluggable interface with four modules
// tried in order -- registry, profile, dns, domain
// (lib/krb5/os/hostrealm.c:69-94) -- and only one of them implements
// the method the KDC calls. hostrealm_dns.c and hostrealm_domain.c
// implement fallback_realm instead, which is reached only by
// krb5_get_fallback_host_realm (:400-447), a client-side API the KDC
// never calls. So the _kerberos TXT lookup, the realm_try_domains
// search and the upcased-parent-domain default are absent here
// because the KDC does not use them, not as a shortcut.
package hostrealm

import (
	"fmt"
	"strings"
)

// Map is a configured host-to-realm map.
//
// A nil Map is usable and means "no configuration", which answers
// every lookup with the empty realm -- the same answer upstream gives
// when no module matches (hostrealm.c:391-393), and the one
// find_referral_tgs reads as "no referral" (do_tgs_req.c:511-515).
// That is the common case and the reason the zero value is not an
// error.
type Map map[string]string

// Parse reads the KD_DOMAIN_REALM form: entries separated by
// semicolons, each "pattern=REALM".
//
//	.elsewhere.test=ELSEWHERE.TEST;host.other.test=OTHER.TEST
//
// The shape is krb5.conf's [domain_realm] turned into one line,
// because configuration here is environment-only and a profile
// section has nowhere to live. A pattern is a host name or a domain
// suffix, with or without a leading dot; which of those it is matters
// to Realm's search order and not at all here.
func Parse(s string) (Map, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := Map{}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		pattern, realm, err := parseEntry(entry)
		if err != nil {
			return nil, err
		}
		out[pattern] = realm
	}
	return out, nil
}

// parseEntry reads one "pattern=REALM" entry.
//
// The pattern is folded to lower case because that is the form Realm
// looks up; the realm is left alone, because a realm name is
// case-sensitive and only conventionally upper case.
func parseEntry(entry string) (string, string, error) {
	pattern, realm, ok := strings.Cut(entry, "=")
	if !ok {
		return "", "", fmt.Errorf(
			"domain_realm %q: no \"=\"", entry)
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	realm = strings.TrimSpace(realm)
	if pattern == "" {
		return "", "", fmt.Errorf(
			"domain_realm %q: no host or domain", entry)
	}
	if realm == "" {
		return "", "", fmt.Errorf(
			"domain_realm %q: no realm", entry)
	}
	return pattern, realm, nil
}

// Realm answers the realm that serves a host, or "" when nothing in
// the map does (profile_host_realm, hostrealm_profile.c:49-76).
//
// The search walks progressively shorter suffixes, and the sequence
// is not the obvious one. Upstream's loop is
//
//	for (p = host; p != NULL;
//	     p = (*p == '.') ? p + 1 : strchr(p, '.'))
//
// so a.b.c tries a.b.c, then .b.c, then b.c, then .c, then c: the
// dot-prefixed form *and* the bare suffix at every level, dot first,
// down to the last label on its own. A single-label entry is
// therefore a real pattern rather than a mistake -- upstream's own
// test maps "d" and looks up "x.d" (tests/t_referral.py:5).
func (m Map) Realm(host string) string {
	host = clean(host)
	if host == "" || numericAddress(host) {
		return ""
	}
	for p := host; p != ""; p = nextSuffix(p) {
		if realm, ok := m[p]; ok {
			return realm
		}
	}
	return ""
}

// nextSuffix is one step of that loop: from a name beginning with a
// dot, drop the dot; from anything else, skip to the next dot.
// Returning "" ends the walk, which upstream spells as a NULL from
// strchr.
func nextSuffix(p string) string {
	if p[0] == '.' {
		return p[1:]
	}
	i := strings.IndexByte(p, '.')
	if i < 0 {
		return ""
	}
	return p[i:]
}

// clean folds a host name to lower case and strips one trailing dot
// (clean_hostname, hostrealm.c:282-314), so "X." matches the entry
// for "x".
func clean(host string) string {
	host = strings.ToLower(host)
	return strings.TrimSuffix(host, ".")
}

// numericAddress reports whether a name looks like an IP address.
// Those are never looked up (k5_is_numeric_address,
// hostrealm.c:316-339).
//
// The test is upstream's, and it is looser than parsing: digits and
// dots with *exactly* three dots is IPv4, and anything holding a
// colon is IPv6. So 1.2.3 is not an address and neither is
// 1.2.3.4.5, while "::1" and "b:c.x" both are. A net.ParseIP here
// would disagree on every one of those, which is why the sloppy
// version is the one reproduced.
func numericAddress(name string) bool {
	if strings.IndexByte(name, ':') >= 0 {
		return true
	}
	if strings.Trim(name, "0123456789.") != "" {
		return false
	}
	return strings.Count(name, ".") == 3
}

// String renders a Map back into the form Parse reads, for an error
// message or a log line. The entry order is not stable.
func (m Map) String() string {
	out := make([]string, 0, len(m))
	for pattern, realm := range m {
		out = append(out, pattern+"="+realm)
	}
	return strings.Join(out, ";")
}
