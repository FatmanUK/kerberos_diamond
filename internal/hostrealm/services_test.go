package hostrealm

import "testing"

// The host_based_services and no_host_referral matrix from upstream's
// referral test (tests/t_referral.py:53-93), which is where every one
// of these list spellings comes from. The service being asked about
// is "a" throughout, as it is there.
func TestServicesReadsUpstreamsSpellings(t *testing.T) {
	for _, c := range []struct {
		list Services
		want bool
	}{
		{"*", true},
		{"a", true},
		{"a b c", true},
		{"a,b", true},
		{"b,c", false},
		{"b", false},
		// A name that is a substring of a listed one is not
		// in the list, which is the whole reason in_list
		// checks both boundaries rather than calling strstr
		// and stopping.
		{"abacus", false},
		{"ab,ba", false},
		// And the reverse: a listed name that contains the
		// one asked about still does not match.
		{"xa", false},
		{"ax", false},
		{"", false},
	} {
		if got := c.list.Matches("a"); got != c.want {
			t.Errorf("%q matched %q: %v, want %v",
				c.list, "a", got, c.want)
		}
	}
}

// Every separator upstream accepts is accepted, because a
// configuration written for kdc.conf should transcribe. isspace in
// the C locale is six characters and a comma is the seventh.
func TestEverySeparatorIsAccepted(t *testing.T) {
	for _, sep := range []string{
		" ", ",", "\t", "\n", "\v", "\f", "\r",
	} {
		list := Services("b" + sep + "a" + sep + "c")
		if !list.Matches("a") {
			t.Errorf("%q did not separate on %q",
				list, sep)
		}
	}
}

// The empty list matches nothing at all, the empty name included.
// Upstream answers FALSE because an unconfigured list is NULL
// (do_tgs_req.c:421-422); here an unset variable is the empty string,
// so the same condition has to answer the same way. Without this a
// server name whose first component was empty would match an
// unconfigured list and be offered a referral upstream refuses.
func TestTheEmptyListMatchesNothing(t *testing.T) {
	var none Services
	for _, name := range []string{"a", "*", ""} {
		if none.Matches(name) {
			t.Errorf("the empty list matched %q", name)
		}
	}
}

// The wildcard is checked at every use upstream, so it is folded into
// Matches here -- which means a list of exactly "*" matches a name
// nobody listed.
func TestTheWildcardMatchesAnything(t *testing.T) {
	for _, name := range []string{"a", "host", "nfs"} {
		if !Services("*").Matches(name) {
			t.Errorf("* did not match %q", name)
		}
	}
	// And a list holding the wildcard among other names still
	// matches everything, because in_list finds it there.
	if !Services("b,*").Matches("a") {
		t.Error("b,* did not match a")
	}
}
