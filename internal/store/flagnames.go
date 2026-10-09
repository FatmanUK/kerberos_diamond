package store

import (
	"fmt"
	"sort"
	"strings"
)

// attrSpec is one accepted spelling of a principal attribute, with
// whether naming it turns the underlying bit *off*.
type attrSpec struct {
	name   string
	attr   uint32
	invert bool
}

// attrSpecs is kadmin's flag table (lib/kadm5/str_conv.c:50-94),
// aliases included.
//
// Most of these names are inverted, and that is the thing to know
// before using any of them: the stored bits are nearly all DISALLOW_
// bits, so "+forwardable" *clears* DISALLOW_FORWARDABLE rather than
// setting anything. An operator who reads "+" as "set the named bit"
// will get the opposite of what they asked for on eight of these
// fourteen attributes. The aliases are carried because they are what
// a Kerberos operator's fingers already know.
var attrSpecs = []attrSpec{
	{"allow_postdated", AttrDisallowPostdated, true},
	{"postdateable", AttrDisallowPostdated, true},
	{"disallow_postdated", AttrDisallowPostdated, false},
	{"allow_forwardable", AttrDisallowForwardable, true},
	{"forwardable", AttrDisallowForwardable, true},
	{"disallow_forwardable", AttrDisallowForwardable, false},
	{"allow_tgs_req", AttrDisallowTGTBased, true},
	{"tgt_based", AttrDisallowTGTBased, true},
	{"disallow_tgt_based", AttrDisallowTGTBased, false},
	{"allow_renewable", AttrDisallowRenewable, true},
	{"renewable", AttrDisallowRenewable, true},
	{"disallow_renewable", AttrDisallowRenewable, false},
	{"allow_proxiable", AttrDisallowProxiable, true},
	{"proxiable", AttrDisallowProxiable, true},
	{"disallow_proxiable", AttrDisallowProxiable, false},
	{"allow_dup_skey", AttrDisallowDupSKey, true},
	{"dup_skey", AttrDisallowDupSKey, true},
	{"disallow_dup_skey", AttrDisallowDupSKey, false},
	{"allow_tickets", AttrDisallowAllTix, true},
	{"allow_tix", AttrDisallowAllTix, true},
	{"disallow_all_tix", AttrDisallowAllTix, false},
	{"preauth", AttrRequiresPreAuth, false},
	{"requires_pre_auth", AttrRequiresPreAuth, false},
	{"requires_preauth", AttrRequiresPreAuth, false},
	{"hwauth", AttrRequiresHWAuth, false},
	{"requires_hw_auth", AttrRequiresHWAuth, false},
	{"requires_hwauth", AttrRequiresHWAuth, false},
	{"needchange", AttrRequiresPWChange, false},
	{"pwchange", AttrRequiresPWChange, false},
	{"requires_pwchange", AttrRequiresPWChange, false},
	{"allow_svr", AttrDisallowSvr, true},
	{"service", AttrDisallowSvr, true},
	{"disallow_svr", AttrDisallowSvr, false},
	{"password_changing_service", AttrPWChangeService, false},
	{"pwchange_service", AttrPWChangeService, false},
	{"pwservice", AttrPWChangeService, false},
	{"new_princ", AttrNewPrinc, false},
	{"ok_as_delegate", AttrOKAsDelegate, false},
	{"ok_to_auth_as_delegate", AttrOKToAuthAsDelegate, false},
	{"no_auth_data_required", AttrNoAuthDataRequired, false},
	{"lockdown_keys", AttrLockdownKeys, false},
}

// ErrBadAttr reports an attribute spelling this does not know.
var ErrBadAttr = fmt.Errorf("unknown attribute")

// ApplyAttr applies one "+name" or "-name" specifier to an attribute
// word and returns the result.
//
// The sign says what the operator wants, not which way the bit moves:
// "+forwardable" asks for forwardable tickets to be permitted, which
// means *clearing* DISALLOW_FORWARDABLE. Combining the sign with the
// table's invert column is the whole of the translation.
func ApplyAttr(attrs uint32, spec string) (uint32, error) {
	if len(spec) < 2 || (spec[0] != '+' && spec[0] != '-') {
		return attrs, fmt.Errorf(
			"%w: %q needs a leading + or -",
			ErrBadAttr, spec)
	}
	want := spec[0] == '+'
	name := strings.ToLower(spec[1:])
	for _, s := range attrSpecs {
		if s.name != name {
			continue
		}
		// set reports whether the stored bit ends up on.
		set := want != s.invert
		if set {
			return attrs | s.attr, nil
		}
		return attrs &^ s.attr, nil
	}
	return attrs, fmt.Errorf("%w: %q", ErrBadAttr, name)
}

// attrDisplay is the name each bit is *printed* as, which is the raw
// stored sense and not the inverted spelling used to set it
// (outflags, lib/kadm5/str_conv.c:97-120).
var attrDisplay = []struct {
	attr uint32
	name string
}{
	{AttrDisallowPostdated, "DISALLOW_POSTDATED"},
	{AttrDisallowForwardable, "DISALLOW_FORWARDABLE"},
	{AttrDisallowTGTBased, "DISALLOW_TGT_BASED"},
	{AttrDisallowRenewable, "DISALLOW_RENEWABLE"},
	{AttrDisallowProxiable, "DISALLOW_PROXIABLE"},
	{AttrDisallowDupSKey, "DISALLOW_DUP_SKEY"},
	{AttrDisallowAllTix, "DISALLOW_ALL_TIX"},
	{AttrRequiresPreAuth, "REQUIRES_PRE_AUTH"},
	{AttrRequiresHWAuth, "REQUIRES_HW_AUTH"},
	{AttrRequiresPWChange, "REQUIRES_PWCHANGE"},
	{AttrDisallowSvr, "DISALLOW_SVR"},
	{AttrPWChangeService, "PWCHANGE_SERVICE"},
	{AttrNewPrinc, "NEW_PRINC"},
	{AttrOKAsDelegate, "OK_AS_DELEGATE"},
	{AttrOKToAuthAsDelegate, "OK_TO_AUTH_AS_DELEGATE"},
	{AttrNoAuthDataRequired, "NO_AUTH_DATA_REQUIRED"},
	{AttrLockdownKeys, "LOCKDOWN_KEYS"},
}

// AttrNames renders an attribute word the way getprinc prints it: the
// stored names, in bit order, lowest first.
func AttrNames(attrs uint32) []string {
	var out []string
	for _, d := range attrDisplay {
		if attrs&d.attr != 0 {
			out = append(out, d.name)
		}
	}
	return out
}

// AttrSpecNames lists every accepted specifier, sorted, for a usage
// message.
func AttrSpecNames() []string {
	out := make([]string, 0, len(attrSpecs))
	for _, s := range attrSpecs {
		out = append(out, s.name)
	}
	sort.Strings(out)
	return out
}

// AttrMask reads one attribute specifier into the bits it sets and
// the bits it clears, which is what an access-control restriction
// needs: it has to be combined with other restrictions before being
// applied, so it cannot just mutate a value the way ApplyAttr does.
//
// Both are returned rather than one, because most of these specifiers
// are inverted -- +forwardable *clears* DISALLOW_FORWARDABLE -- so
// "the bits a + sets" is not a well-formed question.
func AttrMask(spec string) (set, clear uint32, err error) {
	// Applied to zero, the result is the bits a + would have set.
	on, err := ApplyAttr(0, spec)
	if err != nil {
		return 0, 0, err
	}
	// Applied to all-ones, the complement is what it clears.
	off, err := ApplyAttr(^uint32(0), spec)
	if err != nil {
		return 0, 0, err
	}
	return on, ^off, nil
}
