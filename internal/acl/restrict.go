package acl

import (
	"fmt"
	"strings"
	"time"
)

// Restrictions are what an ACL entry imposes on a principal it
// permits being created or changed (parse_restrictions,
// auth_acl.c:155-245).
//
// They are **imposed, not merely checked**, which is the thing to
// understand about them: impose_restrictions (auth.c:203-271) ORs the
// attribute masks together and takes MIN(requested, restricted) for
// each lifetime, then forces the field to be written. An
// administrator restricted to a one-hour maximum ticket life does not
// get an error for asking for a day -- they get an hour.
type Restrictions struct {
	// Set and Clear are attribute bits to force on and off.
	Set   uint32
	Clear uint32

	// Policy is a policy name to force, and ClearPolicy forces no
	// policy at all. The two are exclusive.
	Policy      string
	ClearPolicy bool

	// The four lifetime caps, zero meaning uncapped.
	Expire   time.Duration
	PWExpire time.Duration
	MaxLife  time.Duration
	MaxRenew time.Duration
}

// AttrFunc looks up an attribute specifier like "+requires_preauth",
// which is internal/store's table. It is a function rather than an
// import so that this package depends on nothing.
type AttrFunc func(spec string) (set, clear uint32, err error)

// attrLookup is installed by SetAttrFunc.
var attrLookup AttrFunc

// SetAttrFunc tells this package how to read an attribute specifier.
// It exists because the specifier table belongs with the attributes
// themselves, and this package would otherwise have to duplicate
// forty rows of it.
func SetAttrFunc(f AttrFunc) { attrLookup = f }

// parseRestrictions reads the fourth field onwards.
func parseRestrictions(
	fields []string,
	raw string,
) (*Restrictions, error) {
	r := &Restrictions{}
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if d := r.durationField(f); d != nil {
			if i+1 >= len(fields) {
				return nil, fmt.Errorf(
					"%w: %q: %s wants a value",
					ErrMalformed, raw, f)
			}
			i++
			v, err := time.ParseDuration(fields[i])
			if err != nil {
				return nil, fmt.Errorf("%w: %q: %v",
					ErrMalformed, raw, err)
			}
			*d = v
			continue
		}
		if err := r.keyword(f, fields, &i, raw); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// durationField is the field a lifetime keyword sets, or nil when the
// keyword is not one of the four.
//
// Upstream takes a krb5 deltat for each; this takes a Go duration,
// which is the same wart -maxlife has on addprinc and for the same
// reason -- there is no deltat parser in this project yet.
func (r *Restrictions) durationField(f string) *time.Duration {
	switch f {
	case "-expire":
		return &r.Expire
	case "-pwexpire":
		return &r.PWExpire
	case "-maxlife":
		return &r.MaxLife
	case "-maxrenewlife":
		return &r.MaxRenew
	}
	return nil
}

// keyword reads the restrictions that are not durations.
func (r *Restrictions) keyword(
	f string,
	fields []string,
	i *int,
	raw string,
) error {
	switch {
	case f == "-clearpolicy":
		r.ClearPolicy = true
		return nil
	case f == "-policy":
		if *i+1 >= len(fields) {
			return fmt.Errorf(
				"%w: %q: -policy wants a name",
				ErrMalformed, raw)
		}
		*i++
		r.Policy = fields[*i]
		return nil
	case strings.HasPrefix(f, "+"),
		strings.HasPrefix(f, "-"):
		return r.attribute(f, raw)
	}
	return fmt.Errorf("%w: %q: unknown restriction %q",
		ErrMalformed, raw, f)
}

// attribute reads an attribute specifier through the installed
// lookup.
func (r *Restrictions) attribute(f, raw string) error {
	if attrLookup == nil {
		return fmt.Errorf(
			"%w: %q: no attribute table installed",
			ErrMalformed, raw)
	}
	set, clear, err := attrLookup(f)
	if err != nil {
		return fmt.Errorf("%w: %q: %v",
			ErrMalformed, raw, err)
	}
	r.Set |= set
	r.Clear |= clear
	return nil
}

// Impose applies a restriction to what an administrator asked for.
//
// It is **not** a check: impose_restrictions (auth.c:203-271) ORs the
// attribute masks and takes MIN(requested, restricted) for each
// lifetime, then forces the field to be written. An administrator
// capped at an hour who asks for a day gets an hour rather than an
// error, which is the difference between a restriction and a rule.
//
// A zero cap means uncapped, and a zero *request* means "the default"
// rather than "no life at all" -- so the minimum is taken only when
// both are set, and the cap wins outright when the request is unset.
func (r *Restrictions) Impose(
	attrs *uint32,
	maxLife, maxRenew *time.Duration,
) {
	if r == nil {
		return
	}
	*attrs |= r.Set
	*attrs &^= r.Clear
	capLife(maxLife, r.MaxLife)
	capLife(maxRenew, r.MaxRenew)
}

// capLife takes the smaller of a request and a cap, treating zero on
// either side as "unset".
func capLife(want *time.Duration, cap time.Duration) {
	switch {
	case cap == 0:
	case *want == 0 || *want > cap:
		*want = cap
	}
}
